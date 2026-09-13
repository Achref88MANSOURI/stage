#!/usr/bin/env python3
"""
VR_KillProcess - Cortex responder (OS-aware)

Triggered on a TheHive observable typed `process-path`.

Runtime flow:
  1. Read the triggering process-path observable.
  2. Query the parent case for hostname / endpoint-ip / process-pid observables.
  3. Resolve the Velociraptor client_id (hostname preferred, endpoint-ip fallback).
  4. Detect the client's OS live via Generic.Client.Info.
  5. Run the matching exact-match kill artifact with the path (and optional PID).

Design notes:
  - spec= is built as native VQL (backtick-quoted artifact name), NOT Python
    dict-unpacking syntax and NOT json.dumps() output. Raw JSON embedded in a
    VQL string fails silently.
  - The gRPC channel is stored on self, not scoped to a with-block, because the
    OS-detection collect-and-poll cycle keeps it alive across multiple calls.
  - OS is detected live per-run, never assumed from the observable or the case.
"""

from cortexutils.responder import Responder
import json
import time
import grpc
import yaml
import base64

from thehive4py import TheHiveApi
from thehive4py.query.filters import Eq

import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc


ARTIFACT_BY_OS = {
    "windows": "Custom.Windows.Remediation.KillProcessExact",
    "linux":   "Custom.Linux.Remediation.KillProcessExact",
}

EXPECTED_TRIGGER_DATATYPE = "process-path"

# Polling for the OS-detection flow
OS_POLL_INTERVAL_SEC = 2
OS_POLL_MAX_ATTEMPTS = 30


class VRKillProcess(Responder):
    def __init__(self):
        Responder.__init__(self)

        # --- Velociraptor API client config ---
        self.configpath = self.get_param('config.velociraptor_client_config', None)
        self.config_content_base64 = self.get_param(
            'config.velociraptor_client_config_content_base64', None)
        if not self.configpath and not self.config_content_base64:
            self.error("Either velociraptor_client_config or "
                       "velociraptor_client_config_content_base64 must be provided!")

        if self.config_content_base64:
            try:
                decoded = base64.b64decode(self.config_content_base64).decode('utf-8')
                self.vr_config = yaml.load(decoded, Loader=yaml.FullLoader)
            except Exception as e:
                self.error(f"Failed to decode base64 Velociraptor config: {e}")
        else:
            self.vr_config = yaml.load(open(self.configpath).read(),
                                       Loader=yaml.FullLoader)

        # --- TheHive API client config ---
        self.thehive_url = self.get_param('config.thehive_url', None,
                                          'thehive_url missing!')
        self.thehive_apikey = self.get_param('config.thehive_apikey', None,
                                             'thehive_apikey missing!')

        # --- Behavior config ---
        self.max_wait = self.get_param('config.query_max_duration', 600)
        self.really_do_it = self.get_param('config.really_do_it', False)

        # --- Triggering observable ---
        self.observable_type = self.get_param('data.dataType', None,
                                              "Data type is empty")
        self.observable = self.get_param('data.data', None, 'Data missing!')
        # TheHive 5 nests the case object under data.case -- NOT data._parent
        self.case_id = self.get_param('data.case._id', None,
                                      'Parent case id missing!')

        if self.observable_type != EXPECTED_TRIGGER_DATATYPE:
            self.error(
                f"VR_KillProcess expects a '{EXPECTED_TRIGGER_DATATYPE}' observable, "
                f"got '{self.observable_type}'."
            )

        self._channel = None

    # ---------------------------------------------------------------- #
    # VQL helpers
    # ---------------------------------------------------------------- #

    @staticmethod
    def _vql_escape(value):
        """Escape a value for embedding inside a single-quoted VQL string."""
        return str(value).replace("\\", "\\\\").replace("'", "\\'")

    def _get_stub(self):
        """Open the gRPC channel and keep it referenced on self for the run."""
        creds = grpc.ssl_channel_credentials(
            root_certificates=self.vr_config["ca_certificate"].encode("utf8"),
            private_key=self.vr_config["client_private_key"].encode("utf8"),
            certificate_chain=self.vr_config["client_cert"].encode("utf8"),
        )
        options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
        self._channel = grpc.secure_channel(
            self.vr_config["api_connection_string"], creds, options)
        return api_pb2_grpc.APIStub(self._channel)

    def _vql(self, stub, vql, max_wait=60, name="TheHive-Query"):
        """Run a VQL query and return all result rows as a flat list of dicts."""
        rows = []
        request = api_pb2.VQLCollectorArgs(
            max_wait=max_wait,
            Query=[api_pb2.VQLRequest(Name=name, VQL=vql)],
        )
        for response in stub.Query(request):
            if not response.Response:
                continue
            try:
                parsed = json.loads(response.Response)
                if isinstance(parsed, list):
                    rows.extend(parsed)
                else:
                    rows.append(parsed)
            except Exception:
                pass
        return rows

    # ---------------------------------------------------------------- #
    # TheHive lookup
    # ---------------------------------------------------------------- #

    def resolve_endpoint_and_pid(self):
        """Fetch hostname / endpoint-ip / process-pid from the parent case."""
        hive = TheHiveApi(url=self.thehive_url, apikey=self.thehive_apikey)
        # OR is expressed by chaining filters with | -- there is no Or() class
        filt = (
            Eq(field="dataType", value="hostname")
            | Eq(field="dataType", value="endpoint-ip")
            | Eq(field="dataType", value="process-pid")
        )
        results = hive.case.find_observables(case_id=self.case_id, filters=filt)
        hostname = next(
            (o['data'] for o in results if o.get('dataType') == 'hostname'), None)
        endpoint_ip = next(
            (o['data'] for o in results if o.get('dataType') == 'endpoint-ip'), None)
        pid = next(
            (o['data'] for o in results if o.get('dataType') == 'process-pid'), None)
        return hostname, endpoint_ip, pid

    # ---------------------------------------------------------------- #
    # Velociraptor: client + OS resolution
    # ---------------------------------------------------------------- #

    def _resolve_client_id(self, stub, hostname, endpoint_ip):
        """Resolve a Velociraptor client_id. Hostname preferred, IP fallback."""
        if hostname:
            vql = ("select client_id from clients(search='host:"
                   + self._vql_escape(hostname) + "')")
        elif endpoint_ip:
            vql = ("select client_id from clients() where last_ip =~ '"
                   + self._vql_escape(endpoint_ip) + "'")
        else:
            return None

        rows = self._vql(stub, vql, max_wait=60, name="TheHive-ClientQuery")
        for row in rows:
            cid = row.get("client_id")
            if cid:
                return cid
        return None

    def _detect_os(self, stub, client_id):
        """
        Detect client OS live by collecting Generic.Client.Info on the client
        and reading the OS column from its BasicInformation source.
        Never assumed -- always queried per run.
        """
        schedule_vql = (
            "SELECT collect_client("
            "client_id='" + client_id + "', "
            "artifacts=['Generic.Client.Info'], "
            "spec=dict()"
            ") AS Flow FROM scope()"
        )
        rows = self._vql(stub, schedule_vql, max_wait=60, name="ScheduleOSDetect")
        if not rows:
            return None
        flow_id = (rows[0].get("Flow") or {}).get("flow_id")
        if not flow_id:
            return None

        # Poll until the flow finishes
        status_vql = (
            "SELECT state FROM flows(client_id='" + client_id + "', "
            "flow_id='" + flow_id + "')"
        )
        for _ in range(OS_POLL_MAX_ATTEMPTS):
            status_rows = self._vql(stub, status_vql, max_wait=30,
                                    name="PollOSDetect")
            state = status_rows[0].get("state") if status_rows else None
            if state and str(state).upper() in ("FINISHED", "ERROR"):
                break
            time.sleep(OS_POLL_INTERVAL_SEC)

        result_vql = (
            "SELECT OS FROM source(client_id='" + client_id + "', "
            "flow_id='" + flow_id + "', "
            "artifact='Generic.Client.Info/BasicInformation')"
        )
        result_rows = self._vql(stub, result_vql, max_wait=60,
                                name="ReadOSDetect")
        for row in result_rows:
            os_name = row.get("OS")
            if os_name:
                return str(os_name).strip().lower()
        return None

    # ---------------------------------------------------------------- #
    # Main
    # ---------------------------------------------------------------- #

    def run(self):
        Responder.run(self)

        try:
            hostname, endpoint_ip, pid = self.resolve_endpoint_and_pid()
        except Exception as e:
            self.report({'message': f'TheHive lookup failed: {type(e).__name__}: {e}'})
            return

        if not hostname and not endpoint_ip:
            self.report({
                'message': 'No endpoint identity (hostname/endpoint-ip) found on '
                           f'case {self.case_id} -- cannot resolve Velociraptor client.'
            })
            return

        try:
            stub = self._get_stub()

            client_id = self._resolve_client_id(stub, hostname, endpoint_ip)
            if not client_id:
                self.report({
                    'message': 'Could not find a matching Velociraptor client.',
                    'tried_hostname': hostname,
                    'tried_endpoint_ip': endpoint_ip,
                })
                return

            os_name = self._detect_os(stub, client_id)
            if os_name not in ARTIFACT_BY_OS:
                self.report({
                    'message': f"Unsupported or undetected client OS: {os_name}",
                    'client_id': client_id,
                })
                return
            artifact_name = ARTIFACT_BY_OS[os_name]

            pid_param = str(pid) if pid else "0"
            really_do_it_vql = "TRUE" if self.really_do_it else "FALSE"

            # Native VQL dict syntax with a backtick-quoted artifact name.
            # NOT Python dict-unpacking, NOT json.dumps() -- either fails silently.
            spec_vql = (
                "dict(`" + artifact_name + "`=dict("
                "TargetExe='" + self._vql_escape(self.observable) + "', "
                "TargetPid=" + pid_param + ", "
                "ReallyDoIt=" + really_do_it_vql + "))"
            )

            artifact_query = (
                "LET collection <= collect_client("
                "client_id='" + client_id + "', "
                "artifacts=['" + artifact_name + "'], "
                "spec=" + spec_vql + ") "
                "LET collection_completed <= SELECT * FROM watch_monitoring("
                "artifact='System.Flow.Completion') "
                "WHERE FlowId = collection.flow_id LIMIT 1 "
                "SELECT * FROM source("
                "client_id=collection.request.client_id, "
                "flow_id=collection.flow_id, "
                "artifact=collection_completed.Flow.artifacts_with_results[0])"
            )

            results = self._vql(stub, artifact_query, max_wait=self.max_wait,
                                name="TheHive-KillProcess-Query")

            self.report({
                'message': results if results else
                           'Artifact ran but returned no rows (no matching process).',
                'dry_run': not self.really_do_it,
                'client_id': client_id,
                'client_os': os_name,
                'artifact': artifact_name,
                'target_exe': self.observable,
                'target_pid': pid_param,
            })

        except Exception as e:
            self.report({
                'message': f'UNHANDLED EXCEPTION: {type(e).__name__}: {e}',
            })
        finally:
            if self._channel is not None:
                try:
                    self._channel.close()
                except Exception:
                    pass

    def operations(self, raw):
        tag = ('velociraptor-kill-process-dry-run' if not self.really_do_it
               else 'velociraptor-kill-process-executed')
        return [self.build_operation('AddTagToCase', tag=tag)]


if __name__ == '__main__':
    VRKillProcess().run()
