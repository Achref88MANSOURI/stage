#!/usr/bin/env python3
"""
VR_IsolateHost -- Cortex responder for Velociraptor-based network isolation.

Triggers directly on 'endpoint-ip' or 'hostname' observables -- the
triggering observable IS the target, no case-observable lookup needed
(unlike VR_KillProcess). Resolves OS via Generic.Client.Info, dispatches
to the matching Custom.<OS>.Remediation.IsolateHost artifact, and tags
the case via thehive4py.
"""
import json
import grpc
import yaml

from cortexutils.responder import Responder
from pyvelociraptor import api_pb2, api_pb2_grpc
from thehive4py import TheHiveApi

ARTIFACT_BY_OS = {
    "windows": "Custom.Windows.Remediation.IsolateHost",
    "linux": "Custom.Linux.Remediation.IsolateHost",
}


class VRIsolateHost(Responder):
    def __init__(self):
        Responder.__init__(self)
        self._channel = None

        self.configpath = self.get_param(
            "config.velociraptor_api_config", None, "velociraptor_api_config is required!"
        )
        self.thehive_url = self.get_param("config.thehive_url", None, "thehive_url is required!")
        self.thehive_apikey = self.get_param(
            "config.thehive_apikey", None, "thehive_apikey is required!"
        )
        self.server_address = self.get_param(
            "config.velociraptor_server_address", None,
            "velociraptor_server_address is required!"
        )
        self.allow_interface = self.get_param("config.allow_interface", "")
        self.remove_policy = self.get_param("config.remove_policy", False)
        self.really_do_it = self.get_param("config.really_do_it", False)
        self.poll_timeout = int(self.get_param("config.poll_timeout_seconds", 120))

        self.observable_type = self.get_param("data.dataType", None, "Data type is empty")
        self.observable = self.get_param("data.data", None, "Data missing!")
        self.case_id = self.get_param("data.case._id", None)

        self.config = yaml.load(open(self.configpath).read(), Loader=yaml.FullLoader)

    # ---- Velociraptor gRPC ----

    def _get_stub(self):
        creds = grpc.ssl_channel_credentials(
            root_certificates=self.config["ca_certificate"].encode("utf8"),
            private_key=self.config["client_private_key"].encode("utf8"),
            certificate_chain=self.config["client_cert"].encode("utf8"),
        )
        options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
        self._channel = grpc.secure_channel(self.config["api_connection_string"], creds, options)
        return api_pb2_grpc.APIStub(self._channel)

    def _vql(self, stub, query, max_wait=60):
        request = api_pb2.VQLCollectorArgs(
            max_wait=max_wait,
            Query=[api_pb2.VQLRequest(Name="VR_IsolateHost-Query", VQL=query)],
        )
        rows = []
        for response in stub.Query(request):
            try:
                rows.extend(json.loads(response.Response))
            except Exception:
                pass
        return rows

    # ---- Target resolution -- trigger IS the target, no case lookup ----

    def _resolve_client_id(self, stub):
        if self.observable_type == "endpoint-ip":
            query = f"SELECT client_id FROM clients() WHERE last_ip =~ '^{self.observable}:'"
        elif self.observable_type == "hostname":
            query = f"SELECT client_id FROM clients(search='host:{self.observable}')"
        else:
            self.report({"message": f"Unsupported dataType for IsolateHost: {self.observable_type}"})
            return None

        rows = self._vql(stub, query, max_wait=60)
        if not rows:
            self.report({"message": "Could not find a matching client."})
            return None
        return rows[0]["client_id"]

    def _detect_os(self, stub, client_id):
        query = (
            f"LET collection <= collect_client(client_id='{client_id}', "
            "artifacts=['Generic.Client.Info'], spec=dict())\n"
            "LET completed <= SELECT * FROM watch_monitoring("
            "artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id LIMIT 1\n"
            "SELECT * FROM source(client_id=collection.request.client_id, "
            "flow_id=collection.flow_id, artifact='Generic.Client.Info/BasicInformation')"
        )
        rows = self._vql(stub, query, max_wait=self.poll_timeout)
        if not rows or "OS" not in rows[0]:
            return None
        return rows[0]["OS"].lower()

    # ---- Spec construction -- native VQL dict(), never json.dumps() ----

    def _build_spec(self, os_name):
        artifact = ARTIFACT_BY_OS[os_name]
        remove = "TRUE" if self.remove_policy else "FALSE"
        really = "TRUE" if self.really_do_it else "FALSE"

        if os_name == "linux":
            cidr = self.server_address
            if "/" not in cidr:
                cidr = cidr + "/32"
            params = (
                f'VelociraptorServerCIDR="{cidr}", '
                f'AllowInterface="{self.allow_interface}", '
                f'RemovePolicy={remove}, ReallyDoIt={really}'
            )
        else:  # windows
            params = f'VelociraptorServerIP="{self.server_address}", RemovePolicy={remove}, ReallyDoIt={really}'

        return f'dict(`{artifact}`=dict({params}))'

    # ---- TheHive status tag ----
    # Uses case.update(addTags=...) -- the CONFIRMED-working thehive4py 2.1.0
    # call. A dedicated case-note/comment write needs its exact method name
    # verified against this thehive4py version before being trusted -- not
    # attempted here.

    def _tag_case(self, action_label):
        try:
            hive = TheHiveApi(url=self.thehive_url, apikey=self.thehive_apikey)
            hive.case.update(self.case_id, fields={"addTags": [f"VR_IsolateHost:{action_label}"]})
        except Exception:
            pass  # non-fatal -- isolation result still reported to Cortex either way

    def run(self):
        try:
            Responder.run(self)
            stub = self._get_stub()

            client_id = self._resolve_client_id(stub)
            if not client_id:
                return

            os_name = self._detect_os(stub, client_id)
            if os_name not in ARTIFACT_BY_OS:
                self.report({"message": f"Unsupported or undetected OS: {os_name}"})
                return

            spec_vql = self._build_spec(os_name)
            artifact = ARTIFACT_BY_OS[os_name]

            collect_query = (
                f"LET collection <= collect_client(client_id='{client_id}', "
                f"artifacts=['{artifact}'], spec={spec_vql})\n"
                "LET completed <= SELECT * FROM watch_monitoring("
                "artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id LIMIT 1\n"
                f"SELECT * FROM source(client_id=collection.request.client_id, "
                f"flow_id=collection.flow_id, artifact='{artifact}')"
            )
            results = self._vql(stub, collect_query, max_wait=self.poll_timeout)

            action_label = "un-isolated" if self.remove_policy else "isolated"
            mode_label = "REAL" if self.really_do_it else "DRY-RUN"
            self._tag_case(f"{mode_label}-{action_label}")

            self.report({
                "client_id": client_id,
                "os": os_name,
                "artifact": artifact,
                "mode": mode_label,
                "action": action_label,
                "results": results,
            })

        except Exception as e:
            self.report({"message": f"UNHANDLED EXCEPTION: {str(e)}"})
        finally:
            if self._channel:
                self._channel.close()

    def operations(self, raw):
        action_label = "un-isolated" if self.remove_policy else "isolated"
        return [self.build_operation("AddTagToArtifact", tag=f"vr-{action_label}")]


if __name__ == "__main__":
    VRIsolateHost().run()
