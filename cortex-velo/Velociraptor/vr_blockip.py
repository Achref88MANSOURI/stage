#!/usr/bin/env python3
"""
VR_BlockIP — Cortex Responder
==============================
Triggered on an observable of dataType 'ip' (the malicious/IOC IP).

Steps:
  1. Read the triggering IP from data.data.
  2. Validate it is a plain IPv4 address before passing anywhere.
  3. Look up the parent case for 'hostname' / 'endpoint-ip' typed observables
     to resolve the target Velociraptor client.
  4. Ask the resolved client its OS (live, via collect_client on the
     built-in Generic.Client.Info artifact) -- NOT from the server's cached
     client index, which was found to be unreliable/empty when queried
     from this handler's own gRPC session.
  5. Collect the OS-appropriate artifact:
       windows -> Custom.Windows.Remediation.BlockIPExact
       linux   -> Custom.Linux.Remediation.BlockIPExact
     All firewall logic (rule add/remove, connectivity test, rollback)
     lives in the artifact itself.
  6. Report result and tag the case.

No internet connection required on the endpoint -- the artifacts are
self-contained.
"""

import json
import re
import time

import grpc
from cortexutils.responder import Responder
from thehive4py import TheHiveApi
from thehive4py.query.filters import Eq
import pyvelociraptor
from pyvelociraptor import api_pb2, api_pb2_grpc


# ── Constants ────────────────────────────────────────────────────────────────
ARTIFACT_BY_OS = {
    "windows": "Custom.Windows.Remediation.BlockIPExact",
    "linux":   "Custom.Linux.Remediation.BlockIPExact",
}
IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')


class VRBlockIP(Responder):
    def __init__(self):
        super().__init__()
        self.velociraptor_api_config = self.get_param(
            "config.velociraptor_api_config", None,
            "Velociraptor API config file path is required."
        )
        self.thehive_url = self.get_param(
            "config.thehive_url", None, "TheHive URL is required."
        )
        self.thehive_apikey = self.get_param(
            "config.thehive_apikey", None, "TheHive API key is required."
        )
        self.rule_name = self.get_param("config.rule_name", "VeloBlockIP", None)
        self.really_do_it = self.get_param("config.really_do_it", False, None)
        self.poll_timeout = self.get_param("config.poll_timeout_seconds", 120, None)
        self.poll_interval = self.get_param("config.poll_interval_seconds", 5, None)

    # ── TheHive ──────────────────────────────────────────────────────────────

    def _thehive(self):
        return TheHiveApi(url=self.thehive_url, apikey=self.thehive_apikey)

    def _find_endpoint_observables(self, case_id: str) -> dict:
        """Return {'hostname': str|None, 'endpoint_ip': str|None}."""
        api = self._thehive()
        result = {"hostname": None, "endpoint_ip": None}

        observables = api.case.find_observables(
            case_id=case_id,
            filters=(Eq("dataType", "hostname") | Eq("dataType", "endpoint-ip")),
        )

        for obs in observables:
            dt  = obs.get("dataType", "")
            val = obs.get("data", "")
            if dt == "hostname" and not result["hostname"]:
                result["hostname"] = val
            elif dt == "endpoint-ip" and not result["endpoint_ip"]:
                result["endpoint_ip"] = val

        return result

    # ── Velociraptor: server-side queries ───────────────────────────────────

    def _velo_stub(self):
        config = pyvelociraptor.LoadConfigFile(self.velociraptor_api_config)
        # NOTE: LoadConfigFile() returns a plain dict, not an object with
        # attributes -- use dict-style key access, not dot notation.
        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8"),
        )
        # Velociraptor's self-signed gRPC cert is issued for the name
        # "VelociraptorServer", not the connection IP -- override the TLS
        # target name check accordingly, or hostname verification fails.
        options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
        # IMPORTANT: keep a reference to the channel on self. If the
        # channel object has no durable reference (only the stub, which
        # wraps it), it can be garbage collected mid-operation, causing
        # later calls on the stub to silently return truncated/empty
        # response streams. This was confirmed live: OS-detection calls
        # succeeded, but the very next collect_client() call on the same
        # stub returned an empty stream (2 responses instead of the
        # expected 5) a few seconds after the channel was created.
        self._channel = grpc.secure_channel(
            config["api_connection_string"], creds, options
        )
        return api_pb2_grpc.APIStub(self._channel)

    @staticmethod
    def _vql_escape(value: str) -> str:
        """
        Escape a string for safe embedding inside a single-quoted VQL
        string literal. VQL uses backslash-escaping for embedded single
        quotes and backslashes, similar to many C-like query languages.
        target_ip is already regex-validated (IPV4_RE) before this is
        ever called, but rule_name is operator-configurable, so this
        escape is applied to both rather than relying on upstream
        validation alone.
        """
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _vql(self, stub, vql: str) -> list:
        """
        Run a VQL query SERVER-SIDE, return list of row dicts.
        NOTE: this executes on the Cortex/Velociraptor server's own query
        engine, NOT on a remote client. Only use this for server-side
        plugins (e.g. clients()). Never use this to ask a remote endpoint
        about itself (e.g. info()) -- use collect_client() for that
        (see _detect_os() and _collect_and_poll()).
        """
        request = api_pb2.VQLCollectorArgs(
            Query=[api_pb2.VQLRequest(Name="q", VQL=vql)]
        )
        rows = []
        for response in stub.Query(request):
            if response.Response:
                rows.extend(json.loads(response.Response))
        return rows

    def _resolve_client_id(self, stub, hostname=None, endpoint_ip=None) -> str:
        if hostname:
            vql = f"SELECT client_id FROM clients(search='host:{hostname}') LIMIT 1"
        elif endpoint_ip:
            # NOTE: clients(search='<ip>') does NOT match on IP -- confirmed
            # live (returns nothing for any IP tested). The proven-working
            # pattern is clients() with a WHERE last_ip =~ filter, which
            # matches Velociraptor's own recorded last-seen connection IP.
            # IMPORTANT: last_ip is the IP Velociraptor's server observed
            # the client connect FROM -- this can differ from the machine's
            # LAN/network-interface IP (e.g. when clients reach the server
            # over Tailscale or another overlay network). A Suricata alert
            # reports the LAN-visible IP, so this match will only succeed
            # if the endpoint-ip observable was populated with the same IP
            # Velociraptor itself sees as last_ip -- confirm this holds for
            # your environment before relying on this path for real alerts.
            vql = (
                "SELECT client_id, last_ip FROM clients() "
                f"WHERE last_ip =~ '{self._vql_escape(endpoint_ip)}' LIMIT 1"
            )
        else:
            self.error("No hostname or endpoint-ip observable found on case.")

        rows = self._vql(stub, vql)
        if rows and rows[0].get("client_id"):
            return rows[0]["client_id"]

        self.error(
            f"No Velociraptor client found for '{hostname or endpoint_ip}'."
        )

    # ── Velociraptor: client-side OS detection ──────────────────────────────

    def _detect_os(self, stub, client_id: str) -> str:
        """
        Ask the resolved client its OS, live, via collect_client(). Returns
        'windows' or 'linux' (lowercase). Errors out via self.error() if the
        flow doesn't complete or the OS is unrecognized/unsupported.

        This intentionally does NOT use the server-side clients()/
        client_info() lookups -- both returned empty/unreliable results when
        tested against a live client from this handler's own gRPC session
        during development. Querying the client directly via collect_client()
        with the built-in Generic.Client.Info artifact was confirmed working
        live (SELECT OS FROM info(), run on the endpoint, reliably returned
        the correct OS in manual Shell testing).
        """
        schedule_vql = (
            "SELECT collect_client("
            f"  client_id='{client_id}',"
            "  artifacts=['Generic.Client.Info'],"
            "  spec=dict()"
            ") AS Flow FROM scope()"
        )
        rows = self._vql(stub, schedule_vql)
        flow_id = None
        if rows:
            flow_id = rows[0].get("Flow", {}).get("flow_id")
        if not flow_id:
            self.error("OS detection: collect_client() returned no flow_id.")

        elapsed = 0
        finished = False
        while elapsed < self.poll_timeout:
            status = self._vql(
                stub,
                f"SELECT * FROM flows(client_id='{client_id}', flow_id='{flow_id}')"
            )
            if status:
                state = status[0].get("state", "")
                if state == "FINISHED":
                    finished = True
                    break
                if state == "ERROR":
                    self.error(
                        f"OS detection flow {flow_id} ended in ERROR: {status[0]}"
                    )
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval

        if not finished:
            self.error(
                f"OS detection flow {flow_id} did not complete within "
                f"{self.poll_timeout}s."
            )

        result_vql = (
            f"SELECT OS FROM source(client_id='{client_id}', flow_id='{flow_id}', "
            "artifact='Generic.Client.Info/BasicInformation')"
        )
        result_rows = self._vql(stub, result_vql)
        if not result_rows or not result_rows[0].get("OS"):
            self.error(
                f"OS detection flow {flow_id} completed but returned no OS value."
            )

        os_name = result_rows[0]["OS"].strip().lower()
        if os_name not in ARTIFACT_BY_OS:
            self.error(
                f"Unsupported client OS '{os_name}' -- no BlockIP artifact "
                f"available for this platform."
            )
        return os_name

    # ── Velociraptor: execute the remediation artifact ──────────────────────

    def _collect_and_poll(self, stub, client_id: str, target_ip: str,
                           artifact_name: str) -> dict:
        # NOTE: VQL is NOT JSON. Earlier versions of this method built the
        # spec argument with json.dumps(), producing a raw JSON object
        # literal (e.g. {"TargetIP": "1.2.3.4", "ReallyDoIt": false}) --
        # this is invalid VQL syntax and caused collect_client() to fail
        # to parse silently (confirmed live: VQL parser error "unexpected
        # token... expected <select>" when tested directly in a Notebook).
        # VQL requires its own dict(key=value, ...) call syntax, TRUE/FALSE
        # booleans (not true/false), and backtick-quoting for identifiers
        # containing dots (artifact names like Custom.Linux.Remediation.X).
        really_do_it_vql = "TRUE" if self.really_do_it else "FALSE"
        spec_vql = (
            "dict(`" + artifact_name + "`=dict("
            "TargetIP='" + self._vql_escape(target_ip) + "', "
            "RuleName='" + self._vql_escape(self.rule_name) + "', "
            "ReallyDoIt=" + really_do_it_vql + ", "
            "RemoveRule=FALSE))"
        )

        schedule_vql = (
            f"SELECT collect_client("
            f"  client_id='{client_id}',"
            f"  artifacts=['{artifact_name}'],"
            f"  spec={spec_vql}"
            f") AS Flow FROM scope()"
        )

        rows = self._vql(stub, schedule_vql)
        flow_id = None
        if rows:
            flow_id = rows[0].get("Flow", {}).get("flow_id")

        if not flow_id:
            self.error("collect_client() returned no flow_id.")

        # Poll
        elapsed = 0
        while elapsed < self.poll_timeout:
            status = self._vql(
                stub,
                f"SELECT * FROM flows(client_id='{client_id}', flow_id='{flow_id}')"
            )
            if status:
                state = status[0].get("state", "")
                if state == "FINISHED":
                    return {"flow_id": flow_id, "state": state, "detail": status[0]}
                if state == "ERROR":
                    self.error(
                        f"Velociraptor flow {flow_id} ended in ERROR: {status[0]}"
                    )
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval

        self.error(
            f"Velociraptor flow {flow_id} did not complete within {self.poll_timeout}s."
        )

    # ── Main ─────────────────────────────────────────────────────────────────

    def run(self):
        # Observable type guard.
        # NOTE: self.data_type reflects the responder's manifest-level
        # dataTypeList entry (now "thehive:case_artifact", required for this
        # responder to appear in TheHive's picker -- see deployment notes).
        # It is NOT the triggering observable's own type. The actual
        # observable dataType must be read from data.dataType directly.
        observable_type = self.get_param(
            "data.dataType", None, "Cannot determine observable dataType."
        )
        if observable_type != "ip":
            self.error(
                f"VR_BlockIP must be triggered on an 'ip' observable, got "
                f"'{observable_type}'."
            )

        target_ip = self.get_param(
            "data.data", None, "Missing observable value (IP address)."
        )

        # Validate BEFORE passing to Velociraptor
        if not IPV4_RE.match(target_ip):
            self.error(
                f"Observable value '{target_ip}' is not a valid IPv4 address or CIDR. "
                "Aborting."
            )

        # Resolve endpoint identity from parent case.
        # TheHive 5 embeds the full case object at data.case -- the case ID
        # lives at data.case._id. data._parent does NOT exist in TheHive 5
        # observable payloads (confirmed live during VR_KillProcess session).
        case_id = self.get_param(
            "data.case._id", None, "Cannot determine parent case ID."
        )
        endpoint_obs = self._find_endpoint_observables(case_id)
        hostname     = endpoint_obs["hostname"]
        endpoint_ip  = endpoint_obs["endpoint_ip"]

        if not hostname and not endpoint_ip:
            self.error(
                "No 'hostname' or 'endpoint-ip' observable found on the case. "
                "Add the target endpoint identity before triggering this responder."
            )

        # Connect to Velociraptor
        stub = self._velo_stub()
        client_id = self._resolve_client_id(
            stub, hostname=hostname, endpoint_ip=endpoint_ip
        )

        # Detect OS live from the client itself, then pick the matching
        # artifact. Do NOT trust server-side client index lookups here --
        # confirmed unreliable/empty when tested against this environment.
        os_name = self._detect_os(stub, client_id)
        artifact_name = ARTIFACT_BY_OS[os_name]

        # Execute the OS-appropriate artifact
        result = self._collect_and_poll(stub, client_id, target_ip, artifact_name)

        # Tag case
        api = self._thehive()
        tag = (
            "velociraptor-block-ip-executed"
            if self.really_do_it
            else "velociraptor-block-ip-dry-run"
        )
        api.case.update(case_id, fields={"addTags": [tag]})

        mode = "EXECUTED" if self.really_do_it else "DRY-RUN"
        endpoint_label = f"host:{hostname}" if hostname else f"ip:{endpoint_ip}"

        self.report({
            "success":             True,
            "mode":                mode,
            "target_ip":           target_ip,
            "client_id":           client_id,
            "client_os":           os_name,
            "artifact_used":       artifact_name,
            "resolved_from":       "hostname" if hostname else "endpoint-ip",
            "endpoint_identifier": hostname or endpoint_ip,
            "rule_name":           self.rule_name,
            "flow_id":             result["flow_id"],
            "flow_state":          result["state"],
            "message": (
                f"[{mode}] IP {target_ip} blocked (inbound + outbound) on "
                f"{endpoint_label} ({os_name}) via flow {result['flow_id']}."
                if self.really_do_it else
                f"[DRY-RUN] Would block {target_ip} on {endpoint_label} ({os_name}). "
                "Set really_do_it=true in Cortex config to execute."
            ),
        })

    def operations(self, raw):
        return [self.build_operation("AddTagToCase", tag="velociraptor-block-ip")]


if __name__ == "__main__":
    VRBlockIP().run()
