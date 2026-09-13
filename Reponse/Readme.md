# SOC Pipeline — Automated Response Mechanism
## TheHive → Cortex → Velociraptor Response Layer

**Scope of this document:** the automated endpoint-response capability of the SOC pipeline — how a case observable in TheHive triggers a parameterized, dry-run-gated action on a managed endpoint via Cortex and Velociraptor. This document describes the system as implemented: its architecture, the code logic of each component, and the procedure to deploy and operate it. It does not cover detection, enrichment, or AI triage, which are documented separately.

---

## 1. Purpose and Scope of the Response Layer

The SOC pipeline implements endpoint response as three coupled actions, each delivered through a dedicated Cortex responder and a dedicated Velociraptor artifact pair (one Linux variant, one Windows variant):

| Action | Cortex responder | Triggering observable | Velociraptor artifacts |
|---|---|---|---|
| Terminate a process | `VR_KillProcess` (folder: `Velociraptor_KillProcess/`) | `process-path` | `Custom.Linux.Remediation.KillProcessExact`, `Custom.Windows.Remediation.KillProcessExact` |
| Block an IP address | `VR_BlockIP` | `ip` | `Custom.Linux.Remediation.BlockIPExact`, `Custom.Windows.Remediation.BlockIPExact` |
| Isolate an endpoint | `VR_IsolateHost` | `endpoint-ip`, `hostname` | `Custom.Linux.Remediation.IsolateHost`, `Custom.Windows.Remediation.IsolateHost` |

Each responder is a specialized, parameterized action rather than a generic "run any named artifact" wrapper. Every response artifact enforces a `ReallyDoIt` dry-run gate: by default, the artifact reports the exact commands it would execute without running them, and only performs the action when `ReallyDoIt=TRUE` is explicitly passed. All response logic is self-contained in Velocidex Query Language (VQL) and native OS command execution (`execve`, `netsh`) — no artifact depends on internet access from the endpoint.

---

## 2. Architecture

### 2.1 Component roles

- **TheHive** — case management and the human-in-the-loop approval point. An analyst selects an observable on a case and triggers the corresponding Cortex responder from the case UI.
- **Cortex** — the responder execution engine. It receives the trigger, resolves which Python handler to run, and passes it the job context (observable data, parent case ID, configured parameters).
- **Velociraptor** — the endpoint agent platform. The handler connects to the Velociraptor server over gRPC, resolves the target client, and dispatches an OS-specific VQL artifact that performs the actual endpoint action.

### 2.2 Directory layout on the Cortex host

```
/opt/cortex/Cortex-Analyzers/responders/
│
├── Velociraptor/                       ← execution root: all handler code lives here
│   ├── velociraptor_flow.py            ← router (dispatches unmatched dataTypes to upstream base responder)
│   ├── vr_killprocess.py               ← VRKillProcess handler
│   ├── vr_blockip.py                   ← VRBlockIP handler
│   ├── vr_isolatehost.py               ← VRIsolateHost handler
│   └── requirements.txt
│
├── Velociraptor_KillProcess/           ← manifest for the KillProcess responder
│   └── velociraptor_flow.json          ← dataTypeList: ["process-path"], command → Velociraptor/vr_killprocess.py
│
├── VR_BlockIP/                         ← manifest for the BlockIP responder
│   └── vr_blockip.json                 ← dataTypeList: ["thehive:case_artifact"], command → Velociraptor/vr_blockip.py
│
└── VR_IsolateHost/                     ← manifest for the IsolateHost responder
    └── velociraptor_flow.json          ← dataTypeList: ["thehive:case_artifact"], command → Velociraptor/vr_isolatehost.py
```

Each `command` field is a path relative to the responders root. All three manifests point into the shared `Velociraptor/` folder — none execute a script from their own folder. This is a deliberate, load-bearing design choice (§2.3), not an inconsistency.

### 2.3 Why the handler code is centralized in `Velociraptor/`

Cortex reads a responder's `command` field from its manifest **once, at first registration**, and caches it. It does not re-read the manifest file from disk on subsequent runs — only a full unregister/re-register cycle updates the cached path. Consequently, whichever path is correct the first time a responder is saved is the path Cortex will invoke for the lifetime of that registration.

Given this constraint, keeping every handler's actual code in one shared folder (`Velociraptor/`) rather than distributed across each responder's own folder has two practical benefits:
- A `command` field only has to be set correctly once per responder, pointing at a stable location, rather than risking drift between a manifest folder and a same-named script folder.
- Handler code that needs to evolve (bug fixes, new parameters) is edited in a single, predictable place, independent of which manifest folder is registered under which name.

### 2.4 Dispatch logic (`velociraptor_flow.py`)

`velociraptor_flow.py` is present as a router for any dataType not explicitly owned by one of the three dedicated handlers. It is not on the execution path for `VR_KillProcess`, `VR_BlockIP`, or `VR_IsolateHost` — each of those manifests points `command` directly at its own handler file. The router's role is to preserve compatibility with the upstream generic Velociraptor responder (Cortex-Analyzers, Wes Lambert, AGPL-V3) for any observable type outside the three specialized actions:

```python
job_dir = sys.argv[1] if len(sys.argv) > 1 else None
if job_dir and os.path.isfile(f"{job_dir}/input/input.json"):
    with open(f"{job_dir}/input/input.json") as f:
        raw = json.load(f)
else:
    raw = json.load(sys.stdin)

observable_datatype = raw.get("data", {}).get("dataType", "")

if observable_datatype == "process-path":
    from vr_killprocess import VRKillProcess
    VRKillProcess().run()
elif observable_datatype == "ip":
    from vr_blockip import VRBlockIP
    VRBlockIP().run()
else:
    # upstream generic Velociraptor responder — unchanged
    VelociraptorBase().run()
```

Cortex invokes a responder's `command` with the job directory as `sys.argv[1]`; the router (and every handler) reads `input.json` from `{job_dir}/input/`, with `stdin` only as a fallback. Reading `stdin` directly without this fallback order causes the process to hang indefinitely, since Cortex does not write to it.

---

## 3. Common Handler Logic

All three handlers (`vr_killprocess.py`, `vr_blockip.py`, `vr_isolatehost.py`) follow the same execution skeleton. This section describes that shared logic once; §4 covers what differs per responder.

### 3.1 Parameter resolution (`__init__`)

Each handler is a `cortexutils.responder.Responder` subclass. On construction it reads, via `self.get_param(...)`:
- The Velociraptor API client config path (`config.velociraptor_api_config` or, for KillProcess, `config.velociraptor_client_config` / a base64 variant for containerized deployments).
- TheHive connection parameters (`config.thehive_url`, `config.thehive_apikey`).
- Behavior flags: `config.really_do_it` (default `False`), and for IsolateHost, `config.remove_policy` (default `False`) and `config.allow_interface`.
- The triggering observable: `data.dataType` and `data.data`.
- The parent case ID: `data.case._id` — this is the TheHive 5 field for the case identifier. It replaces the `data._parent` field used in TheHive 4; handlers must read `data.case._id`, not `data._parent`.

Missing required parameters call `self.error(...)`, which reports failure to Cortex and TheHive with a descriptive message.

### 3.2 gRPC connection to Velociraptor

```python
creds = grpc.ssl_channel_credentials(
    root_certificates=config["ca_certificate"].encode("utf8"),
    private_key=config["client_private_key"].encode("utf8"),
    certificate_chain=config["client_cert"].encode("utf8"),
)
options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
self._channel = grpc.secure_channel(config["api_connection_string"], creds, options)
stub = api_pb2_grpc.APIStub(self._channel)
```

Two properties of this connection are required for correct operation:
- **`grpc.ssl_target_name_override` must be set to `"VelociraptorServer"`.** Velociraptor issues its self-signed gRPC certificate for that fixed name, not for the server's connection IP. Without the override, gRPC's TLS hostname verification rejects the connection regardless of certificate validity.
- **The channel object must be stored on `self`** (`self._channel`), not left as a local variable. A handler makes multiple sequential gRPC calls across a single run (OS detection, artifact collection, flow polling); if the channel has no durable reference, it can be garbage-collected mid-run, silently truncating a later response stream. `VRIsolateHost` and `VRKillProcess` additionally close the channel explicitly in a `finally` block at the end of `run()`.

### 3.3 Running VQL queries

Every handler implements a `_vql(stub, query)` helper that wraps a single VQL statement in a `VQLCollectorArgs` request, iterates the streamed response, and flattens all returned JSON rows into a Python list:

```python
def _vql(self, stub, vql, max_wait=60, name="Query"):
    request = api_pb2.VQLCollectorArgs(
        max_wait=max_wait,
        Query=[api_pb2.VQLRequest(Name=name, VQL=vql)],
    )
    rows = []
    for response in stub.Query(request):
        if response.Response:
            rows.extend(json.loads(response.Response))
    return rows
```

This helper is used both for **server-side** queries (e.g. `clients()`, evaluated by the Velociraptor server's own query engine) and to **schedule client-side collections** (`collect_client(...)`, which asks a specific endpoint to run an artifact). The two are not interchangeable: `clients()` and its filters run against the server's client index; `info()` or a custom artifact's own logic runs on the endpoint itself and must be reached via `collect_client()`.

### 3.4 Resolving the Velociraptor client

Handlers resolve a target endpoint's Velociraptor `client_id` using one of two VQL patterns, chosen by which identity observable is available:

```python
# by hostname
"SELECT client_id FROM clients(search='host:{hostname}') LIMIT 1"

# by IP — clients(search='<ip>') does not match on IP; the working pattern
# uses an anchored regex against the server's recorded last-seen address
"SELECT client_id FROM clients() WHERE last_ip =~ '^{ip}:'"
```

`last_ip` is stored by Velociraptor as `"ip:port"`, so exact-equality or unanchored matching against a bare IP fails; the anchored regex against the `ip:` prefix is required. `last_ip` reflects the address the server observed the client connect *from*, which is not necessarily the same address a network detection reports for that host (for example, when the endpoint reaches the server over an overlay network such as Tailscale rather than its LAN interface) — the `endpoint-ip` / `hostname` observable populated on the case must correspond to what Velociraptor itself records for the match to succeed.

### 3.5 Live OS detection

No handler assumes or caches an endpoint's operating system. Each run detects it live by scheduling the built-in `Generic.Client.Info` artifact against the resolved client, polling the flow to completion, and reading the `OS` field from its `BasicInformation` result source:

```python
schedule_vql = (
    "SELECT collect_client(client_id='{client_id}', "
    "artifacts=['Generic.Client.Info'], spec=dict()) AS Flow FROM scope()"
)
# poll: SELECT state FROM flows(client_id=..., flow_id=...) until FINISHED or ERROR
result_vql = (
    "SELECT OS FROM source(client_id='{client_id}', flow_id='{flow_id}', "
    "artifact='Generic.Client.Info/BasicInformation')"
)
```

The detected value (`"windows"` or `"linux"`, lowercased) selects the artifact to dispatch via a static map:

```python
ARTIFACT_BY_OS = {
    "windows": "Custom.Windows.Remediation.<Action>",
    "linux":   "Custom.Linux.Remediation.<Action>",
}
```

An undetected or unrecognized OS value aborts the run with a descriptive error rather than defaulting to either platform.

### 3.6 Passing parameters to the Velociraptor artifact

`collect_client()`'s `spec` argument must be constructed as a **native VQL `dict()` expression with a backtick-quoted artifact name**, because the artifact name contains dots (e.g. `Custom.Linux.Remediation.KillProcessExact`), which VQL requires backtick-quoting to parse as a single identifier:

```python
spec_vql = (
    "dict(`" + artifact_name + "`=dict("
    "TargetExe='" + escaped_value + "', "
    "TargetPid=" + pid_param + ", "
    "ReallyDoIt=" + really_do_it_vql + "))"
)
```

`ReallyDoIt` and other booleans are emitted as the VQL literals `TRUE`/`FALSE`, not Python/JSON `true`/`false`. Building this string with `json.dumps()` or Python dict-unpacking produces syntactically invalid VQL — the collection call fails to parse and returns no result, with no exception raised in the handler. All string values interpolated into VQL (IP addresses, hostnames, rule names, executable paths) are passed through a `_vql_escape()` helper that escapes backslashes and single quotes before insertion, to prevent malformed or injected VQL from a value that contains those characters.

### 3.7 Collecting and polling the flow

Once scheduled, the handler polls `flows(client_id=..., flow_id=...)` at a configurable interval (`config.poll_interval_seconds`, default 5s) until `state` reaches `FINISHED` or `ERROR`, bounded by `config.poll_timeout_seconds` (default 120s for BlockIP/IsolateHost; `config.query_max_duration`, default 600s, for KillProcess). A timeout or `ERROR` state aborts the run with the flow ID and last known state reported to Cortex for operator diagnosis.

### 3.8 Reporting and case tagging

On completion, each handler calls `self.report({...})` with a structured result (mode — dry-run or executed, target value, client ID, detected OS, artifact used, flow ID, and a human-readable message), which becomes the Cortex job report visible in TheHive's observable/case history. Handlers additionally tag the parent case via `thehive4py` to leave a durable, queryable record of the action independent of the Cortex job log:

```python
api = TheHiveApi(url=self.thehive_url, apikey=self.thehive_apikey)
api.case.update(case_id, fields={"addTags": [tag]})
```

Tag values encode both the action and its mode (e.g. `velociraptor-block-ip-executed` vs. `velociraptor-block-ip-dry-run`), so a case's tag list alone shows whether a real action was taken. `VRIsolateHost` wraps its tagging call in a `try/except` that swallows failures non-fatally — isolation success or failure is still reported to Cortex even if the TheHive tagging call itself fails, since the endpoint-side result is not contingent on it.

---

## 4. Per-Responder Detail

### 4.1 `VR_KillProcess`

**Trigger:** `process-path` observable.
**Manifest:** `Velociraptor_KillProcess/velociraptor_flow.json` — `dataTypeList: ["process-path"]`, `command: "Velociraptor/vr_killprocess.py"`.

**Targeting model:** the triggering observable identifies *what* to kill, not *where*. The handler queries TheHive for the parent case's `hostname`, `endpoint-ip`, and `process-pid` observables via `thehive4py`:

```python
filt = (
    Eq(field="dataType", value="hostname")
    | Eq(field="dataType", value="endpoint-ip")
    | Eq(field="dataType", value="process-pid")
)
results = hive.case.find_observables(case_id=self.case_id, filters=filt)
```

`thehive4py` 2.1.0 does not provide an `Or()` filter class; disjunction is expressed by chaining `Eq()` instances with the `|` operator, as shown above. Hostname is preferred for client resolution when present, falling back to `endpoint-ip`. If a `process-pid` observable is also present on the case, it is passed to the artifact as a secondary filter; if absent, `TargetPid=0` is passed, meaning the artifact matches on executable path alone.

**Artifact parameters:** `TargetExe` (string, required), `TargetPid` (int, `0` = no PID filter), `ReallyDoIt` (bool).

**Artifact logic** (`Custom.Linux.Remediation.KillProcessExact`, mirrored for Windows with case-insensitive path matching):

```
LET me = SELECT Pid FROM pslist(pid=getpid())

LET targets = SELECT Name AS ProcessName, Exe, CommandLine, Pid
  FROM pslist()
  WHERE Exe = TargetExe
    AND (TargetPid = 0 OR Pid = TargetPid)
    AND NOT Pid IN me.Pid

SELECT ProcessName, Exe, CommandLine, Pid,
  if(condition = ReallyDoIt, then = pskill(pid=Pid), else = "DRY_RUN...") AS Result
FROM targets
```

The artifact matches on exact executable path equality (not a substring or regex), optionally narrowed by PID, and explicitly excludes its own process from the candidate set (`NOT Pid IN me.Pid`) so the collection cannot terminate itself. No process is killed unless `ReallyDoIt=TRUE`.

### 4.2 `VR_BlockIP`

**Trigger:** `ip` observable.
**Manifest:** `VR_BlockIP/vr_blockip.json` — `dataTypeList: ["thehive:case_artifact"]`, `command: "Velociraptor/vr_blockip.py"`.

**Targeting model:** identical case-observable lookup pattern to KillProcess, restricted to `hostname` / `endpoint-ip`. The triggering `ip` value is validated against an IPv4/CIDR regex (`^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$`) before any further processing; a malformed value aborts immediately without contacting Velociraptor.

**Artifact parameters:** `TargetIP` (string, required), `RuleName` (string, default `"VeloBlockIP"`), `ReallyDoIt` (bool), `RemoveRule` (bool — rollback mode, takes precedence over `ReallyDoIt` when both are set).

**Artifact logic** (`Custom.Linux.Remediation.BlockIPExact`; Windows variant uses `netsh advfirewall firewall add rule` in place of `iptables`):

- Re-validates `TargetIP` against the same IPv4/CIDR pattern independently inside the artifact (defense in depth — the artifact does not trust the caller's validation alone).
- Builds a deterministic iptables comment tag, `<RuleName>-<TargetIP>`, since iptables rules have no native name field; this tag is what rollback and idempotency checks search for.
- Checks for existing matching rules via `iptables -C` (check mode) before adding, so re-running the artifact against an already-blocked IP is a no-op rather than a duplicate rule.
- Applies inbound (`INPUT … DROP`) and outbound (`OUTPUT … DROP`) rules via `execve`, with the target IP passed as a single argv element (never interpolated into a shell string).
- **Post-apply connectivity verification:** after applying the block, the artifact extracts the Velociraptor frontend host/port from its own `config.server_urls` and issues an HTTPS request to it (`http_client(url=..., disable_ssl_security=TRUE)`, checking for a `200` response against `/server.pem`). If this check fails, the artifact automatically deletes the rules it just added and reports a `connectivity-fail-rollback` result — the artifact will not leave an endpoint in a state where it has cut its own management channel.
- `RemoveRule=TRUE` deletes the tagged rules directly, independent of the above flow.
- `ReallyDoIt=FALSE` short-circuits to a dry-run report describing the rules that would be added, without any `execve` call.

### 4.3 `VR_IsolateHost`

**Trigger:** `endpoint-ip` or `hostname` observable, directly.
**Manifest:** `VR_IsolateHost/velociraptor_flow.json` — `dataTypeList: ["thehive:case_artifact"]`, `command: "Velociraptor/vr_isolatehost.py"`.

**Targeting model:** unlike the other two responders, the triggering observable *is* the target — no case-observable lookup is performed. Client resolution reads `data.dataType` directly:

```python
if self.observable_type == "endpoint-ip":
    query = f"SELECT client_id FROM clients() WHERE last_ip =~ '^{self.observable}:'"
elif self.observable_type == "hostname":
    query = f"SELECT client_id FROM clients(search='host:{self.observable}')"
```

**Required configuration parameter — `velociraptor_server_address`:** the address the *target endpoint itself* uses to reach the Velociraptor frontend, per that endpoint's own `client.config.yaml` (`server_urls`), not the LAN address of the Velociraptor server. This value is whitelisted by the artifact so the endpoint retains management connectivity while every other route is dropped. An incorrect value here isolates the endpoint from its own management channel with no remote recovery path — this is a required field precisely because a wrong or blank value produces a silent, one-way lockout. An optional `allow_interface` parameter (Linux only) additionally whitelists an entire named interface (e.g. an overlay-network interface) as a broader safety margin alongside the single-address whitelist.

**Artifact parameters:**
- Linux (`Custom.Linux.Remediation.IsolateHost`): `VelociraptorServerCIDR`, `AllowInterface` (optional), `RemovePolicy` (bool), `ReallyDoIt` (bool).
- Windows (`Custom.Windows.Remediation.IsolateHost`): `VelociraptorServerIP`, `RemovePolicy` (bool), `ReallyDoIt` (bool).

**Linux artifact logic:** creates two dedicated iptables chains, `VR_ISOLATE_IN` and `VR_ISOLATE_OUT`. Within them, the whitelisted server CIDR (and optional interface) are permitted via `RETURN` rules, followed by a catch-all `DROP`. The chains are then jumped into from position **1** of `INPUT` and `OUTPUT` — inserting at position 1 (rather than appending) guarantees the isolation rule is evaluated before any pre-existing rule, without deleting or reordering the existing ruleset. Un-isolation (`RemovePolicy=TRUE`) removes the two jump rules and flushes/deletes the two chains, which fully restores the pre-isolation ruleset because no existing rule was ever modified.

**Windows artifact logic:** creates `VR_ISOLATE_IN` / `VR_ISOLATE_OUT` `netsh advfirewall` allow rules scoped to `VelociraptorServerIP` **before** applying `firewallpolicy blockinbound,blockoutbound` to all profiles — this ordering is required so the endpoint is never in a state where the block policy is active without the allow rule already in place. Un-isolation restores `firewallpolicy blockinbound,allowoutbound`, Windows Firewall's factory default, *before* deleting the allow rules, so connectivity returns even if a later step in the sequence fails. This is explicitly documented in the artifact as restoring factory default, not necessarily the host's original policy — if the original policy was GPO-managed or otherwise customized beyond factory default, that state is not recovered by this artifact.

Both variants support a dry-run mode identical in structure to the other two artifacts: when `ReallyDoIt=FALSE`, each planned command is reported with a `"DRY RUN - not executed"` result instead of being passed to `execve`.

---

## 5. Deployment and Implementation Procedure

### 5.1 Prerequisites

- A running Velociraptor server, with at least one enrolled client per target OS.
- A running Cortex instance with network access to the Velociraptor server's API port (default `8001`) and to TheHive's API.
- TheHive custom observable types created for endpoint identity: `hostname`, `endpoint-ip` (distinct from IOC/threat-intel `ip` observables — `ioc: false`), and `process-pid` for KillProcess targeting.
- Python dependencies installed in the Cortex virtualenv: `cortexutils`, `thehive4py>=2.1.0`, `grpcio`, `grpcio-tools`, `pyvelociraptor`, `cryptography`, `PyYAML`.

### 5.2 Generate and install the Velociraptor API client config

On the Velociraptor server:

```bash
velociraptor --config /path/to/server.config.yaml config api_client \
  --name cortex_responder --role administrator api_client.yaml
```

Transfer the resulting `api_client.yaml` to the Cortex host and restrict its permissions:

```bash
sudo mkdir -p /opt/cortex/velociraptor
sudo mv api_client.yaml /opt/cortex/velociraptor/api_client.yaml
sudo chown -R thehive:thehive /opt/cortex/velociraptor/
sudo chmod 600 /opt/cortex/velociraptor/api_client.yaml
```

Verify network reachability from the Cortex host to the Velociraptor API port before proceeding:

```bash
nc -zv <velociraptor_server_ip> 8001
```

### 5.3 Upload the custom artifacts

In the Velociraptor GUI, **View Artifacts → Upload**, import each of the six `Custom.<OS>.Remediation.<Action>.yaml` files. Confirm each is listed from the server CLI:

```bash
velociraptor --config /path/to/server.config.yaml artifacts list | grep Remediation
```

### 5.4 Place responder code and manifests on the Cortex host

Copy the contents of the repository's `cortex-velo/` directory into `/opt/cortex/Cortex-Analyzers/responders/`, preserving the folder structure described in §2.2. Ensure correct ownership and executable permissions:

```bash
sudo chown -R thehive:thehive /opt/cortex/Cortex-Analyzers/responders/{Velociraptor,Velociraptor_KillProcess,VR_BlockIP,VR_IsolateHost}
sudo chmod 755 /opt/cortex/Cortex-Analyzers/responders/Velociraptor/*.py
```

### 5.5 Register each responder in Cortex

For each of `Velociraptor_KillProcess`, `VR_BlockIP`, `VR_IsolateHost`:

1. Restart Cortex, then in the Cortex UI: **Organization → Responders → Refresh responders**.
2. Locate the responder and click **Edit**. Populate the configuration items declared in its manifest — at minimum `velociraptor_api_config` (path to `api_client.yaml`), `thehive_url`, `thehive_apikey`. `VR_IsolateHost` additionally requires `velociraptor_server_address`, set to the address the target endpoints actually use to reach the Velociraptor frontend (§4.3).
3. Leave `really_do_it` set to its default (`False`) until dry-run behavior has been verified end-to-end.
4. Save, reload the page, and reopen **Edit** to confirm the values persisted.

**This step determines the responder's execution path for its entire registration lifetime** (§2.3) — verify the manifest's `command` field is correct in the repository *before* this first save. Correcting it afterward requires disabling the responder, restarting Cortex, and re-registering from a clean state; editing the file on disk alone has no effect on an already-registered responder.

### 5.6 Verification sequence

Before enabling `really_do_it`, validate each responder in dry-run mode:

1. Create a test case in TheHive.
2. Add an observable identifying a real, enrolled Velociraptor client — a `hostname` or `endpoint-ip` observable matching that client's actual identity as Velociraptor records it.
3. Add the action's triggering observable (`process-path`, `ip`, or another `hostname`/`endpoint-ip` for isolation) with a safe test value.
4. Run the responder from the case UI. Confirm the Cortex report shows successful client and OS resolution and a `DRY-RUN` result, with no unhandled exception.
5. Only after a clean dry-run, set `really_do_it=True` on the responder's Cortex configuration and re-run against a disposable, non-production test target.

---

## 6. Design Constraints and Known Limitations

- **`really_do_it` is a per-responder Cortex configuration value, not a per-invocation parameter.** It applies to every run of that responder until an operator changes it back in Cortex's configuration UI — there is no per-click override from the TheHive responder popup.
- **`VR_IsolateHost`'s `velociraptor_server_address` must exactly match the address the target endpoint uses to reach the Velociraptor frontend**, which may be an overlay-network address rather than a LAN address. A mismatch here is a one-way isolation failure with no remote recovery path; recovery in that case requires out-of-band console access to the endpoint.
- **The Windows un-isolation path restores Windows Firewall's factory-default policy, not necessarily the host's pre-isolation policy.** If the endpoint's firewall was managed by Group Policy or otherwise customized beyond factory default prior to isolation, that specific prior state is not recovered automatically.
- **Client resolution by IP depends on `last_ip` alignment.** The `hostname`/`endpoint-ip` observable populated on a case must correspond to the address Velociraptor itself records as the client's last-seen connection address; a detection source reporting a different network view of the same host (e.g. LAN IP vs. overlay-network IP) will fail to resolve a client match.
- **`Velociraptor_KillProcess` retains its pre-`VR_*` naming convention.** It is functionally equivalent in structure and behavior to `VR_BlockIP` and `VR_IsolateHost` (manifest-only folder, handler in the shared `Velociraptor/` directory) but was registered under its original folder name before that naming convention was adopted for the two later responders, and was not renamed in order to avoid an unnecessary re-registration of a working responder.
