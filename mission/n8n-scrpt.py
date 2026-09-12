"""
Build a COMPLETE TheHive 5 "create alert" request body -- metadata AND
observables -- from a raw SOC alert of ANY shape (Sigma / YARA / Suricata
via Security Onion -> n8n). One node, one POST.

Does IOC extraction (walks the whole alert tree, validates every candidate
with ipaddress/urlparse, filters infrastructure noise) and alert metadata
resolution (engine/severity/rule/time/sourceRef) together.

For Sigma/YARA, observables are exactly:
  - `ioc: true` threat-intel observables -- external IPs, domains, URLs,
    file hashes (dataTypes ip/domain/url/hash) -- fit to check against a
    reputation feed;
  - a minimal `ioc: false` source-of-alert pair -- `hostname` and
    `endpoint-ip` (the alert's own host/endpoint identity, not a threat
    indicator) -- and nothing else.
Process identity (path/pid/entity-id), host-id, registry, and file-path
observables are NOT extracted -- this script's mission is IOC-only, not
general incident-response tooling data. Suricata's own normalizer
(`normalize_suricata_alert`) extracts its own IOC-shaped set independently:
ip/port/community-id/sid/dns-content-match.

Every hash observable that can be traced to a specific process or file
gets a `process:<name>` or `file:<name>` tag naming that owner. See
`_extract_hash_owners` for the two real, structurally different shapes
this covers (Sigma's process-nested hash, YARA/Strelka's file-sibling
hash).

Custom TheHive observable dataType used by this deployment (must exist as
a custom observable type in TheHive's admin config, alongside the stock
ones): `endpoint-ip` (our own asset's IP -- host.ip for Sigma/YARA, the
internal side of a Suricata flow -- distinct from the `ip` dataType, which
is always the threat-intel external side).

The alert body carries no `tags` field for Sigma/YARA, and no observable
is ever reported under the generic `other` dataType for either engine.

Threat-intel observables (external IPs, domains, URLs, hashes) are
additionally checked against a curated allowlist of well-known LEGITIMATE
infrastructure (Windows telemetry/update, major CDNs, CA/CRL/OCSP, etc. --
see `KNOWN_LEGITIMATE_DOMAINS`) before being marked `ioc: true`: a domain
or URL matching it is still reported (never silently dropped) but as
`ioc: false` with a `known-legitimate` tag, so it doesn't get treated as
an actionable indicator. This is an offline heuristic, not a live
reputation lookup -- deeper vetting (VirusTotal/OpenCTI/Cortex) happens
downstream in the real SOC-3s pipeline.

Field coverage is grounded in `so-alert-reference/ingest/*` (Security
Onion's own ingest pipeline definitions) plus real captured alerts -- see
inline comments for what's confirmed vs. defensive. Windows/Sysmon
endpoint categories (process_creation, file_event, registry_*, etc.) and
Suricata/Zeek-shaped network alerts are covered by dedicated field
extraction. Cloud/identity/proxy sources this deployment also runs Sigma
rules against (Azure AD, AWS CloudTrail, GCP, Okta, M365, PaloAlto,
generic webserver/proxy logs) are deliberately NOT given dedicated field
mappings: none of their schemas exist in so-alert-reference or any real
captured fixture in this repo, and guessing field names for a schema never
verified against real data is exactly what this project's fixture
discipline prohibits. They still get whatever the schema-agnostic IOC
scanner below can find generically (IPs/domains/URLs/hashes anywhere in
the tree) -- just not a targeted response-observable extraction. Extend
`resolve_response_observables` for one of these the same way the others
were built: real captured alert first, then code.

Output shape (TheHive 5, POST /api/v1/alert):
{
  "type": "...", "source": "...", "sourceRef": "...",
  "title": "...", "description": "...",
  "severity": 1-4, "tlp": 0-3, "pap": 0-3, "date": <epoch ms>,
  "observables": [{"dataType": "domain", "data": "...", "ioc": true}, ...]
}
"""

import re
import json
import hashlib
import ipaddress
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlparse

# ==================================================================
# SECTION 1 -- IOC extraction (validated, noise-filtered, schema-agnostic)
# ==================================================================
IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
)
IPV6_RE = re.compile(r'\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b')
URL_RE = re.compile(r'\b(?:https?|ftp)://[^\s"\'<>\\]+', re.IGNORECASE)
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,24}\b'
)
SHA512_RE = re.compile(r'\b[a-fA-F0-9]{128}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_RE   = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_RE    = re.compile(r'\b[a-fA-F0-9]{32}\b')

# ==================================================================
# Structural (namespace-level) infrastructure exclusion.
#
# A leaf-by-leaf denylist (adding one specific fake domain/hash source
# field at a time -- `metadata.stream_id`, `event.dataset`,
# `dns.query_name`, ...) is a losing strategy: it only ever catches the
# leaf that has already misfired once. `rule.name` is a clean example --
# the rule title "...Backdoor.HTTP.GORAT..." on a real GORAT alert
# produces a fake `backdoor.http.gorat` domain if that field is scanned.
#
# The fix instead excludes whole NAMESPACES, grounded in a field-mapping
# census across the four real Elasticsearch indices spanning both alert
# shapes this deployment produces and the underlying event-log shapes
# they embed:
#   - logs-detections.alerts-so*          (Sigma alert doc)
#   - logs-suricata.alerts-so*             (Suricata alert doc)
#   - logs-windows.sysmon_operational-*    (Sysmon event_data source)
#   - logs-endpoint.events.process-*       (Elastic Endpoint event_data source)
#
# All four independently confirm the SAME set of top-level ECS/beats/
# pipeline namespaces -- `agent`, `elastic_agent`, `ecs`, `cloud`,
# `container`, `data_stream`, `dataset`, `log`, `metadata`, `observer`,
# `input`, `orchestrator`, `package`, `tags`, `event` -- and that
# `rule.name`/`rule.category`/`rule.product`/`rule.uuid` are mapped
# KEYWORD CLASSIFICATION fields in both the Sigma alert index and the
# Sysmon index. None of these ever carry attacker-controlled content
# on any engine this deployment runs -- they are the rule/pipeline's
# own identity and bookkeeping, not something observed in traffic.
# Excluding them as whole namespaces, rather than chasing individual
# leaked leaves, closes the entire class of bug rather than one
# instance of it at a time.
#
# `message` gets the same namespace-style treatment but keyed on FIELD
# NAME rather than path, because every mapping above independently
# defines it (and `error.message`) as `match_only_text` -- ECS's own
# convention for "free-form re-serialized/human log text", never
# structured indicator data, regardless of which namespace it turns up
# under for a given engine.
INFRASTRUCTURE_NAMESPACES = {
    'agent', 'elastic_agent', 'ecs', 'cloud', 'container', 'data_stream',
    'dataset', 'log', 'metadata', 'observer', 'input', 'orchestrator',
    'package', 'tags', 'event', 'rule', 'import',
    # `ioc.*` is a custom development-time ingest addition, NOT a real
    # Security Onion field -- this repo's own CLAUDE.md documents it as
    # "present but never read" and directs never building on it.
    'ioc',
    # n8n webhook-transport leftovers (normally already stripped by
    # unwrap_webhook before this runs) and SO's own response-envelope
    # bookkeeping fields -- never attacker content, for any engine.
    'headers', 'webhookurl', 'executionmode', 'num_hits', 'num_matches',
    'source_system', '@version', '_id', '_index', '_score',
}

# The `rule` namespace excludes cleanly with no carve-out: Suricata
# alerts never reach this blind scanner at all (see
# normalize_suricata_alert, which reads `dns.query_name` -- the
# pipeline's own already-dissected copy of the rule's content clause --
# directly instead), and Sigma/YARA never populate `rule.rule` with
# inline Suricata syntax.

# Residual leaf/path-specific exclusions that do NOT belong to any of the
# namespaces above -- each lives under an otherwise genuinely useful
# namespace (`dns`, `network`, `source`/`destination`), so excluding the
# whole namespace would throw away real coverage (dns.question.*,
# network.community_id, source.ip/destination.ip) along with the noise.
EXCLUDE_PATH_SUBSTRINGS = [
    'policy.applied.artifacts',
    # `destination.as.network` / `source.as.network` is an ASN CIDR range
    # (e.g. "54.36.0.0/14"), not a host IP -- the IP regex has no CIDR
    # awareness and would otherwise extract the network address as a fake
    # single-host external-IP observable.
    '.as.network',
    # `network.data.decoded`/`network.data.packet` -- the decoded/raw
    # packet payload: arbitrary uninterpreted payload text (e.g. a raw
    # C2-session directory listing), not structured indicator data, so
    # scanning it produces fake domain/hash matches from binary noise.
    # `network.community_id`/`network.transport`/etc. stay scannable.
    'network.data',
    # `dns.query_name` is a Suricata pipeline dissect artifact: it
    # duplicates the firing rule's own `content:"..."` match bytes rather
    # than carrying a real DNS query, so it can never independently
    # corroborate anything. Excluded on that basis. `dns.question.*`/
    # `dns.answers.*` are real ECS DNS fields and stay scannable.
    'dns.query_name',
]


def _is_excluded_path(path):
    """True if `path` (dotted, e.g. "rule.name" or "event_data.data_stream.dataset")
    should never be treated as attacker-controlled content.

    Checks EVERY dot-segment of the path against INFRASTRUCTURE_NAMESPACES,
    not just the first -- required because a Sigma alert doc embeds a full
    nested copy of the underlying raw event under `event_data.*`, WITH ITS
    OWN copy of `data_stream`, `tags`, `event`, `metadata`, `ecs`, `agent`,
    `group`, etc. one level deeper. A first-segment-only check misses that
    second copy entirely: "endpoint.events.process"/"events.process"/the
    raw index name would otherwise come through as fake domains from
    event_data.data_stream.dataset / event_data.tags / a re-embedded
    _index, even with the top-level namespace exclusion in place. These
    reserved ECS field-group names are never legitimately reused as a
    nested key for unrelated content at any depth, so an any-segment check
    is safe, not just convenient.

    Namespace check first (structural), then the small residual substring
    list for leaves that don't belong to a whole excluded namespace."""
    low_path = path.lower()
    segments = [seg.split('[', 1)[0] for seg in low_path.split('.')]
    if any(seg in INFRASTRUCTURE_NAMESPACES for seg in segments):
        return True
    if segments and segments[-1] == 'message':
        return True
    return any(bad in low_path for bad in EXCLUDE_PATH_SUBSTRINGS)

# Deliberately NOT a TLD allowlist (see add_domain_if_valid) -- a small,
# CLOSED set of Windows executable/script extensions that are never real
# gTLDs/ccTLDs, used only to reject the false-positive pattern where
# command-line text like "...Temp\xordump.exe" produces a fake
# "xordump.exe" domain. Excludes ambiguous ones on purpose: "com" is a
# real, huge gTLD (and the historical DOS-executable extension is
# effectively extinct), so it is NOT in this set -- dropping real .com
# domains would be a far worse regression than occasionally missing a
# *.com executable reference.
_NON_DOMAIN_EXECUTABLE_SUFFIXES = {
    'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'msi', 'scr',
    'cpl', 'msc', 'jar', 'wsf', 'wsh',
    # `pdb` -- Strelka's scan.pe.debug.pdb (the PE debug symbol path every
    # non-stripped Windows binary carries, e.g. "MpSigStub.pdb") would
    # otherwise come through as a fake `mpsigstub.pdb` domain, ioc:true --
    # a near-100%-of-alerts false positive for the YARA/Strelka engine
    # specifically, since almost every scanned PE has a .pdb debug path.
    'pdb',
}

IMPHASH_KEYS = {'imphash', 'imp_hash', 'importhash', 'import_hash',
                'peimphash', 'pe_imphash'}

_REFANG_PATTERNS = [
    (re.compile(r'\[\.\]|\(\.\)|\{\.\}'), '.'),
    (re.compile(r'\[:\]|\(:\)'), ':'),
    (re.compile(r'hxxps', re.IGNORECASE), 'https'),
    (re.compile(r'hxxp', re.IGNORECASE), 'http'),
]


def refang(text):
    for pattern, replacement in _REFANG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def get_path(obj, dotted_path):
    cur = obj
    for part in dotted_path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def first_non_empty(*values):
    for v in values:
        if v not in (None, '', [], {}):
            return v
    return None


def find_all_dicts_by_key(obj, target_key):
    """BFS: ALL dict values assigned to a key named target_key, anywhere
    in the tree (ECS/beats data splits one concept across sibling blocks
    at different depths, so a single dotted-path lookup can miss it)."""
    target_key = target_key.lower()
    matches = []
    queue = deque([obj])
    while queue:
        cur = queue.popleft()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.lower() == target_key and isinstance(v, dict):
                    matches.append(v)
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    queue.append(v)
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    queue.append(v)
    return matches


def unwrap_webhook(alert):
    """Strip the n8n Webhook transport wrapper if present. No-op otherwise."""
    if isinstance(alert, dict) and isinstance(alert.get('body'), dict) and (
        'headers' in alert or 'webhookUrl' in alert or 'executionMode' in alert
    ):
        return alert['body']
    return alert


def scan_strings(alert):
    """Walk the whole alert tree and yield (path, key_name, value) for
    every non-empty string leaf NOT excluded by _is_excluded_path.

    Always descends through dicts/lists rather than pruning at an
    excluded intermediate node (as a pure path-prefix check would) --
    the excluded subtrees in practice are single string leaves anyway
    (`message`, `network.data.decoded`), so this costs nothing in
    practice; it is not a real tree to prune."""
    stack = [("", alert)]
    while stack:
        path, cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                stack.append((f"{path}.{k}" if path else str(k), v))
        elif isinstance(cur, list):
            for i, v in enumerate(cur):
                stack.append((f"{path}[{i}]", v))
        elif isinstance(cur, str) and cur.strip():
            if _is_excluded_path(path):
                continue
            key_name = path.rsplit('.', 1)[-1].split('[')[0].lower()
            yield path, key_name, cur


def classify_ip(candidate):
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
            ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
        return 'internal'
    return 'external'


def add_domain_if_valid(candidate, domains_set):
    """No hardcoded TLD allowlist. There are 1000+ real gTLDs/ccTLDs today
    (real ET rules in this deployment's actual ruleset alert on Lumma
    Stealer C2 domains under .lat/.cyou/.shop, for example) and a fixed
    TLD list can only ever go stale and silently drop a real, currently-
    active malicious domain. Validating structure (label syntax/length,
    alphabetic TLD shape, not a bare IP) instead of TLD membership is the
    only way to not silently miss whatever TLD a malicious domain happens
    to be registered on. Trade-off: this is looser than a curated list, so
    it will occasionally flag a non-domain, TLD-shaped token from free
    text (e.g. a file extension). Acceptable here because the input is
    structured detection-engine field values, not free-flowing prose."""
    candidate = candidate.strip().strip('.').lower()
    if not candidate or '.' not in candidate or len(candidate) > 253:
        return
    if classify_ip(candidate) is not None:
        return
    labels = candidate.split('.')
    if any(len(lbl) == 0 or len(lbl) > 63 for lbl in labels):
        return
    if any(lbl.startswith('-') or lbl.endswith('-') for lbl in labels):
        return
    if labels[-1] in _NON_DOMAIN_EXECUTABLE_SUFFIXES:
        return
    domains_set.add(candidate)


# Every domain/URL the regex scanner finds needs a "is this an IOC, or
# legitimate infrastructure" check before being reported ioc:true --
# without it, near-universal Windows-telemetry / update / CRL-OCSP / NTP /
# major-CDN traffic (which shows up incidentally on a large share of real
# EDR and NIDS alerts and is not attacker-controlled) would be reported as
# a threat indicator. This is a curated, suffix-matched allowlist of
# well-known LEGITIMATE infrastructure -- the offline complement to
# `_NON_DOMAIN_EXECUTABLE_SUFFIXES` above (that one rejects false
# domain-shaped tokens; this one downgrades real domains that are
# genuinely not indicators). It is NOT a live reputation lookup (no
# network calls happen in this n8n code node -- that already happens
# downstream, in the real SOC-3s pipeline's Cortex/OpenCTI analyzers, see
# `tools/opencti.py` and `get_full_alert_with_analysis`). A match here
# does not delete the observable -- it stays visible for audit/context,
# just with `ioc: false` and a `known-legitimate` tag instead of being
# reported as an actionable threat-intel indicator. Deliberately NOT
# applied to `external_ips` -- there is no offline, dependency-free way
# to attribute an arbitrary IP to a known-legitimate owner without an
# ASN/GeoIP database this script does not have; that vetting already
# happens downstream via OpenCTI/Cortex in the real pipeline.
KNOWN_LEGITIMATE_DOMAINS = {
    # Microsoft / Windows telemetry, update, auth and connectivity-check
    # infrastructure -- near-universal in real Windows EDR/NIDS traffic.
    'microsoft.com', 'msftncsi.com', 'msftconnecttest.com', 'windowsupdate.com',
    'windows.com', 'live.com', 'office.com', 'office365.com', 'msn.com',
    'bing.com', 'skype.com', 'microsoftonline.com', 'msauth.net',
    'msauthimages.net', 'msecnd.net', 'trafficmanager.net', 'azureedge.net',
    'azure.com', 'windowsazure.com', 'events.data.microsoft.com',
    'sharepointonline.com', 'outlook.com',
    # Google
    'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    'youtube.com', 'gvt1.com', 'gvt2.com', 'googlesyndication.com',
    # Apple
    'apple.com', 'icloud.com', 'apple-dns.net',
    # Major CDN / cloud infrastructure frequently seen as incidental traffic
    'akamai.net', 'akamaiedge.net', 'akamaitechnologies.com',
    'amazonaws.com', 'cloudfront.net', 'cloudflare.com', 'cloudflare-dns.com',
    'fastly.net', 'edgesuite.net', 'edgekey.net',
    # Certificate/CRL/OCSP infrastructure -- routinely contacted during a
    # normal TLS handshake, not attacker infrastructure.
    'digicert.com', 'sectigo.com', 'globalsign.com', 'entrust.net',
    'verisign.com', 'symcd.com', 'symcb.com', 'geotrust.com',
    'letsencrypt.org', 'identrust.com', 'ocsp.com',
    # Linux distro package/update infrastructure
    'ubuntu.com', 'debian.org', 'archlinux.org', 'redhat.com', 'centos.org',
    'canonical.com',
    # NTP
    'ntp.org', 'pool.ntp.org',
}


def is_known_legitimate_domain(candidate):
    """Suffix match against KNOWN_LEGITIMATE_DOMAINS -- 'a.b.microsoft.com'
    matches 'microsoft.com', an unrelated domain that merely contains one
    of these as a substring (e.g. 'notmicrosoft.com.evil.tld') does not."""
    if not candidate:
        return False
    candidate = candidate.strip().strip('.').lower()
    return any(
        candidate == d or candidate.endswith('.' + d)
        for d in KNOWN_LEGITIMATE_DOMAINS
    )


def clean_url(raw_url):
    return raw_url.rstrip('\'",;:.)]}')


def normalize_ip_list(raw):
    """Validates syntax AND drops loopback/link-local addresses.
    event_data.host.ip is a LIST on real Elastic Endpoint data (every
    interface the host has), e.g. ["127.0.0.1","::1","192.168.1.74",
    "fe80::286f:d277:a3f3:9e2d"] -- not just the one meaningful address.
    127.0.0.1/::1 are identical on every host (zero pivot value as "which
    endpoint"), and a link-local address is interface-scoped and not
    globally unique either -- both would otherwise reach the endpoint-ip
    observable unfiltered. Private-but-routable addresses (the
    192.168.1.74 in that same real list) are deliberately KEPT -- that IS
    the real, useful host identity, same as classify_ip's own internal/
    external split treats a private address as legitimate, just not
    'external'."""
    if raw is None:
        return []
    values = raw if isinstance(raw, list) else [raw]
    out = []
    for v in values:
        if isinstance(v, str):
            try:
                ip_obj = ipaddress.ip_address(v)
            except ValueError:
                continue
            if ip_obj.is_loopback or ip_obj.is_link_local:
                continue
            out.append(v)
    return out


def extract_context(alert):
    """hostname/host_ip/agent_id resolution for Sigma/YARA (EDR telemetry:
    dataset endpoint.events.*). Suricata has its own normalizer
    (normalize_suricata_alert) and never calls this function.

    `metadata.input.beats.host.ip` (and any dict keyed "host" found by the
    blind BFS fallback) is the IP of whichever machine is RUNNING the
    beats/elastic-agent shipper. For Sigma/YARA that shipper runs ON the
    monitored endpoint, so it IS the host's own IP -- legitimate. (For a
    passive network sensor's shipper, that same field would be the
    sensor's own management IP, not the monitored host's -- a trap this
    function avoids by never being called for that case, since Suricata
    is routed to its own normalizer instead.)
    """
    hostname = first_non_empty(
        get_path(alert, 'host.name'), get_path(alert, 'host.hostname'),
        get_path(alert, 'event_data.host.name'),
        get_path(alert, 'event_data.host.hostname'),
        get_path(alert, 'winlog.computer_name'),
        get_path(alert, 'event_data.winlog.computer_name'),
    )
    host_ip_raw = first_non_empty(
        get_path(alert, 'host.ip'), get_path(alert, 'event_data.host.ip'),
        get_path(alert, 'event_data.metadata.input.beats.host.ip'),
    )
    agent_id = first_non_empty(
        get_path(alert, 'agent.id'), get_path(alert, 'event_data.agent.id'),
        get_path(alert, 'elastic.agent.id'),
        get_path(alert, 'event_data.elastic.agent.id'),
        get_path(alert, 'elastic_agent.id'),
        get_path(alert, 'event_data.elastic_agent.id'),
    )
    if hostname is None or not host_ip_raw:
        host_blocks = find_all_dicts_by_key(alert, 'host')
        if hostname is None:
            for hb in host_blocks:
                hostname = first_non_empty(
                    hb.get('name'), hb.get('hostname'), hb.get('computer_name'),
                )
                if hostname:
                    break
        if not host_ip_raw:
            for hb in host_blocks:
                if hb.get('ip'):
                    host_ip_raw = hb['ip']
                    break
    if agent_id is None:
        for ab in find_all_dicts_by_key(alert, 'agent'):
            if ab.get('id'):
                agent_id = ab['id']
                break
    return hostname, normalize_ip_list(host_ip_raw), agent_id


def resolve_network_flow(alert):
    """The flow identity for any network-behavior alert -- Suricata NIDS,
    or a Zeek-backed Sigma rule (lateral movement, SMB/RDP anomalies), both
    of which use the same source.ip/destination.ip/network.transport ECS
    shape. These are the real, normalized field names -- NOT the flat
    src_ip/dest_ip/proto that only exist in the raw, un-normalized
    eve.json (nested inside `message`, excluded from scanning above).

    Checks the top-level path first (the confirmed-real shape), then falls
    back to a deep tree search (find_all_dicts_by_key) for alerts that
    nest source/destination differently -- e.g. under event_data for some
    Sigma rule shapes -- rather than only ever looking in one hardcoded
    spot."""
    src = get_path(alert, 'source.ip')
    dst = get_path(alert, 'destination.ip')
    proto = get_path(alert, 'network.transport')

    if src is None:
        for block in find_all_dicts_by_key(alert, 'source'):
            if block.get('ip'):
                src = block['ip']
                break
    if dst is None:
        for block in find_all_dicts_by_key(alert, 'destination'):
            if block.get('ip'):
                dst = block['ip']
                break
    if proto is None:
        for block in find_all_dicts_by_key(alert, 'network'):
            if block.get('transport'):
                proto = block['transport']
                break

    if not src or not dst:
        return None, None, None
    return src, dst, proto



def extract_iocs(alert: dict) -> dict:
    """Extract threat-intel-ready IOCs from a Sigma/YARA alert of any
    shape. Suricata has its own dedicated, table-driven normalizer
    (normalize_suricata_alert) for its fully-confirmed ECS shape and never
    calls this function. This blind, schema-agnostic tree scan exists for
    Sigma/YARA specifically because their real-world field shapes are far
    less predictable (Sysmon event-type variety, cloud/identity/proxy
    Sigma sources with no dedicated field mapping in this repo, YARA/
    Strelka's PE-metadata sprawl)."""
    if not isinstance(alert, dict):
        alert = {}
    alert = unwrap_webhook(alert)

    hostname, host_ips, agent_id = extract_context(alert)
    local_ips = set(host_ips)

    external_ips, domains, urls = set(), set(), set()
    md5s, sha1s, sha256s, sha512s, imphashes = set(), set(), set(), set(), set()

    for _path, key_name, raw_text in scan_strings(alert):
        text = refang(raw_text)
        for m in URL_RE.finditer(text):
            url = clean_url(m.group(0))
            urls.add(url)
            try:
                host = urlparse(url).hostname
            except ValueError:
                host = None
            if host:
                cls = classify_ip(host)
                if cls == 'external':
                    external_ips.add(host)
                elif cls is None:
                    add_domain_if_valid(host, domains)
        for pattern in (IPV4_RE, IPV6_RE):
            for m in pattern.finditer(text):
                ip = m.group(0)
                if classify_ip(ip) == 'external' and ip not in local_ips:
                    external_ips.add(ip)
        for m in DOMAIN_RE.finditer(text):
            # PowerShell type-accelerator syntax ([Net.ServicePointManager],
            # [Net.SecurityProtocolType]) is dot-shaped and matches the same
            # pattern as a domain, and shows up routinely in command_line/args
            # text. Structurally distinct from a real domain: always wrapped
            # in [...] in PowerShell syntax, which a domain never is.
            before = text[m.start() - 1] if m.start() > 0 else ''
            after = text[m.end()] if m.end() < len(text) else ''
            if before == '[' or after == ']':
                continue
            add_domain_if_valid(m.group(0), domains)
        for m in SHA512_RE.finditer(text):
            sha512s.add(m.group(0).lower())
        for m in SHA256_RE.finditer(text):
            sha256s.add(m.group(0).lower())
        for m in SHA1_RE.finditer(text):
            sha1s.add(m.group(0).lower())
        for m in MD5_RE.finditer(text):
            val = m.group(0).lower()
            if key_name in IMPHASH_KEYS:
                imphashes.add(val)
            else:
                md5s.add(val)

    external_ips -= local_ips  # never report the endpoint's own IP as external

    def list_or_false(sorted_list):
        return sorted_list if sorted_list else False

    return {
        "hostname": {"value": hostname if hostname else "unknown", "found": bool(hostname)},
        "host_ip": list_or_false(sorted(host_ips)),
        "agent_id": {"value": agent_id if agent_id else "unknown", "found": bool(agent_id)},
        "external_ips": list_or_false(sorted(external_ips)),
        "domains": list_or_false(sorted(domains)),
        "urls": list_or_false(sorted(urls)),
        "hashes": {
            "md5": list_or_false(sorted(md5s)),
            "sha1": list_or_false(sorted(sha1s)),
            "sha256": list_or_false(sorted(sha256s)),
            "sha512": list_or_false(sorted(sha512s)),
            "imphash": list_or_false(sorted(imphashes)),
        },
    }


# ==================================================================
# SECTION 2 -- Alert metadata resolution (engine, severity, rule, time)
# ==================================================================
SEVERITY_LABEL_MAP = {
    'informational': 1, 'info': 1, 'low': 1,
    'medium': 2, 'moderate': 2,
    'high': 3,
    'critical': 4, 'severe': 4,
}

DEFAULT_TLP = 2   # 0=white/clear, 1=green, 2=amber, 3=red
DEFAULT_PAP = 2   # same 0-3 scale, permissible-actions protocol


def detect_source_engine(alert):
    explicit = first_non_empty(
        get_path(alert, 'ioc.source_engine'),
        get_path(alert, 'event.module'),
    )
    if isinstance(explicit, str) and explicit.lower() in ('sigma', 'suricata', 'yara'):
        return explicit.lower()
    # Strelka is a documented SO integration (so-alert-reference/ingest/
    # strelka.file) with zero live evidence in this deployment (no index,
    # no captured alert) -- what event.module it actually sets is NOT in
    # that reference dump. Assumed "strelka" by the same naming convention
    # as "suricata", flagged as the one unconfirmed field name in this
    # extension. Falls back to the raw-shape heuristic below regardless.
    if isinstance(explicit, str) and explicit.lower() == 'strelka':
        return 'yara'

    if get_path(alert, 'sigma_level') is not None or find_all_dicts_by_key(alert, 'rule'):
        if get_path(alert, 'alert.signature') is None:
            return 'sigma'

    if (get_path(alert, 'alert.signature') is not None or
            (alert.get('src_ip') is not None and alert.get('dest_ip') is not None)):
        return 'suricata'

    if alert.get('rule_name') is not None or 'strings' in alert or 'meta' in alert:
        return 'yara'

    return 'unknown'


def resolve_rule_name(alert):
    return first_non_empty(
        get_path(alert, 'rule.name'),
        get_path(alert, 'ioc.rule.name'),
        get_path(alert, 'alert.signature'),
        alert.get('rule_name'),
        "Unnamed detection",
    )


def resolve_rule_uuid(alert):
    return first_non_empty(
        get_path(alert, 'rule.uuid'),
        get_path(alert, 'ioc.rule.uuid'),
        get_path(alert, 'alert.signature_id'),
    )


def resolve_severity(alert):
    """Sigma/YARA severity resolution. Suricata has its own, stricter
    `_map_suricata_severity` (event.severity_label only, no scan_strings
    fallback, no raw Suricata alert.severity handling) and never calls
    this function."""
    label = first_non_empty(
        get_path(alert, 'sigma_level'),
        get_path(alert, 'event.severity_label'),
        get_path(alert, 'ioc.rule.severity'),
    )
    if label is None:
        for _p, key_name, value in scan_strings(alert):
            if key_name in ('severity_label', 'sigma_level'):
                label = value
                break
    if isinstance(label, str) and label.lower() in SEVERITY_LABEL_MAP:
        return SEVERITY_LABEL_MAP[label.lower()]

    return 2  # unknown severity -> Medium; safer than silently picking Low


def resolve_timestamp_ms(alert):
    ts = first_non_empty(
        get_path(alert, '@timestamp'),
        get_path(alert, 'event_data.@timestamp'),
        get_path(alert, 'timestamp'),
    )
    if isinstance(ts, str):
        try:
            cleaned = ts.replace('Z', '+00:00')
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            pass
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def resolve_source_ref(alert, hostname, rule_uuid, timestamp_ms):
    """TheHive requires (type, source, sourceRef) to be unique per alert.
    Prefer a natural id already in the data (Elastic doc _id) so replays
    of the SAME upstream event map to the SAME TheHive alert instead of
    creating duplicates; fall back to a deterministic hash otherwise."""
    natural_id = first_non_empty(alert.get('_id'), get_path(alert, 'event_data._id'))
    if natural_id:
        return str(natural_id)
    basis = f"{rule_uuid}|{hostname}|{timestamp_ms}".encode('utf-8')
    return hashlib.sha256(basis).hexdigest()[:24]


def resolve_context_line(alert, source_engine):
    """One short line of extra context for the description, engine-specific.
    Sigma/YARA only -- Suricata builds its own description entirely in
    _build_suricata_description."""
    if source_engine == 'sigma':
        cmd = get_path(alert, 'event_data.process.command_line')
        parent_cmd = get_path(alert, 'event_data.process.parent.command_line')
        lines = []
        if cmd:
            lines.append(f"Command line: {cmd}")
        if parent_cmd and parent_cmd != cmd:
            lines.append(f"Parent command line: {parent_cmd}")
        return "\n".join(lines) if lines else None
    if source_engine == 'yara':
        strings = alert.get('strings')
        if isinstance(strings, list) and strings:
            return f"Matched string (1 of {len(strings)}): {strings[0]}"
        return None
    return None


# ==================================================================
# SECTION 3 -- observables (IOCs only)
# ==================================================================
# Alert-level tag extraction (engine/rule/agent-id/sensor/flow/hostname/
# host_ip as free-standing tag strings on the ALERT itself) is out of
# scope. hostname/host_ip/agent_id context still reaches TheHive -- via
# the description text and, per the observable set below, as
# endpoint-ip/hostname observables -- just not duplicated a third time
# as alert tags.
def build_observables(iocs, hash_owners=None):
    """Observables built ONLY from actual IOCs -- external IPs, domains,
    URLs, hashes. hostname/host_ip/agent_id are NEVER included here.

    Observables carry no `re&ct:<category>` tag -- only the algorithm tag
    (md5/sha1/.../imphash) on hashes and, where applicable, the
    `process:<name>`/`file:<name>`/`known-legitimate` tags below.

    This also covers the YARA/Strelka file-hash case: Strelka's real
    field names (hash.sha256/hash.md5, per so-alert-reference/ingest/
    strelka.file) are plain string values the scan_strings-based
    extractor above already catches correctly with ioc:true -- no
    separate YARA resolver needed.

    `hash_owners` (from `_extract_hash_owners`): a
    {hash_lowercased: (kind, owner_name)} map -- ANY hash that is
    genuinely traceable to a specific process OR file (not just found
    somewhere else in the alert tree) gets an extra `process:<name>` or
    `file:<name>` tag (kind-specific -- a file-owned hash, e.g.
    YARA/Strelka's, is never mislabeled `process:`), so an analyst
    pivoting on the hash observable can see where it came from -- this
    tag is the only place that provenance survives on the hash
    observable itself."""
    hash_owners = hash_owners or {}

    def hash_tags(h, *base_tags):
        tags = list(base_tags)
        owner = hash_owners.get(h)
        if owner:
            kind, name = owner
            tags.append(f"{kind}:{name}")
        return tags

    observables = []
    for ip in (iocs['external_ips'] or []):
        # No offline attribution source for IP ownership (no ASN/GeoIP db
        # in this script) -- always reported ioc:true; legitimacy vetting
        # for IPs happens downstream via OpenCTI/Cortex in the real pipeline.
        observables.append({"dataType": "ip", "data": ip, "ioc": True, "tags": []})
    for d in (iocs['domains'] or []):
        if is_known_legitimate_domain(d):
            observables.append({"dataType": "domain", "data": d, "ioc": False,
                                 "tags": ["known-legitimate"]})
        else:
            observables.append({"dataType": "domain", "data": d, "ioc": True, "tags": []})
    for u in (iocs['urls'] or []):
        try:
            url_host = urlparse(u).hostname
        except ValueError:
            url_host = None
        if url_host and is_known_legitimate_domain(url_host):
            observables.append({"dataType": "url", "data": u, "ioc": False,
                                 "tags": ["known-legitimate"]})
        else:
            observables.append({"dataType": "url", "data": u, "ioc": True, "tags": []})
    hashes = iocs['hashes']
    for h in (hashes['md5'] or []):
        observables.append({"dataType": "hash", "data": h, "ioc": True, "tags": hash_tags(h, "md5")})
    for h in (hashes['sha1'] or []):
        observables.append({"dataType": "hash", "data": h, "ioc": True, "tags": hash_tags(h, "sha1")})
    for h in (hashes['sha256'] or []):
        observables.append({"dataType": "hash", "data": h, "ioc": True, "tags": hash_tags(h, "sha256")})
    for h in (hashes['sha512'] or []):
        observables.append({"dataType": "hash", "data": h, "ioc": True, "tags": hash_tags(h, "sha512")})
    for h in (hashes['imphash'] or []):
        # Not a file hash -- don't submit to VT/etc. as one. ioc=False keeps
        # it from being treated as a straightforward malicious-hash lookup.
        observables.append({"dataType": "hash", "data": h, "ioc": False,
                             "tags": hash_tags(h, "imphash")})
    return observables


def _network_flow_response_observables(alert):
    """Source-of-alert context (hostname, endpoint-ip) for Zeek-backed
    Sigma network-behavior rules (lateral movement, SMB/RDP anomalies --
    the same source.ip/destination.ip/network.transport ECS shape, see
    resolve_network_flow). Sigma-only -- Suricata alerts are normalized by
    normalize_suricata_alert instead.

    This script's mission is IOC-only (hash/domain/url/external-ip) plus
    minimal source-of-alert context. No autonomous-system observable is
    produced for the EXTERNAL side of a flow -- it's neither an IOC in the
    hash/domain/url/external-ip sense nor source-of-alert context; ASN
    attribution for an external IP is threat-intel enrichment that
    belongs downstream (OpenCTI/Cortex), not this script. Only the
    INTERNAL side's endpoint-ip and source/destination.hostname are
    produced here."""
    observables = []
    src, dst, _proto = resolve_network_flow(alert)
    if not src or not dst:
        return observables

    for ip in (src, dst):
        if classify_ip(ip) != 'internal':
            continue
        # The internal/endpoint side of a flow (our own asset) is reported
        # under the custom `endpoint-ip` dataType, not `ip` -- keeps "our
        # asset's address"
        # (a response/pivot handle) visually and structurally distinct
        # from `ip` threat-intel observables (external_ips, always the
        # OTHER side of the flow, built in build_observables).
        observables.append({"dataType": "endpoint-ip", "data": ip, "ioc": False, "tags": []})

    # source.hostname/destination.hostname -- confirmed real fields, Sysmon
    # network_connection events (so-alert-reference/ingest/sysmon, renamed
    # from winlog.event_data.SourceHostname/DestinationHostname). Many
    # internal Windows hostnames have no dot (e.g. "WORKSTATION-05"), so
    # the generic domain scanner never catches them -- this is the only
    # path that does.
    for side in ('source', 'destination'):
        host = get_path(alert, f'{side}.hostname')
        if host:
            observables.append({
                "dataType": "hostname", "data": host, "ioc": False,
                "tags": [f"field:{side}.hostname"],
            })

    return observables


def find_all_dicts(obj):
    """BFS: every dict node anywhere in the tree, regardless of its own
    key name (unlike find_all_dicts_by_key, which filters by key).
    Needed to find a dict whose OWN keys include both "file" and "hash"
    as siblings (Strelka's real shape, see _extract_hash_owners) -- a
    key-name filter can't express "this dict happens to contain these
    two other keys"."""
    matches = []
    queue = deque([obj])
    while queue:
        cur = queue.popleft()
        if isinstance(cur, dict):
            matches.append(cur)
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    queue.append(v)
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    queue.append(v)
    return matches


def _extract_hash_owners(alert):
    """{hash_value_lowercased: (kind, owner_name)} for every IOC hash
    this script can trace back to a specific process or file -- feeds
    build_observables' `process:<name>` / `file:<name>` tag on the
    traditional hash observables, per this deployment's own "the hash
    extracted must be determined from what it came from (process, file,
    ...)" requirement. `kind` is carried through (not collapsed to a
    single tag prefix) precisely so a file-owned hash is never
    mislabeled `process:<name>` just because that was the first owner
    kind this function supported.

    Two real, distinct shapes this deployment actually produces, handled
    separately because the hash lives in a different STRUCTURAL relation
    to its owner in each:

    1. Process-owned hash (Sigma/Elastic Endpoint) -- the hash is NESTED
       INSIDE the process object, alongside its name/pid:
       event_data.process.name == "powershell.exe", event_data.
       process.hash == {"sha256": "1c84c863..."} (Elastic Endpoint's own
       hash.* dict -- the process's OWN executable hash, distinct from
       process.pe.imphash, the PE import-table hash, also carried on the
       same process object). A parent block commonly has neither `hash`
       nor `pe` populated (Elastic doesn't always compute a parent's own
       hash) -- both read defensively, never assumed present.

    2. File-owned hash (YARA/Strelka) -- the hash is a SIBLING of the
       file object, both direct children of the SAME parent dict, not
       nested inside it: a real Strelka document's top level has `file`
       ({"name": "/nsm/strelka/staging/...exe", ...}) and `hash`
       ({"sha1": ..., "sha256": ..., "md5": ..., "tlsh": ..., "ssdeep":
       ...}) as two separate keys of the SAME dict -- there is no
       `file.hash` path in this real shape. find_all_dicts_by_key can't
       express "this dict has both of these sibling keys", hence
       find_all_dicts (unfiltered BFS) instead.

    Not generalized further ("or whatever") beyond these two -- e.g.
    Strelka's own scan.pe.imphash is NOT associated with the file here,
    since it lives several levels deeper under a completely different
    parent (`scan.pe`, not sibling to `file`) and doing so would be a
    structural guess this deployment's real data doesn't confirm."""
    owners = {}

    def record_process(proc):
        if not isinstance(proc, dict):
            return
        name = first_non_empty(proc.get('name'), proc.get('executable'))
        if not name:
            return
        hashes = proc.get('hash')
        if isinstance(hashes, dict):
            for v in hashes.values():
                if isinstance(v, str) and v:
                    owners[v.lower()] = ("process", name)
        pe = proc.get('pe')
        if isinstance(pe, dict) and pe.get('imphash'):
            owners[pe['imphash'].lower()] = ("process", name)

    for proc in find_all_dicts_by_key(alert, 'process'):
        record_process(proc)
        record_process(proc.get('parent'))

    for d in find_all_dicts(alert):
        file_block = d.get('file')
        hashes = d.get('hash')
        if not isinstance(file_block, dict) or not isinstance(hashes, dict):
            continue
        name = first_non_empty(file_block.get('name'), file_block.get('target'),
                                file_block.get('source'))
        if not name:
            continue
        for v in hashes.values():
            if isinstance(v, str) and v:
                owners.setdefault(v.lower(), ("file", name))

    return owners


def _source_context_observables(hostname, host_ips):
    """The alert's own source/asset identity -- hostname and the
    endpoint's own IP(s) -- NOT threat-intel (ioc:false), kept because
    this script's mission still needs to say WHICH host/asset an alert is
    about. Process identity (path/pid/entity-id), host-id, registry, and
    file-path are not extracted as observables -- this script's mission
    is IOC-only (hash/url/domain/external-ip, see build_observables) plus
    this minimal source-of-alert pair, not general incident-response
    tooling data.

    Shared by Sigma AND YARA alike; in practice this still no-ops for
    YARA/Strelka alerts in this deployment, since the real Strelka
    document shape has no "host" block to extract from at all."""
    observables = []

    def add(data_type, data, tags):
        if data is None or data == '':
            return
        entry = {"dataType": data_type, "data": str(data), "ioc": False, "tags": list(tags)}
        observables.append(entry)

    if hostname:
        add("hostname", hostname, [])
    for ip in (host_ips or []):
        # dataType endpoint-ip, not ip -- this IS the monitored endpoint's
        # own address (host.ip), the same "our asset" concept endpoint-ip
        # represents for a Suricata flow's internal side, see
        # _network_flow_response_observables.
        add("endpoint-ip", ip, ["field:host.ip"])

    return observables


def resolve_response_observables(alert, source_engine, hostname, host_ips):
    """Source-of-alert observables for Sigma/YARA (hostname/endpoint-ip
    only, see _source_context_observables) plus, for Sigma specifically,
    the same pair derived from a Zeek-backed network-behavior rule's flow
    (_network_flow_response_observables). Suricata has its own
    normalize_suricata_alert and never reaches this function."""
    observables = _source_context_observables(hostname, host_ips)
    if source_engine == 'sigma':
        observables += _network_flow_response_observables(alert)
    return observables


# ==================================================================
# SECTION 4 -- Suricata-only normalizer
# ==================================================================
# Suricata alerts do NOT go through SECTIONS 1-3 above (the blind,
# schema-agnostic tree scan built for Sigma/YARA's far less predictable
# shapes). Security Onion's own pipeline chain for a Suricata alert is
# fully confirmed field-by-field by reading the pipeline source itself
# (suricata.common -> suricata.alert -> common.nids -> common), not
# inferred from samples, so this normalizer reads a small, exact table of
# named fields instead of scanning the whole tree.
#
# Suricata config assumption, confirmed 2026-09 (Security Onion default,
# not overridden on this deployment): eve-log.types.alert.metadata.
# app-layer: false -- http.*/tls.*/url.*/dns.question.* (real ECS DNS,
# distinct from the dns.query_name dissect bug below) never populate on
# an `alert` object under this config, for any rule. No extractor is
# written for them; revisit if this config ever changes (event.dataset
# would then also stop being "suricata.alert" for those richer forms --
# see UnsupportedSuricataDatasetError below, raised rather than guessed
# at for that case).
_SURICATA_SEVERITY_LABEL_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class UnsupportedSuricataDatasetError(ValueError):
    """`event.dataset` is present and differs from "suricata.alert" -- a
    document shape (suricata.dns/http/tls) this deployment does not
    structurally produce today (Suricata app-layer logging is off, see
    the section header above). If this is ever raised in production,
    that config has changed -- extend this normalizer deliberately
    against real captured data from the new shape, don't guess."""


def _map_suricata_severity(severity_label):
    """event.severity_label -> TheHive severity (1-4). NEVER use raw
    Suricata `rule.severity`/`alert.severity` for this -- that field is
    already consumed and transformed into event.severity by
    common.nids, then into event.severity_label by common, before this
    document exists; event.severity_label is the only reliable source
    left at this stage of the pipeline. resolve_severity above is
    Sigma/YARA-only; Suricata always goes through this function
    instead."""
    return _SURICATA_SEVERITY_LABEL_MAP.get(severity_label, 2)  # 2 = medium if absent/unexpected


def _suricata_timestamp_ms(alert):
    """ISO8601 @timestamp -> epoch millis, or None (never "now") if
    absent/unparseable -- unlike resolve_timestamp_ms's Sigma/YARA
    fallback, a missing/bad Suricata timestamp omits `date` from the
    result entirely rather than inventing one, per this normalizer's
    "never a plausible-but-false value" spec."""
    ts = get_path(alert, '@timestamp')
    if not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _extract_suricata_observables(alert):
    """Threat-intel/response observables for a Suricata alert, per the
    definitive field -> dataType -> tags table this normalizer
    implements. Every dataType used here is one of the 23 confirmed to
    exist on this TheHive instance (Administration > Entities management
    > Observable Types) -- no invented type. Suricata's own spec defines
    its own tag vocabulary (source/destination/community-id/sid/
    rule-content-match) and carries no `ioc` key at all, unlike SECTION 3
    above's Sigma/YARA observables."""
    observables = []

    def add(data_type, data, tags, message=None):
        if data is None or data == '':
            return
        entry = {"dataType": data_type, "data": str(data), "tags": list(tags)}
        if message is not None:
            entry["message"] = message
        observables.append(entry)

    add("ip", get_path(alert, 'source.ip'), ["source"])
    add("ip", get_path(alert, 'destination.ip'), ["destination"])
    add("port", get_path(alert, 'source.port'), ["source"])
    add("port", get_path(alert, 'destination.port'), ["destination"])

    # network.vlan.id is a LIST on real documents (e.g. [2024]), not a
    # scalar -- handled defensively either way. Absent entirely if the
    # traffic isn't VLAN-tagged.
    vlan_ids = get_path(alert, 'network.vlan.id')
    if vlan_ids is not None:
        if not isinstance(vlan_ids, list):
            vlan_ids = [vlan_ids]
        for vlan_id in vlan_ids:
            add("vlan", vlan_id, [])

    add("other", get_path(alert, 'network.community_id'), ["community-id"])
    add("other", get_path(alert, 'rule.uuid'), ["sid"])

    # dns.query_name is NEVER a real domain, regardless of content -- it's
    # the first content:"..." clause found in rule.rule, produced by a
    # `dissect` processor in the suricata.alert pipeline (confirmed at
    # the pipeline source, not a heuristic). Always "other", never
    # "domain". Truncated to 500 chars -- the rule can carry a long
    # binary-ish pattern.
    content_match = get_path(alert, 'dns.query_name')
    if content_match:
        add(
            "other",
            content_match[:500],
            ["rule-content-match"],
            message="matched Suricata rule content string (not a DNS query)",
        )

    return observables


def _extract_suricata_tags(alert):
    """Alert-level tags (engine/rule/sensor context) for a Suricata alert,
    distinct from observable tags. "engine:suricata" is always present;
    the rest is conditional on the corresponding source field."""
    tags = ["engine:suricata"]

    category = get_path(alert, 'rule.category')
    if category:
        tags.append(f"category:{category}")

    ruleset = get_path(alert, 'rule.ruleset')
    if ruleset:
        tags.append(f"ruleset:{ruleset}")

    sensor = get_path(alert, 'observer.name')
    if sensor:
        tags.append(f"sensor:{sensor}")

    dataset = get_path(alert, 'event.dataset')
    if dataset:
        tags.append(f"dataset:{dataset}")

    # network.private_ip / network.public_ip are two lists produced by a
    # Painless script in suricata.common that classifies source.ip AND
    # destination.ip together -- only source.ip (never destination)
    # decides this tag. Both lists can be absent/empty (no IP classified)
    # -- never assumed present.
    source_ip = get_path(alert, 'source.ip')
    if source_ip is not None:
        private_ips = get_path(alert, 'network.private_ip') or []
        public_ips = get_path(alert, 'network.public_ip') or []
        if source_ip in private_ips:
            tags.append("internal-source")
        elif source_ip in public_ips:
            tags.append("external-source")

    return tags


def _build_suricata_description(alert):
    """Markdown description for a Suricata alert -- never a raw JSON dump.
    Sections in spec order; a section whose source fields are all absent
    is omitted entirely (never an "N/A" placeholder)."""
    sections = []

    rule_name = get_path(alert, 'rule.name')
    header_lines = [f"## {rule_name}" if rule_name else "## (unnamed Suricata rule)"]
    category = get_path(alert, 'rule.category')
    if category:
        header_lines.append(f"**Category:** {category}")
    sections.append("\n".join(header_lines))

    # Network: source -> destination (transport). Ports/VLAN are NOT
    # repeated here -- already dedicated observables above.
    src_ip = get_path(alert, 'source.ip')
    dst_ip = get_path(alert, 'destination.ip')
    if src_ip or dst_ip:
        flow = f"{src_ip or '?'} → {dst_ip or '?'}"
        transport = get_path(alert, 'network.transport')
        if transport:
            flow += f" ({transport})"
        sections.append(f"**Network:** {flow}")

    sensor_name = get_path(alert, 'observer.name')
    interface_name = get_path(alert, 'observer.ingress.interface.name')
    if sensor_name or interface_name:
        sensor_line = f"**Sensor:** {sensor_name or '?'}"
        if interface_name:
            sensor_line += f" (interface: {interface_name})"
        sections.append(sensor_line)

    flow_id = get_path(alert, 'log.id.uid')
    if flow_id:
        sections.append(f"**Flow ID:** {flow_id}")

    # GeoIP/ASN -- absent if the IP is private and/or not found in the
    # GeoLite2 database, accessed defensively level by level.
    geo_lines = []
    for side, label in (("source", "Source"), ("destination", "Destination")):
        country = get_path(alert, f'{side}.geo.country_name')
        asn_org = get_path(alert, f'{side}.as.organization.name')
        parts = [p for p in (country, asn_org) if p]
        if parts:
            geo_lines.append(f"**{label} GeoIP:** {' / '.join(parts)}")
    if geo_lines:
        sections.append("\n".join(geo_lines))

    # rule.metadata -- readable key/value dump, never dynamic tags.
    metadata = get_path(alert, 'rule.metadata')
    if isinstance(metadata, dict) and metadata:
        meta_lines = ["**Rule Metadata:**"]
        for key, value in metadata.items():
            display_value = ", ".join(value) if isinstance(value, list) else value
            meta_lines.append(f"- **{key.replace('_', ' ').title()}**: {display_value}")
        sections.append("\n".join(meta_lines))

    # Decoded payload, truncated -- NEVER put into an observable.
    payload = get_path(alert, 'network.data.decoded')
    if payload:
        sections.append(
            "**Payload (truncated to 300 chars, may be binary/unreadable):**\n"
            f"```\n{payload[:300]}\n```"
        )

    return "\n\n".join(sections)


def normalize_suricata_alert(alert: dict) -> dict:
    """Suricata-only entry point, per the dedicated spec this implements.
    `alert` is already unwrapped (build_hive_alert does
    that before dispatching here) -- the ECS-normalized Suricata document
    itself, fields at its own top level (rule/source/destination/network/
    event/...), not the n8n webhook envelope.

    Deliberately does NOT set `pap` (unlike the Sigma/YARA path below) --
    the spec this implements only defines `tlp` as an explicit TODO and
    is silent on `pap` entirely; adding either would be inventing a field
    the spec never asked for."""
    if not isinstance(alert, dict):
        alert = {}

    dataset = get_path(alert, 'event.dataset')
    if dataset is not None and dataset != 'suricata.alert':
        raise UnsupportedSuricataDatasetError(
            f"normalize_suricata_alert only supports event.dataset == "
            f"'suricata.alert' (this deployment's Suricata app-layer "
            f"logging is off); got {dataset!r}."
        )

    result = {
        "type": "suricata",
        "source": "security-onion",
        "title": get_path(alert, 'rule.name'),
        "severity": _map_suricata_severity(get_path(alert, 'event.severity_label')),
        "description": _build_suricata_description(alert),
        "tags": _extract_suricata_tags(alert),
        "observables": _extract_suricata_observables(alert),
        # TODO: tlp -- not decided for this deployment. Do not default it
        # here; set explicitly once chosen (n8n workflow or human review).
    }

    # `_id` lives conceptually at the Elasticsearch hit's own root, not
    # nested under a named ECS group (rule/source/event/...) -- read here
    # as a direct top-level key of `alert` itself. Omitted (not guessed)
    # if the upstream n8n workflow doesn't propagate it into the webhook
    # body.
    source_ref = alert.get('_id')
    if source_ref is not None:
        result["sourceRef"] = source_ref

    date_ms = _suricata_timestamp_ms(alert)
    if date_ms is not None:
        result["date"] = date_ms

    return result


# ==================================================================
# SECTION 5 -- build the full TheHive alert body (Sigma/YARA)
# ==================================================================
def build_hive_alert(alert: dict) -> dict:
    """Entry point: raw SOC alert of any shape -> full TheHive 5 alert
    body, metadata AND observables.

    Suricata alerts are dispatched to `normalize_suricata_alert`
    immediately and do not run any of the Sigma/YARA logic below --
    Suricata's ECS shape is fully confirmed field-by-field (the
    so-alert-reference pipeline chain, read source-to-source, not
    inferred from samples), so it gets its own table-driven, schema-exact
    normalizer, instead of the blind whole-tree IOC scan built for
    Sigma/YARA's far less predictable shapes."""
    if not isinstance(alert, dict):
        alert = {}
    alert = unwrap_webhook(alert)

    source_engine = detect_source_engine(alert)

    if source_engine == 'suricata':
        return normalize_suricata_alert(alert)

    iocs = extract_iocs(alert)
    hostname = iocs['hostname']['value'] if iocs['hostname']['found'] else None
    host_ips = iocs['host_ip'] or []
    agent_id = iocs['agent_id']['value'] if iocs['agent_id']['found'] else None
    hash_owners = _extract_hash_owners(alert)

    rule_name = resolve_rule_name(alert)
    rule_uuid = resolve_rule_uuid(alert)
    severity = resolve_severity(alert)
    timestamp_ms = resolve_timestamp_ms(alert)
    source_ref = resolve_source_ref(alert, hostname, rule_uuid, timestamp_ms)
    context_line = resolve_context_line(alert, source_engine)

    severity_label = {1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}[severity]
    host_part = hostname or 'unknown-host'
    title = f"[{severity_label}] {rule_name} - {host_part}"

    # network.community_id is the pivot key to this flow's companion
    # Elasticsearch documents (http/tls/dns event_type records SO indexes
    # SEPARATELY from the alert). This function can't join across
    # documents, but exposing the key lets an analyst manually find what
    # it can't reach. Sysmon network_connection events compute a real
    # community_id (so-alert-reference/ingest/sysmon's trailing
    # {"community_id": {}} processor) nested under event_data.network.*
    # for a Sigma alert; the top-level path is a defensive fallback for an
    # 'unknown'-engine alert that happens to carry a top-level one.
    community_id = first_non_empty(
        get_path(alert, 'network.community_id'),
        get_path(alert, 'event_data.network.community_id'),
    )

    description_lines = [
        f"Detection engine: {source_engine}",
        f"Rule: {rule_name}" + (f" ({rule_uuid})" if rule_uuid else ""),
    ]
    if hostname:
        description_lines.append(f"Host: {hostname}" + (f" ({host_ips[0]})" if host_ips else ""))
    if agent_id:
        description_lines.append(f"Agent ID: {agent_id}")
    if context_line:
        description_lines.append(context_line)
    if community_id:
        description_lines.append(f"Flow ID (community_id): {community_id}")
    description = "\n".join(description_lines)

    return {
        "type": source_engine,
        "source": "security-onion",
        "sourceRef": source_ref,
        "title": title,
        "description": description,
        "severity": severity,
        "tlp": DEFAULT_TLP,
        "pap": DEFAULT_PAP,
        "date": timestamp_ms,
        "observables": build_observables(iocs, hash_owners) + resolve_response_observables(
            alert, source_engine, hostname, host_ips,
        ),
    }


# ==================================================================
# n8n entry point -- must be the LAST code in the box. n8n's NATIVE
# Python runner (v2.0+) exposes only `_items` (all-items mode) or
# `_item` (per-item mode) -- not `_input`, which was Pyodide-only and
# was removed in v2.0. `_items` is already a plain list shaped like
# [{"json": {...}}, ...]. Set the node's Mode to "Run Once for All Items".
# ==================================================================
results = []
for item in _items:
    try:
        raw = item.get("json") if isinstance(item, dict) else None
        results.append({"json": build_hive_alert(raw)})
    except Exception as e:
        results.append({"json": {
            "error": f"hive_alert_full failed: {e}",
            "raw_item": item.get("json") if isinstance(item, dict) else None,
        }})

return results