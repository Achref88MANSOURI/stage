"""Resolves an alert's host to its CMDB asset in iTop, for the
asset-criticality side of triage reasoning.

Looks up by asset number first, falling back to hostname (see `_locate`
below). Authentication is username/password (`ITOP_USER`/`ITOP_PWD`), not an
API key.

This deployment runs the stock iTop community demo dataset (`Server1`-`4`,
`VM1`-`4`, hypervisors, network devices, no `PC` class), with no real host
records populated yet. A lookup miss on a real Security Onion alert reflects
that missing data, not a bug, and adding real records later requires no code
changes here. A few fields are also simply not available on this instance:
there's no IP-based lookup at all (`managementip` is blank everywhere and no
IPv4Address/IPv4Subnet class exists), and `network_zone`, `data_sensitivity`,
and `owner` aren't attributes on any class. None of these should be
synthesized from other data (e.g. deriving `network_zone` from a subnet
map) — an absent field should stay absent, not be guessed at.

`asset_type` has no single source field across classes, so it falls back
through `type`, then `networkdevicetype_name` (the real "kind of device"
field on `NetworkDevice`, e.g. `"Router"`), then `model_name`. Virtual
machines and hypervisors carry none of the three, so `asset_type` stays
`None` for those.

Two real API behaviors are worth knowing before touching this file:
`output_fields: "*"` only returns the attributes of the class actually
queried, not of the object's real subclass — querying `FunctionalCI` misses
fields only `Server` has, and vice versa — which is why the lookup below is
two-phase: locate, then re-fetch on the object's `finalclass`. And
`asset_number` is not a filterable attribute on `FunctionalCI` (the API
rejects it with an `OqlNormalizeException`); it only exists on
`PhysicalDevice` and its subclasses, which `VirtualMachine` is not one of —
hence the hostname fallback for VMs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time

import httpx

import config
from schemas import AssetContext, Gap

logger = logging.getLogger(__name__)

TOOL_NAME = "itop_asset_lookup"
SOURCE = "itop"

REST_VERSION = "1.3"

# The observed set of business_criticity values across this instance's CIs.
# iTop's OQL does not validate enum values in a WHERE clause (an invalid value
# returns 0 rows rather than an error), so this is an observed set, not a
# schema-derived one. An unseen value is passed through unchanged and logged,
# never silently coerced — a new tier appearing is something to find out about.
KNOWN_CRITICALITY_VALUES = {"low", "medium", "high"}

# Hostnames arrive from Security Onion telemetry and are attacker-influenceable,
# and they are interpolated into an OQL string. Anything outside this set is
# rejected rather than escaped — no legitimate hostname needs it, and rejecting
# is safer than trusting an escaping routine against a query language whose
# quoting rules we do not control.
_SAFE_OQL_VALUE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")


class ItopOqlValueError(ValueError):
    """A lookup key contained characters unsafe to interpolate into OQL."""


def _check_oql_value(value: str, label: str) -> str:
    if not _SAFE_OQL_VALUE.match(value or ""):
        raise ItopOqlValueError(
            f"{label} {value!r} contains characters not permitted in an OQL literal"
        )
    return value


def _normalise_criticality(raw: str | None) -> str | None:
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if not value:
        return None
    if value not in KNOWN_CRITICALITY_VALUES:
        logger.warning(
            "%s: unrecognised business_criticity %r (known: %s) — passing through",
            TOOL_NAME,
            raw,
            sorted(KNOWN_CRITICALITY_VALUES),
        )
    return value


def _as_list(value) -> list[str]:
    """iTop returns link-set attributes as `[]` or a list of link objects, and
    occasionally as the string `'[]'`."""
    if not value or value == "[]":
        return []
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict):
                name = item.get("friendlyname") or item.get("name")
                if name:
                    out.append(str(name))
            elif item:
                out.append(str(item))
        return out
    return []


def _blank_to_none(value):
    """iTop returns unset scalars as `''` and unset external keys as `'0'`,
    neither of which should reach the model as a value."""
    if value in (None, "", "0"):
        return None
    return value


async def _itop_call(payload: dict, timeout: float) -> dict:
    """POST to the iTop REST endpoint. Raises on transport or HTTP error."""
    data = {
        "auth_user": config.ITOP_USER,
        "auth_pwd": config.ITOP_PWD,
        "json_data": json.dumps(payload),
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{config.ITOP_URL}/webservices/rest.php",
            params={"version": REST_VERSION},
            data=data,
        )
        response.raise_for_status()
        return response.json()


async def _itop_get(cls: str, oql: str, timeout: float, fields: str = "*") -> dict:
    return await _itop_call(
        {"operation": "core/get", "class": cls, "key": oql, "output_fields": fields},
        timeout=timeout,
    )


def _first_object(payload: dict) -> tuple[str, dict] | None:
    """iTop returns `objects` keyed by `"<Class>::<id>"`. A non-zero `code` is
    an application-level error even though the HTTP status was 200 — iTop does
    not use HTTP status codes for API errors."""
    if payload.get("code") not in (0, "0"):
        raise RuntimeError(f"iTop error {payload.get('code')}: {payload.get('message')}")
    objects = payload.get("objects") or {}
    for key, obj in objects.items():
        return key, obj
    return None


def _build_asset_context(key: str, obj: dict, matched_by: str) -> AssetContext:
    fields = obj.get("fields") or {}
    itop_class = obj.get("class") or fields.get("finalclass")
    _, _, itop_id = key.partition("::")

    return AssetContext(
        found=True,
        hostname=_blank_to_none(fields.get("name")),
        criticality=_normalise_criticality(fields.get("business_criticity")),
        # No owner attribute exists in this iTop — see module docstring.
        owner=None,
        organization=_blank_to_none(
            fields.get("organization_name") or fields.get("org_id_friendlyname")
        ),
        services=_as_list(fields.get("services_list")),
        # Neither attribute exists in this iTop — see module docstring.
        network_zone=None,
        data_sensitivity=[],
        asset_type=_blank_to_none(
            fields.get("type") or fields.get("networkdevicetype_name") or fields.get("model_name")
        ),
        # No object in this iTop carries an IP — see module docstring.
        ip_addresses=[],
        asset_number=_blank_to_none(fields.get("asset_number")),
        itop_class=itop_class,
        itop_id=itop_id or None,
        matched_by=matched_by,
        status=_blank_to_none(fields.get("status")),
        os_family=_blank_to_none(fields.get("osfamily_name")),
        os_version=_blank_to_none(fields.get("osversion_name")),
        location=_blank_to_none(fields.get("location_name")),
        obsolete=fields.get("obsolescence_flag")
        if isinstance(fields.get("obsolescence_flag"), bool)
        else None,
    )


async def _locate(hostname: str | None, host_id: str | None, timeout: float):
    """Find the object, primary key first.

    Returns `(key, obj, matched_by, queried_class)` or None. The queried class
    is threaded out because the caller needs it to decide whether a re-fetch on
    the real subclass is required — see `_refetch_on_final_class`.

    `asset_number` is tried first because, when populated, it's a stable
    identifier that can match an alert's host id exactly, whereas hostname
    comparison in OQL `=` is case-sensitive and breaks on FQDN vs short name.
    On this instance `asset_number` is blank on every object (see module
    docstring) so this branch never matches today — it's kept because it's
    free and forward-compatible. It must be queried on `PhysicalDevice`; it
    is not filterable on `FunctionalCI`.

    The hostname fallback queries `FunctionalCI` deliberately — the broadest
    class — so that a VirtualMachine (which has no `asset_number`) or any other
    CI type still resolves.
    """
    if host_id:
        _check_oql_value(host_id, "host_id")
        found = _first_object(
            await _itop_get(
                "PhysicalDevice",
                f'SELECT PhysicalDevice WHERE asset_number = "{host_id}"',
                timeout,
            )
        )
        if found:
            return found[0], found[1], "asset_number", "PhysicalDevice"

    if hostname:
        _check_oql_value(hostname, "hostname")
        found = _first_object(
            await _itop_get(
                "FunctionalCI", f'SELECT FunctionalCI WHERE name = "{hostname}"', timeout
            )
        )
        if found:
            return found[0], found[1], "hostname", "FunctionalCI"

    return None


async def _refetch_on_final_class(
    key: str, obj: dict, queried_class: str, timeout: float
) -> dict:
    """Re-fetch on the object's real subclass so the full field set comes back.

    `output_fields: "*"` yields only the queried class's attributes. Locating via
    `FunctionalCI` misses `asset_number`/`status`; locating via `PhysicalDevice`
    misses `osfamily_name`. Both are wanted, so the object is re-read on its
    `finalclass` once it is known.

    A failure here is non-fatal: the partial object from the locate phase is
    still a valid, useful result.
    """
    # NOTE `obj["class"]` is the object's ACTUAL class, not the class that was
    # queried — comparing against it makes this a silent no-op, which is how the
    # first live run lost osfamily_name and asset_number. `queried_class` must
    # be threaded down from the locate phase.
    final_class = obj.get("fields", {}).get("finalclass") or obj.get("class")
    if not final_class or final_class == queried_class:
        return obj

    _, _, itop_id = key.partition("::")
    if not itop_id.isdigit():
        return obj

    try:
        found = _first_object(
            await _itop_get(
                final_class, f"SELECT {final_class} WHERE id = {int(itop_id)}", timeout
            )
        )
    except Exception as exc:  # noqa: BLE001 — partial data beats no data
        logger.debug("%s: refetch on %s failed, using partial: %s", TOOL_NAME, final_class, exc)
        return obj
    return found[1] if found else obj


async def itop_asset_lookup(
    hostname: str | None,
    host_id: str | None = None,
    timeout: float | None = None,
) -> tuple[AssetContext, Gap | None]:
    """Look up an asset by Elastic Agent host UUID, falling back to hostname.
    Never raises. Returns `(AssetContext, Gap | None)`:

    - found        -> `(populated AssetContext, Gap | None)`. A Gap is STILL
                      returned alongside a successful lookup when the asset has
                      no criticality, because impact reasoning silently
                      degrades to a baseline in that case — a real risk worth
                      surfacing. A found-but-blank asset must not look like a
                      fully successful lookup.
    - not in CMDB  -> `(AssetContext(found=False), Gap)` — a real result, not a
                      failure, and its reason says so.
    - backend fail -> `(AssetContext(found=False), Gap)` with the transport error
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_ITOP
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    def gap(reason: str) -> Gap:
        return Gap(source=SOURCE, tool=TOOL_NAME, reason=reason, duration_ms=elapsed_ms())

    if not hostname and not host_id:
        return AssetContext(found=False), gap(
            "Alert carried neither a hostname nor a host id — nothing to look up"
        )

    try:
        located = await asyncio.wait_for(
            _locate(hostname, host_id, timeout), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs for %s", TOOL_NAME, timeout, hostname)
        return AssetContext(found=False, hostname=hostname), gap(
            f"Timeout after {timeout}s querying iTop at {config.ITOP_URL}"
        )
    except ItopOqlValueError as exc:
        logger.warning("%s rejected an unsafe lookup value: %s", TOOL_NAME, exc)
        return AssetContext(found=False), gap(f"Unsafe lookup value: {exc}")
    except httpx.HTTPStatusError as exc:
        body = (exc.response.text or "")[:200].replace("\n", " ")
        return AssetContext(found=False, hostname=hostname), gap(
            f"HTTP {exc.response.status_code} from iTop: {body}"
        )
    except httpx.ConnectError as exc:
        return AssetContext(found=False, hostname=hostname), gap(
            f"Cannot connect to iTop at {config.ITOP_URL}: {exc}"
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s failed for %s: %s", TOOL_NAME, hostname, exc)
        return AssetContext(found=False, hostname=hostname), gap(
            f"{type(exc).__name__}: {exc}"
        )

    if located is None:
        return AssetContext(found=False, hostname=hostname), gap(
            f"No CMDB object matched asset_number={host_id!r} or name={hostname!r}"
        )

    key, obj, matched_by, queried_class = located
    try:
        obj = await asyncio.wait_for(
            _refetch_on_final_class(key, obj, queried_class, timeout), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.debug("%s: refetch timed out, using partial object", TOOL_NAME)

    try:
        context = _build_asset_context(key, obj, matched_by)
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s could not map %s: %s", TOOL_NAME, key, exc)
        return AssetContext(found=False, hostname=hostname), gap(
            f"Object mapping failed for {key}: {type(exc).__name__}: {exc}"
        )

    if context.criticality is None:
        return context, gap(
            f"Asset {key} found but has no business_criticity — impact scoring "
            f"will fall back to its baseline for this alert"
        )

    return context, None
