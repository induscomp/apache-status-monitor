"""Windowed IP/network observations, not reconstructed access logs."""

import ipaddress
import re
from collections import Counter
from datetime import timedelta
from urllib.parse import unquote

from app.analysis import baseline, domain_spike
from app.geo import lookup
from app.performance import internal

WINDOWS = (5, 10, 25, 30, 60)
PROBE = re.compile(
    r"/(?:\.env|\.git|\.svn|\.bashrc|\.htpasswd|\.DS_Store|\.aws/credentials|actuator/env|wp-content/uploads/.*\.php|wp-config\.php|phpinfo(?:\.php)?|vendor/phpunit|cgi-bin|\.well-known/.*\.php)(?:[/.]|$)|(?:\.\./|%2e%2e)",
    re.I,
)
SENSITIVE = re.compile(
    r"/(?:wp-login\.php|xmlrpc\.php|wp-admin|admin|administrator|login|phpmyadmin)(?:[/.]|$)", re.I
)


def traces(workers, domains_only=False):
    result = []
    for w in workers:
        path, ip = w.get("path"), w.get("client")
        if (
            internal(w)
            or not path
            or not ip
            or w.get("request_kind") == "h2_session"
            or not w.get("method")
            or w["method"].startswith("[")
        ):
            continue
        if w.get("state") not in {"R", "W", "K", "C", "_"}:
            continue
        previous = w.get("observation") != "current" or w.get("state") in {"K", "C"}
        # A retained request without an age cannot be assigned to a recent window.
        if previous and (w.get("seconds_since") is None or not 0 <= w["seconds_since"] <= 300):
            continue
        decoded = unquote(path)
        if not domains_only and not (PROBE.search(decoded) or SENSITIVE.search(decoded)):
            continue
        result.append(
            dict(
                ip=ip,
                domain=(w.get("domain") or "")[:254],
                path=path,
                method=w["method"],
                probe=bool(PROBE.search(decoded)),
                previous=previous,
                auth=w["method"] == "POST"
                and bool(re.search(r"/(?:wp-login\.php|xmlrpc\.php|login)(?:/|$)", decoded, re.I)),
                slot=w.get("slot"),
                req=w.get("request_ms"),
            )
        )
    return result


def domain_observations(workers):
    visits = {}
    for trace in traces(workers, domains_only=True):
        if trace["domain"]:
            visits.setdefault(trace["ip"], set()).add(trace["domain"])
    return {ip: sorted(domains) for ip, domains in visits.items()}


def trusted(ip, settings):
    address = ipaddress.ip_address(ip)
    address = getattr(address, "ipv4_mapped", None) or address
    return any(
        address in ipaddress.ip_network(value)
        for value in settings.get("multidomain_trusted_ips", [])
    )


def network(ip):
    try:
        address = ipaddress.ip_address(ip)
        address = getattr(address, "ipv4_mapped", None) or address
        return str(
            ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 64}", strict=False)
        )
    except ValueError:
        return None


def aggregate(frames):
    groups = {"ips": {}, "networks": {}}
    seen = set()
    for frame in frames:
        captured = (frame.details or {}).get("security", {})
        if not frame.valid or captured.get("window_version") != 1:
            continue
        records = captured.get("traces", [])
        visits = captured.get("domain_observations", {})
        addresses = set(captured.get("ips", {})) | {r["ip"] for r in records} | set(visits)
        for ip in addresses:
            active = captured.get("ips", {}).get(ip, {})
            items = [r for r in records if r["ip"] == ip]
            for group, key in (("ips", ip), ("networks", network(ip))):
                if not key:
                    continue
                row = groups[group].setdefault(
                    key,
                    dict(
                        key=key,
                        ips=set(),
                        domains=set(),
                        samples=set(),
                        active_by_sample=Counter(),
                        endpoints=Counter(),
                        signatures=0,
                        retained=0,
                        probes=0,
                        auth=0,
                        auth_samples=set(),
                        probe_samples=set(),
                        first=frame.observed_at,
                        last=frame.observed_at,
                        shared={},
                    ),
                )
                row["ips"].add(ip)
                row["domains"].update(active.get("peers", {}))
                row["domains"].update(visits.get(ip, []))
                for domain in set(active.get("peers", {})) | set(visits.get(ip, [])):
                    row.setdefault("domain_samples", {}).setdefault(domain, set()).add(
                        frame.observed_at
                    )
                row["samples"].add(frame.observed_at)
                row["active_by_sample"][frame.observed_at] += active.get("active", 0)
                row["last"] = frame.observed_at
                for r in items:
                    if r["domain"]:
                        row["domains"].add(r["domain"])
                    endpoint = f"{r['method']} {r['path']}"
                    shared = f"{r['domain']} · {endpoint}"
                    row["shared"].setdefault(shared, set()).add(ip)
                    signature = (group, key, ip, r["slot"], r["domain"], endpoint, r["req"])
                    if signature in seen:
                        continue
                    seen.add(signature)
                    row["endpoints"][endpoint] += 1
                    row["signatures"] += 1
                    row["retained"] += int(r["previous"])
                    row["probes"] += int(r["probe"])
                    row["auth"] += int(r.get("auth", False))
                    if r.get("auth"):
                        row["auth_samples"].add(frame.observed_at)
                    if r["probe"]:
                        row["probe_samples"].add(frame.observed_at)
    return groups


def analyze(frames, at, minutes, settings=None):
    from app.alert_settings import AlertSettings

    settings = settings or AlertSettings().model_dump()
    frames = list(
        {
            int(f.observed_at.timestamp()) // 300: f
            for f in sorted(frames, key=lambda f: f.observed_at)
        }.values()
    )
    selected = [f for f in frames if at - timedelta(minutes=minutes) < f.observed_at <= at]
    valid = [
        f
        for f in selected
        if f.valid and (f.details or {}).get("security", {}).get("window_version") == 1
    ]
    expected = minutes // 5
    coverage = min(1, len(valid) / expected)
    current = aggregate(valid)
    preceding = [
        f
        for f in frames
        if at - timedelta(minutes=2 * minutes) < f.observed_at <= at - timedelta(minutes=minutes)
        and f.valid
        and (f.details or {}).get("security", {}).get("window_version") == 1
    ]
    previous = aggregate(preceding) if len(preceding) >= expected else {"ips": {}, "networks": {}}
    # Equal-length, non-overlapping windows, excluding the most recent hour.
    reference = []
    for offset in range(60, 24 * 60, minutes):
        right = at - timedelta(minutes=offset)
        bucket = [f for f in frames if right - timedelta(minutes=minutes) < f.observed_at <= right]
        if (
            len(
                [
                    f
                    for f in bucket
                    if f.valid and (f.details or {}).get("security", {}).get("window_version") == 1
                ]
            )
            >= expected
        ):
            reference.append(aggregate(bucket))
    output = dict(
        minutes=minutes,
        samples=len(valid),
        expected=expected,
        coverage=coverage,
        start=at - timedelta(minutes=minutes),
        end=at,
        ips=[],
        networks=[],
    )
    for group in ("ips", "networks"):
        for key, row in current[group].items():
            counts = [
                sum(b[group].get(key, {}).get("active_by_sample", {}).values()) for b in reference
            ]
            ref = baseline(counts, minimum=12) if sum(v > 0 for v in counts) >= 3 else None
            observed = sum(row["active_by_sample"].values())
            before = sum(previous[group].get(key, {}).get("active_by_sample", {}).values())
            short_ref = (
                {"median": before, "samples": 1, "mad": 0, "kind": "previous_window"}
                if before > 0
                else None
            )
            if ref is None and domain_spike(observed, short_ref, settings):
                ref = short_ref
            spike = domain_spike(observed, ref, settings)
            shared = [
                dict(target=k, ips=sorted(v)) for k, v in row["shared"].items() if len(v) >= 2
            ]
            probe_pattern = row["probes"] >= 2 and (
                len(row["probe_samples"]) >= 2 or len(row["endpoints"]) >= 2
            )
            credential_pattern = (
                row["auth"] >= 3 and len(row["auth_samples"]) >= 2 and (ref is None or spike)
            )
            coordinated = (
                group == "networks"
                and bool(shared)
                and (row["probes"] >= 2 or credential_pattern or spike)
            )
            domain_limit = settings.get("multidomain_min_domains", 3)
            exempt = group == "ips" and trusted(key, settings)
            multidomain = group == "ips" and len(row["domains"]) >= domain_limit and not exempt
            flagged = (
                probe_pattern or credential_pattern or coordinated or spike or multidomain
            ) and (group == "ips" or len(row["ips"]) >= 2)
            score = min(
                100,
                (35 if probe_pattern or credential_pattern else 0)
                + (25 if spike else 0)
                + (25 if coordinated else 0)
                + (30 if multidomain else 0)
                + (min(3, len(row["samples"])) * 5 if row["signatures"] else 0),
            )
            reasons = []
            if multidomain:
                reasons.append(
                    f"Una misma IP observada en {len(row['domains'])} dominios dentro de {minutes} minutos (aviso desde {domain_limit}); revisar navegación entre sitios"
                )
            elif exempt and len(row["domains"]) >= domain_limit:
                reasons.append(
                    "IP de confianza para la regla multidominio; las demás señales siguen evaluándose"
                )
            if spike:
                reasons.append(
                    f"{observed} conexiones sumadas frente a {ref['median']} en "
                    + (
                        "la ventana anterior; comparación corta, no línea base consolidada"
                        if ref.get("kind") == "previous_window"
                        else "su referencia de ventanas iguales"
                    )
                )
            if row["signatures"]:
                reasons.append(
                    f"{row['signatures']} huellas de petición a rutas sensibles; {row['retained']} son últimas peticiones retenidas"
                )
            if probe_pattern:
                reasons.append(
                    f"{row['probes']} huellas sobre rutas de exposición/configuración; revisar posible escaneo"
                )
            if credential_pattern:
                reasons.append(
                    f"{row['auth']} huellas POST de autenticación/XML-RPC en {len(row['auth_samples'])} capturas; revisar repetición"
                )
            if shared:
                reasons.append(
                    f"{len(row['ips'])} IP del rango coinciden en {len(shared)} destinos y endpoints; no demuestra coordinación"
                )
            if len(row["samples"]) >= 2:
                reasons.append(f"Presencia en {len(row['samples'])} capturas de la ventana")
            output[group].append(
                dict(
                    key=key,
                    score=score,
                    flagged=flagged,
                    multidomain=multidomain,
                    domain_samples={
                        d: sorted(times) for d, times in row.get("domain_samples", {}).items()
                    },
                    reasons=reasons,
                    reference=ref,
                    observations=observed,
                    peak=max(row["active_by_sample"].values(), default=0),
                    samples=len(row["samples"]),
                    ips=sorted(row["ips"]),
                    domains=sorted(row["domains"]),
                    endpoints=dict(row["endpoints"]),
                    shared=shared,
                    first=row["first"],
                    last=row["last"],
                    retained=row["retained"],
                    probes=row["probes"],
                    signatures=row["signatures"],
                    status="Patrón para revisar"
                    if flagged
                    else "Rutas sensibles observadas"
                    if row["signatures"]
                    else "Actividad observada",
                    geo=lookup(key) if group == "ips" else None,
                )
            )
        output[group].sort(key=lambda r: (r["score"], r["observations"]), reverse=True)
    return output


def evaluate(db, frame, history, settings):
    from sqlalchemy import select

    from app.incidents import transition
    from app.models import AnomalyState, Incident

    selected = [f for f in history if f.observed_at >= frame.observed_at - timedelta(hours=25)] + [
        frame
    ]
    results = [analyze(selected, frame.observed_at, m, settings) for m in WINDOWS]
    candidates = {}
    for result in results:
        for group in ("ips", "networks"):
            for row in result[group]:
                if not row["flagged"] or result["coverage"] < 1:
                    continue
                subject = f"ipwatch:{group}:{row['key']}"
                if subject not in candidates or row["score"] > candidates[subject][0]["score"]:
                    candidates[subject] = (row, result["minutes"])
    states = db.scalars(
        select(AnomalyState).where(
            AnomalyState.service_id == frame.service_id, AnomalyState.subject.like("ipwatch:%")
        )
    ).all()
    pending = {
        s.subject
        for s in states
        if s.bad or (s.incident_id and db.get(Incident, s.incident_id).status == "open")
    }
    for subject in set(candidates) | pending:
        state = next((s for s in states if s.subject == subject), None)
        if state and state.last_at >= frame.observed_at:
            continue
        existing = db.get(Incident, state.incident_id) if state and state.incident_id else None
        opened = bool(existing and existing.status == "open")
        row, minutes = candidates.get(subject, ({}, 60))
        # Missing observations must not resolve a window-based incident.
        complete = all(r["coverage"] == 1 for r in results) and frame.valid
        ref = {"median": 0, "samples": 0, "mad": 0} if complete else None
        if row:

            def signature(t):
                return (t["ip"], t["slot"], t["domain"], t["method"], t["path"], t["req"])

            older = {
                signature(t)
                for f in selected[:-1]
                if f.observed_at > frame.observed_at - timedelta(minutes=60)
                for t in (f.details or {}).get("security", {}).get("traces", [])
            }
            fresh_probe = any(
                t["ip"] in row["ips"]
                and (t["probe"] or t.get("auth"))
                and signature(t) not in older
                for t in (frame.details or {}).get("security", {}).get("traces", [])
            )
            current_ips = (frame.details or {}).get("security", {}).get("ips", {})
            fresh_spike = domain_spike(row["observations"], row["reference"], settings) and any(
                current_ips.get(ip, {}).get("active", 0) > 0 for ip in row["ips"]
            )
            current_visits = (
                (frame.details or {}).get("security", {}).get("domain_observations", {})
            )
            previous_frame = selected[-2] if len(selected) > 1 else None
            previous_visits = (
                (previous_frame.details or {}).get("security", {}).get("domain_observations", {})
                if previous_frame
                else {}
            )
            key = row["key"]
            fresh_multidomain = row.get("multidomain", False) and (
                len(current_ips.get(key, {}).get("peers", {}))
                >= settings.get("multidomain_min_domains", 3)
                or bool(set(current_visits.get(key, [])) - set(previous_visits.get(key, [])))
            )
            if not (fresh_probe or fresh_spike or fresh_multidomain):
                ref = None  # Overlapping windows cannot provide new confirmation alone.
        event = dict(
            at=frame.observed_at.isoformat(),
            active=row.get("peak", 0),
            domains=row.get("domains", [])[:30],
            reasons=row.get("reasons", ["Sin patrón combinado en las ventanas completas"]),
        )
        timeline = (existing.evidence.get("timeline", []) if opened else []) + [event]
        evidence = dict(
            algorithm="ip-window-v1",
            revision=frame.revision,
            feature="window_priority",
            value=row.get("score", 0),
            reference=ref,
            window_minutes=minutes,
            baseline=row.get("reference"),
            reasons=event["reasons"],
            timeline=timeline[-288:],
            alert_settings=settings,
            frame_id=frame.id,
            note="Huellas observadas, no solicitudes distintas ni ataque confirmado. Compartir prefijo no demuestra coordinación.",
        )
        if opened and existing.evidence.get("revision") != frame.revision:
            ref = None
        transition(db, frame, subject, "ip_activity", row.get("score", 0), ref, bool(row), evidence)
        if opened and ref:
            existing.evidence = {**existing.evidence, "timeline": timeline[-288:]}
