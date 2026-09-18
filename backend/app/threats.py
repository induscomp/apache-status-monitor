"""Explainable snapshot signals; never an attribution or a traffic counter."""

import re
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta
from urllib.parse import unquote

from sqlalchemy import select

from app.analysis import baseline, domain_spike, resource_spike
from app.geo import lookup
from app.models import ServerFrame
from app.performance import internal, stats

SENSITIVE = re.compile(
    r"/(?:wp-login\.php|xmlrpc\.php|\.env|\.git|\.bashrc|phpinfo(?:\.php)?|admin|wp-admin)(?:[/.]|$)",
    re.I,
)


def capture(workers):
    ips, domains = {}, {}
    for w in workers:
        if (
            internal(w)
            or w.get("observation") != "current"
            or w.get("state") not in {"R", "W", "K", "C"}
            or not w.get("client")
        ):
            continue
        ip, domain = w["client"], (w.get("domain") or "")[:254] or None
        path = (
            w.get("path")
            if w.get("state") in {"R", "W"} and w.get("request_kind") != "h2_session"
            else None
        )
        sensitive = bool(path and SENSITIVE.search(unquote(path)))
        for table, key, other in ((ips, ip, domain), (domains, domain, ip)):
            if not key:
                continue
            row = table.setdefault(
                key, dict(active=0, peers={}, states={}, endpoints={}, sensitive=0, posts=0, req=[])
            )
            row["active"] += 1
            if other:
                row["peers"][other] = row["peers"].get(other, 0) + 1
            state = w["state"]
            row["states"][state] = row["states"].get(state, 0) + 1
            if sensitive:
                label = f"{w.get('method') or '?'} {path}"
                row["endpoints"][label] = row["endpoints"].get(label, 0) + 1
                row["sensitive"] += 1
                row["posts"] += int(w.get("method") == "POST")
            if state in {"R", "W"} and path and w.get("request_ms") is not None:
                row["req"].append(w["request_ms"])
    for ip, row in ips.items():
        row["country"] = lookup(ip).get("country")
    for table in (ips, domains):
        for row in table.values():
            row.update(stats(row.pop("req")))
    from app.ip_activity import traces

    return dict(version=1, window_version=1, traces=traces(workers), ips=ips, domains=domains)


def history(db, frame):
    rows = db.scalars(
        select(ServerFrame)
        .where(
            ServerFrame.service_id == frame.service_id,
            ServerFrame.revision == frame.revision,
            ServerFrame.observed_at >= frame.observed_at - timedelta(days=30),
            ServerFrame.observed_at < frame.observed_at,
        )
        .order_by(ServerFrame.observed_at)
    ).all()
    return list({int(r.observed_at.timestamp()) // 300: r for r in rows}.values())


def data(frame):
    return (frame.details or {}).get("security", {})


def reference_rows(rows, at):
    eligible = [
        r
        for r in rows
        if r.valid and data(r).get("version") == 1 and r.observed_at <= at - timedelta(minutes=30)
    ]
    seasonal = [
        r
        for r in eligible
        if r.observed_at.weekday() == at.weekday() and r.observed_at.hour == at.hour
    ]
    if len(seasonal) >= 24 and len({r.observed_at.date() for r in seasonal}) >= 3:
        return seasonal, "mismo día de semana y hora UTC"
    hourly = [r for r in eligible if r.observed_at.hour == at.hour]
    if len(hourly) >= 48 and len({r.observed_at.date() for r in hourly}) >= 4:
        return hourly, "misma hora UTC"
    return [
        r for r in eligible if r.observed_at >= at - timedelta(hours=24)
    ], "últimas 24 h, excluidos 30 min recientes"


def origins(frame, domain):
    counts = Counter()
    for row in data(frame).get("ips", {}).values():
        if row.get("country") and domain in row["peers"]:
            counts[row["country"]] += row["peers"][domain]
    return counts


def assess(frame, rows, settings=None):
    refs, basis = reference_rows(rows, frame.observed_at)
    result = dict(ips=[], domains=[], degradation=[], basis=basis, samples=len(refs))
    recent = [r for r in rows if r.observed_at >= frame.observed_at - timedelta(minutes=30)]
    for group in ("ips", "domains"):
        for key, stored_row in data(frame).get(group, {}).items():
            # Stored ranking scores are outputs, never inputs to a fresh assessment.
            row = {k: v for k, v in stored_row.items() if k not in {"score", "deviation"}}
            values = [data(r).get(group, {}).get(key, {}).get("active", 0) for r in refs]
            # New IPs have no personal baseline, even when the server has history.
            ref = (
                baseline(values, minimum=24)
                if group == "domains" or sum(v > 0 for v in values) >= 12
                else None
            )
            spike = domain_spike(row["active"], ref, settings)
            streak, previous_at = 1, frame.observed_at
            for old in reversed(recent):
                old_row = data(old).get(group, {}).get(key)
                if (
                    not old.valid
                    or previous_at - old.observed_at > timedelta(minutes=10)
                    or not old_row
                ):
                    break
                streak += 1
                previous_at = old.observed_at
            peers = row["peers"]
            concentration = max(peers.values(), default=0) / max(1, row["active"])
            reasons = [
                f"{row['active']} conexiones observadas",
                f"{len(peers)} {'dominios' if group == 'ips' else 'IP distintas'}",
            ]
            if group == "domains":
                countries = origins(frame, key)
                habitual = Counter()
                for old in refs:
                    habitual.update(origins(old, key))
                if sum(countries.values()) >= 5 and sum(habitual.values()) >= 50:
                    for country, count in countries.items():
                        current_share = count / sum(countries.values())
                        previous_share = habitual[country] / sum(habitual.values())
                        if current_share - previous_share >= 0.5:
                            reasons.append(
                                f"Cambio de procedencia observada: {country} {previous_share:.0%} → {current_share:.0%}; no prueba ataque"
                            )
            if spike:
                reasons.append(
                    f"Incremento ×{row['active'] / ref['median']:.1f} frente a su referencia"
                    if ref["median"]
                    else f"De {ref['median']} habituales a {row['active']} conexiones"
                )
            if row["sensitive"]:
                reasons.append("Rutas sensibles: " + ", ".join(list(row["endpoints"])[:4]))
            if row["posts"]:
                reasons.append(f"{row['posts']} POST a endpoints sensibles en esta captura")
            if streak >= 3:
                reasons.append(
                    f"Presente en {streak} capturas consecutivas; no demuestra que sea la misma conexión"
                )
            signals = (
                int(spike)
                + int(row["sensitive"] > 0)
                + int(row["posts"] > 1)
                + int(len(peers) >= 3 and row["sensitive"] > 0)
            )
            anomaly_streak = 1 if signals else 0
            for old in reversed(recent):
                old_row = data(old).get(group, {}).get(key)
                if (
                    not old.valid
                    or not old_row
                    or not (domain_spike(old_row["active"], ref, settings) or old_row["sensitive"])
                ):
                    break
                if anomaly_streak >= streak:
                    break
                anomaly_streak += 1
            score = min(100, signals * 15 + (min(anomaly_streak, 5) * 5 if signals else 0))
            category = "datos insuficientes" if ref is None else "sin desviación clara"
            if spike:
                category = (
                    "pico probablemente legítimo"
                    if not row["sensitive"] and concentration < 0.5
                    else "tráfico anómalo"
                )
            if row["sensitive"]:
                category = (
                    "patrón compatible con bots/escaneo"
                    if streak >= 3 or len(peers) >= 3
                    else "tráfico anómalo"
                )
            if spike and row["sensitive"] and signals >= 3 and anomaly_streak >= 3:
                category = "posible ataque"
            result[group].append(
                dict(
                    key=key,
                    **row,
                    reference=ref,
                    deviation=row["active"] / ref["median"] if ref and ref["median"] else None,
                    peak=max(
                        [row["active"]]
                        + [data(r).get(group, {}).get(key, {}).get("active", 0) for r in recent]
                    ),
                    concentration=concentration,
                    persistence=streak,
                    anomaly_persistence=anomaly_streak,
                    signals=signals,
                    score=score,
                    category=category,
                    reasons=reasons,
                )
            )
        result[group].sort(key=lambda r: (r["score"], r["active"]), reverse=True)
    for role in (
        "cpu",
        "load",
        "ram_free",
        "swap_free",
        "request_ms",
        "busy_workers",
        "idle_workers",
        "free_slots",
        "state_W",
        "state_R",
        "state_K",
        "state_C",
        "active_req_mean",
    ):
        if role == "request_ms" and frame.metrics.get("internal_workers", 0):
            continue
        point = frame.resources.get(role)
        if point:
            try:
                fresh = (
                    abs(
                        (
                            frame.observed_at - datetime.fromisoformat(point["source_at"])
                        ).total_seconds()
                    )
                    <= 900
                )
            except KeyError, TypeError, ValueError:
                fresh = False
            if not fresh:
                continue
            value = point["value"]
            values = [
                r.resources[role]["value"]
                for r in refs
                if r.resources.get(role, {}).get("basis") == point.get("basis")
                and r.resources.get(role, {}).get("source_at")
                and abs(
                    (
                        r.observed_at - datetime.fromisoformat(r.resources[role]["source_at"])
                    ).total_seconds()
                )
                <= 900
            ]
        else:
            value = frame.metrics.get(role)
            values = [r.metrics[role] for r in refs if r.metrics.get(role) is not None]
        ref = baseline(values, minimum=24)
        if value is None or not ref:
            continue
        down = role in {"ram_free", "swap_free", "idle_workers", "free_slots"}
        bad = resource_spike(value, ref, "ram_free" if down else role, settings)
        if bad:
            result["degradation"].append(
                dict(
                    metric=role,
                    before=ref["median"],
                    value=value,
                    source="MRTG" if point else "Apache Status",
                    note="Swap libre desciende; uso total desconocido"
                    if role == "swap_free" and point.get("capacity") is None
                    else "Desviación respecto al histórico",
                )
            )
    result["contributors"] = (
        [
            dict(kind=g, key=r["key"], reasons=r["reasons"], score=r["score"])
            for g in ("domains", "ips")
            for r in result[g]
            if r["signals"]
        ][:12]
        if result["degradation"]
        else []
    )
    if result["degradation"]:
        for old in recent[-3:]:
            if not old.valid:
                continue
            for key, row in data(old).get("domains", {}).items():
                ref = baseline(
                    [data(r).get("domains", {}).get(key, {}).get("active", 0) for r in refs],
                    minimum=24,
                )
                if domain_spike(row["active"], ref, settings):
                    result["contributors"].append(
                        dict(
                            kind="previous",
                            key=key,
                            score=0,
                            reasons=[
                                f"Captura anterior {old.observed_at.isoformat()}: {row['active']} conexiones frente a {ref['median']} habituales"
                            ],
                        )
                    )
        result["contributors"] = result["contributors"][:20]
    return result


def evaluate(db, frame, settings):
    from app.incidents import transition
    from app.models import AnomalyState, Incident

    rows = history(db, frame)
    from app.ip_activity import evaluate as evaluate_ip_activity

    evaluate_ip_activity(db, frame, rows, settings)
    result = (
        assess(frame, rows, settings) if frame.valid and data(frame) else dict(ips=[], domains=[])
    )
    frame.metrics = (
        {
            **frame.metrics,
            "security_anomalies": sum(
                r["signals"] >= 2 for g in ("ips", "domains") for r in result[g]
            ),
        }
        if frame.valid and data(frame)
        else frame.metrics
    )
    if frame.valid and data(frame):
        captured = deepcopy(data(frame))
        for group in ("ips", "domains"):
            for row in result[group]:
                captured[group][row["key"]].update(score=row["score"], deviation=row["deviation"])
        frame.details = {**frame.details, "security": captured}
    targets = {
        f"security:{group}:{r['key']}": r
        for group in ("ips", "domains")
        for r in result[group]
        if r["signals"] >= 2 and domain_spike(r["active"], r["reference"], settings)
    }
    states = db.scalars(
        select(AnomalyState).where(
            AnomalyState.service_id == frame.service_id, AnomalyState.subject.like("security:%")
        )
    ).all()
    subjects = set(targets) | {
        s.subject
        for s in states
        if s.bad or (s.incident_id and db.get(Incident, s.incident_id).status == "open")
    }
    for subject in subjects:
        row = targets.get(subject)
        state = next((s for s in states if s.subject == subject), None)
        if state and state.last_at >= frame.observed_at:
            continue
        existing = db.get(Incident, state.incident_id) if state and state.incident_id else None
        was_open = existing is not None and existing.status == "open"
        group, key = subject.split(":", 2)[1:]
        current = next((r for r in result[group] if r["key"] == key), None)
        ref = (row or current or {}).get("reference")
        if (
            existing
            and existing.status == "open"
            and existing.evidence.get("revision") == frame.revision
        ):
            ref = existing.evidence.get("reference")
        if existing and existing.status == "open" and ref and current:
            if domain_spike(current["active"], ref, settings) and current["sensitive"]:
                row = current
        if (
            not frame.valid
            or not data(frame)
            or (was_open and existing.evidence.get("revision") != frame.revision)
        ):
            ref = None
        evidence = dict(
            algorithm="snapshot-security-v1",
            revision=frame.revision,
            feature="active",
            value=(row or current or {}).get("active", 0),
            reference=ref,
            reasons=(row or current or {}).get("reasons", []),
            frame_id=frame.id,
            resources=frame.resources,
            alert_settings={**settings, "open_samples": max(3, settings["open_samples"])},
            note="Coincidencia observada; no confirma ataque ni causalidad.",
        )
        event = dict(
            at=frame.observed_at.isoformat(),
            active=evidence["value"],
            reasons=evidence["reasons"],
            degradation=result.get("degradation", []),
        )
        timeline = (
            existing.evidence.get("timeline", [])
            if was_open
            else [
                dict(
                    at=old.observed_at.isoformat(),
                    active=data(old).get(group, {}).get(key, {}).get("active", 0),
                    reasons=["Captura anterior a la confirmación"],
                )
                for old in rows[-5:]
                if old.valid
                and data(old)
                and frame.observed_at - old.observed_at <= timedelta(minutes=25)
            ]
        )
        evidence["timeline"] = (timeline + [event])[-288:]
        transition(db, frame, subject, "security", evidence["value"], ref, bool(row), evidence)
        if was_open and ref:
            existing.evidence = {**existing.evidence, "timeline": evidence["timeline"]}
