from datetime import timedelta

from sqlalchemy import select, update

from app.analysis import baseline, domain_spike, resource_spike
from app.evidence import domain_evidence
from app.models import AnomalyState, EmailDelivery, Incident, Server, ServerFrame, now


def enqueue(db, incident, transition, at):
    from app.notifications import configuration

    if not configuration(db).get("enabled") or at < now() - timedelta(minutes=15):
        return
    query = select(EmailDelivery).where(
        EmailDelivery.incident_id == incident.id, EmailDelivery.created_at > at - timedelta(hours=1)
    )
    if transition != "reminder":
        query = query.where(EmailDelivery.transition == transition)
    recent = db.scalar(query.limit(1))
    if not recent:
        db.add(EmailDelivery(incident_id=incident.id, transition=transition, created_at=at))


def memory_severity(resources):
    swap = resources.get("swap_free", {})
    total, free = swap.get("capacity"), swap.get("value")
    if total is None or free is None or not 0 <= free <= total:
        return "warning", "unknown"
    return ("critical", "used") if free < total else ("warning", "unused")


def transition(db, frame, subject, kind, value, reference, bad, evidence):
    state = db.scalar(
        select(AnomalyState)
        .where(AnomalyState.service_id == frame.service_id, AnomalyState.subject == subject)
        .with_for_update()
    )
    if state and state.last_at >= frame.observed_at:
        return
    if state is None:
        state = AnomalyState(
            service_id=frame.service_id, subject=subject, last_at=frame.observed_at, bad=0, good=0
        )
        db.add(state)
    if frame.observed_at - state.last_at > timedelta(minutes=10):
        state.bad = state.good = 0
    state.last_at = frame.observed_at
    if reference is None:
        state.bad = state.good = 0
        return
    state.bad = state.bad + 1 if bad else 0
    state.good = 0 if bad else state.good + 1
    incident = db.get(Incident, state.incident_id) if state.incident_id else None
    severity = (
        "critical"
        if kind == "resources" or value >= max(1, reference["median"]) * 10
        else "warning"
    )
    if kind == "performance":
        severity = "warning"
    memory = kind == "resources" and subject in {"resource:ram_free", "resource:swap_free"}
    if memory:
        severity, swap_state = memory_severity(evidence.get("resources", {}))
        evidence = {**evidence, "severity_policy": "memory-swap-v1", "swap_state": swap_state}
        # Missing data cannot clear an already confirmed red condition.
        if (
            swap_state == "unknown"
            and incident
            and incident.status == "open"
            and incident.evidence.get("severity_policy") == "memory-swap-v1"
            and incident.severity == "critical"
        ):
            severity = "critical"
            if not bad:
                state.good = 0
                return
    settings = evidence.get("alert_settings", {})
    if bad and state.bad >= settings.get("open_samples", 2):
        if not incident or incident.status == "resolved":
            incident = Incident(
                server_id=frame.server_id,
                service_id=frame.service_id,
                subject=subject,
                kind=kind,
                status="open",
                severity=severity,
                opened_at=frame.observed_at,
                updated_at=frame.observed_at,
                evidence=evidence,
            )
            db.add(incident)
            db.flush()
            state.incident_id = incident.id
            enqueue(db, incident, "opened", frame.observed_at)
        else:
            old_severity = incident.severity
            # Preserve the opening baseline; adapting it to an ongoing anomaly could hide it.
            anchor = incident.evidence.get("reference", reference)
            feature = incident.evidence.get("feature")
            incident.evidence = {
                **evidence,
                "reference": anchor,
                "feature": feature or evidence.get("feature"),
            }
            incident.updated_at = frame.observed_at
            if memory or severity == "critical":
                incident.severity = severity
            enqueue(
                db,
                incident,
                "escalated"
                if incident.severity == "critical" and old_severity != "critical"
                else "reminder",
                frame.observed_at,
            )
    elif (
        incident and incident.status == "open" and state.good >= settings.get("recovery_samples", 3)
    ):
        incident.status = "resolved"
        incident.resolved_at = frame.observed_at
        incident.updated_at = frame.observed_at
        enqueue(db, incident, "resolved", frame.observed_at)


def evaluate(db, frame):
    from app.alert_settings import settings_for

    server = db.scalar(select(Server).where(Server.id == frame.server_id).with_for_update())
    settings = settings_for(server)
    policy_revision = (server.alert_settings or {}).get("revision", 0)
    if not frame.valid:
        db.execute(
            update(AnomalyState)
            .where(
                AnomalyState.service_id == frame.service_id,
                AnomalyState.last_at < frame.observed_at,
                AnomalyState.subject.like("domain:%"),
            )
            .values(bad=0, good=0, last_at=frame.observed_at)
        )
        # Continue evaluating independent MRTG evidence even if Apache failed.
    rows = db.scalars(
        select(ServerFrame)
        .where(
            ServerFrame.service_id == frame.service_id,
            ServerFrame.revision == frame.revision,
            ServerFrame.observed_at >= frame.observed_at - timedelta(hours=24),
            ServerFrame.observed_at <= frame.observed_at - timedelta(minutes=30),
        )
        .order_by(ServerFrame.observed_at)
        .limit(600)
    ).all()
    buckets = {int(r.observed_at.timestamp()) // 300: r for r in rows}
    resource_history = list(buckets.values())
    history = [r for r in resource_history if r.valid]
    states = db.scalars(
        select(AnomalyState).where(AnomalyState.service_id == frame.service_id)
    ).all()
    open_incidents = {s.subject: db.get(Incident, s.incident_id) for s in states if s.incident_id}
    domains = set(frame.domains) | {
        s.subject[7:]
        for s in states
        if s.subject.startswith("domain:")
        and (s.bad or (s.subject in open_incidents and open_incidents[s.subject].status == "open"))
    }
    for domain in domains if frame.valid else ():
        subject = "domain:" + domain
        existing = open_incidents.get(subject)
        candidates = []
        for feature in ("active", "appearances"):
            reference = baseline([r.domains.get(domain, {}).get(feature, 0) for r in history])
            value = frame.domains.get(domain, {}).get(feature, 0)
            if (
                existing
                and existing.status == "open"
                and existing.evidence.get("feature") == feature
                and existing.evidence.get("revision") == frame.revision
            ):
                reference = existing.evidence["reference"]
            candidates.append((domain_spike(value, reference, settings), feature, value, reference))
        bad, feature, value, reference = max(
            candidates,
            key=lambda item: (item[0], item[2] / max(1, (item[3] or {}).get("median", 1))),
        )
        if existing and existing.status == "open":
            feature = existing.evidence["feature"]
            value = frame.domains.get(domain, {}).get(feature, 0)
            reference = (
                existing.evidence["reference"]
                if existing.evidence.get("revision") == frame.revision
                else None
            )
            bad = domain_spike(value, reference, settings)
        evidence = {
            "algorithm": "median-mad-v1",
            "alert_settings": settings,
            "alert_settings_revision": policy_revision,
            "revision": frame.revision,
            "feature": feature,
            "value": value,
            "reference": reference,
            "frame_id": frame.id,
            "resources": frame.resources,
            "coincidences": domain_evidence(db, frame, domain) if bad else {},
            "note": "Actividad observada; no tráfico total ni causalidad demostrada.",
        }
        transition(db, frame, subject, "domain", value, reference, bad, evidence)
    from app.performance import evaluate as evaluate_performance

    evaluate_performance(db, frame, history, open_incidents, settings)
    previous = db.scalar(
        select(ServerFrame)
        .where(
            ServerFrame.service_id == frame.service_id, ServerFrame.observed_at < frame.observed_at
        )
        .order_by(ServerFrame.observed_at.desc())
        .limit(1)
    )
    for role in ("ram_free", "swap_free", "load", "cpu"):
        point = frame.resources.get(role)
        if point is None:
            transition(db, frame, "resource:" + role, "resources", 0, None, False, {})
            continue
        if (
            previous
            and point.get("source_key")
            and previous.resources.get(role, {}).get("source_key") == point["source_key"]
        ):
            continue  # Reusing the same MRTG update is not independent confirmation.
        reference = baseline(
            [
                r.resources[role]["value"]
                for r in resource_history
                if role in r.resources and r.resources[role]["basis"] == point["basis"]
            ],
            minimum=12,
        )
        subject = "resource:" + role
        existing = open_incidents.get(subject)
        if existing and existing.status == "open":
            reference = (
                existing.evidence["reference"]
                if existing.evidence.get("basis") == point["basis"]
                else None
            )
        if (
            role == "swap_free"
            and point.get("capacity") is not None
            and memory_severity(frame.resources)[1] == "unknown"
        ):
            transition(db, frame, subject, "resources", 0, None, False, {})
            continue
        value = point["value"]
        evidence = {
            "algorithm": "median-mad-v1",
            "alert_settings": settings,
            "alert_settings_revision": policy_revision,
            "revision": frame.revision,
            "feature": role,
            "value": value,
            "reference": reference,
            "basis": point["basis"],
            "frame_id": frame.id,
            "resources": frame.resources,
            "domains": sorted(
                [dict(domain=d, **v) for d, v in frame.domains.items()],
                key=lambda d: d["active"],
                reverse=True,
            )[:15],
            "coincidences": frame.details or {},
            "note": "Coincidencia temporal; no demuestra qué dominio causó la presión ni confirma errores HTTP 500.",
        }
        transition(
            db,
            frame,
            subject,
            "resources",
            value,
            reference,
            (
                memory_severity(frame.resources)[1] == "used"
                if role == "swap_free" and point.get("capacity") is not None
                else resource_spike(value, reference, role, settings)
            ),
            evidence,
        )
