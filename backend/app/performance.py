"""Sampled latency: Req is a worker's reported duration, not an end-to-end timer."""

import math
from collections import Counter
from datetime import datetime, timedelta


def internal(worker):
    return worker.get("internal", False) or (
        worker.get("client") == "93.93.68.189"
        and worker.get("method") == "OPTIONS"
        and worker.get("path") == "*"
        and worker.get("request_protocol", "HTTP/1.0") == "HTTP/1.0"
    )


def stats(values):
    values = sorted(
        v for v in values if isinstance(v, (int, float)) and math.isfinite(v) and v >= 0
    )
    return {
        "req_count": len(values),
        "req_mean": sum(values) / len(values) if values else None,
        "req_max": max(values) if values else None,
        "req_p95": values[math.ceil(len(values) * 0.95) - 1] if len(values) >= 20 else None,
    }


def sample_metrics(workers, domains):
    states = Counter(w["state"] for w in workers)
    by_domain = {}
    active = []
    for w in workers:
        if (
            internal(w)
            or w["state"] not in {"R", "W"}
            or not w.get("method")
            or w.get("method", "").startswith("[")
            or w.get("request_kind") == "h2_session"
        ):
            continue
        value = w.get("request_ms")
        if value is not None:
            active.append(value)
            if w.get("domain"):
                by_domain.setdefault(w["domain"], []).append(value)
    for domain, counts in domains.items():
        counts.update(stats(by_domain.get(domain, [])))
    return {
        "performance_version": 1,
        "internal_workers": sum(internal(w) for w in workers),
        **{
            f"state_{ {'.': 'dot', '_': 'idle'}.get(s, s) }": states[s]
            for s in ["W", "R", "K", "C", "_", "."]
        },
        **{"active_" + k: v for k, v in stats(active).items()},
    }


def elevated(value, reference):
    return (
        value is not None
        and reference is not None
        and value
        > max(reference["median"] * 3, reference["median"] + 6 * 1.4826 * reference["mad"])
    )


def context(frame, history):
    from app.analysis import baseline

    evidence = {}
    for key in ("cpu", "load"):
        point = frame.resources.get(key)
        if not point or not point.get("source_at"):
            return {"apparently_available": False, "reason": "Falta CPU/carga fresca y comparable."}
        if (
            abs((frame.observed_at - datetime.fromisoformat(point["source_at"])).total_seconds())
            > 900
        ):
            return {"apparently_available": False, "reason": "CPU/carga sin frescura suficiente."}
        ref = baseline(
            [
                p.resources[key]["value"]
                for p in history
                if key in p.resources
                and p.resources[key].get("basis") == point.get("basis")
                and p.resources[key].get("source_at")
                and abs(
                    (
                        p.observed_at - datetime.fromisoformat(p.resources[key]["source_at"])
                    ).total_seconds()
                )
                <= 900
            ],
            minimum=12,
        )
        if ref is None:
            return {"apparently_available": False, "reason": "Aprendiendo CPU/carga."}
        evidence[key] = {"value": point["value"], "reference": ref}
    available = all(
        p["value"]
        <= max(
            p["reference"]["median"] * 1.5,
            p["reference"]["median"] + 3 * 1.4826 * p["reference"]["mad"],
        )
        for p in evidence.values()
    )
    for key in ("idle_workers", "free_slots"):
        ref = baseline(
            [p.metrics[key] for p in history if p.metrics.get(key) is not None], minimum=12
        )
        value = frame.metrics.get(key)
        available = (
            available
            and ref is not None
            and value is not None
            and value > 0
            and value >= ref["median"] * 0.5
        )
        evidence[key] = {"value": value, "reference": ref}
    return {
        "apparently_available": bool(available),
        "evidence": evidence,
        "reason": (
            "Latencia elevada con CPU/carga habituales y workers/slots disponibles. "
            if available
            else "Sin evidencia suficiente de disponibilidad de recursos. "
        )
        + "No descarta presión de RAM/swap ni esperas de aplicación.",
    }


def evaluate(db, frame, history, existing, settings):
    from app.analysis import baseline
    from app.incidents import transition

    history = [f for f in history if f.metrics.get("performance_version") == 1]
    targets = {
        "latency:server": frame.metrics.get("request_ms")
        if not frame.metrics.get("internal_workers")
        else None
    }
    targets.update(
        {
            "latency:domain:" + d: v.get("req_mean") if v.get("req_count", 0) >= 1 else None
            for d, v in frame.domains.items()
        }
    )
    targets.update(
        {
            s: targets.get(s)
            for s in existing
            if s.startswith("latency:") and existing[s].status == "open"
        }
    )
    assessed = 0
    correlation = context(frame, history) if frame.valid else {}
    for subject, value in targets.items():
        domain = (
            subject.removeprefix("latency:domain:")
            if subject.startswith("latency:domain:")
            else None
        )
        previous = existing.get(subject)
        features = ("req_mean", "req_max", "req_p95") if domain else ("request_ms",)
        if previous and previous.status == "open":
            features = (previous.evidence["feature"],)
        candidates = []
        for feature in features:
            current = frame.domains.get(domain, {}).get(feature) if domain else value
            values = [
                f.domains.get(domain, {}).get(feature)
                if domain
                else f.metrics.get(feature)
                if not f.metrics.get("internal_workers")
                else None
                for f in history
            ]
            ref = baseline([v for v in values if v is not None], minimum=24 if domain else 170)
            if ref and ref["median"] <= 0:
                ref = None
            if (
                previous
                and previous.status == "open"
                and previous.evidence.get("revision") == frame.revision
            ):
                ref = previous.evidence.get("reference")
            candidates.append(
                (
                    elevated(current, ref),
                    (current or 0) / max(0.000001, (ref or {}).get("median", 1)),
                    feature,
                    current,
                    ref,
                )
            )
        _, _, feature, value, reference = max(
            candidates, key=lambda x: (x[0], x[4] is not None, x[1])
        )
        if not frame.valid or value is None:
            reference = None
        assessed += int(reference is not None)
        evidence = {
            "algorithm": "latency-median-mad-v1",
            "revision": frame.revision,
            "feature": feature,
            "value": value,
            "reference": reference,
            "frame_id": frame.id,
            "resources": frame.resources,
            "performance_context": correlation,
            "alert_settings": settings,
            "note": "Req observado en workers R/W; no es latencia final ni identifica la causa. Las sondas internas se excluyen de los dominios."
            if domain
            else "Media global entre muestras; no puede separarse todo el tráfico interno de los contadores globales.",
        }
        transition(
            db,
            frame,
            subject,
            "performance",
            value,
            reference,
            elevated(value, reference),
            evidence,
        )
    frame.metrics = {**frame.metrics, "latency_evaluated": assessed > 0}


def monitor(start, end, frames, incidents, complete):
    from app.operational_summary import segment

    related = [i for i in incidents if i.kind == "performance"]
    opened = [i for i in related if i.status == "open"]
    by_service = {}
    for f in sorted(frames, key=lambda f: f.observed_at):
        by_service[f.service_id] = f
    latest = max(frames, key=lambda f: f.observed_at, default=None)
    fresh = (
        latest is not None
        and latest.valid
        and end - latest.observed_at <= timedelta(minutes=10)
        and complete
    )
    state = (
        "warning"
        if opened
        else "observed"
        if fresh and all(f.metrics.get("latency_evaluated") for f in by_service.values())
        else "learning"
        if fresh
        else "unknown"
    )
    value = latest.metrics.get("request_ms") if fresh else None
    bins = []
    for index in range(48):
        left = start + timedelta(minutes=index * 30)
        right = left + timedelta(minutes=30)
        samples = [
            f
            for f in frames
            if left <= f.observed_at < right and f.valid and f.metrics.get("latency_evaluated")
        ]
        covered = bool(by_service) and all(
            len({int(f.observed_at.timestamp()) // 300 for f in samples if f.service_id == sid})
            >= 5
            for sid in by_service
        )
        bins.append(
            segment(
                left,
                right,
                related,
                "complete" if covered else "partial" if samples else "missing",
                len(samples),
            )
        )
    return {
        "id": "latency",
        "name": "Latencia / tiempo de respuesta",
        "state": state,
        "status_text": {
            "warning": "Degradación observada",
            "observed": "Sin desviaciones detectadas",
            "learning": "Aprendiendo latencia",
            "unknown": "Sin evaluación reciente",
        }[state],
        "reason": "Se comparan ms/request global y Req medio por dominio con su propio histórico (24 h, excluyendo 30 min recientes). Se necesitan 170 intervalos globales o 24 con Req del dominio y una mediana positiva. Los avisos respetan las confirmaciones configuradas. Req no garantiza el tiempo de respuesta final. Las sondas internas se contabilizan aparte; no se usan intervalos globales con sondas observadas para alertar.",
        "value": value,
        "unit": "ms",
        "display_bytes": None,
        "value_label": "media global entre muestras",
        "latest_at": latest.observed_at if fresh else None,
        "context": [
            {
                "label": "Diagnóstico",
                "text": i.evidence.get("performance_context", {}).get(
                    "reason", "Degradación de latencia."
                ),
            }
            for i in opened[:3]
        ],
        "action": "latency",
        "bins": bins,
    }
