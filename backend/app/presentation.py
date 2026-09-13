"""Display memory units without changing the detector's historical numeric basis."""

import math
import re

from app.config import get_settings
from app.connectors.mrtg import parse_detail
from app.models import MrtgObservation


class ResourcePresentation:
    def __init__(self, db):
        self.db = db
        self.scales = {}

    def resources(self, resources):
        return {key: self.point(key, point) for key, point in resources.items()}

    def point(self, key, point):
        if key not in {"ram_free", "swap_free"}:
            return point
        unit = point.get("unit", "")
        known = {
            "bytes": 1,
            "B": 1,
            "kB": 1000,
            "KB": 1000,
            "KiB": 1024,
            "MB": 1e6,
            "MiB": 1024**2,
            "GB": 1e9,
            "GiB": 1024**3,
        }
        factor = known.get(unit)
        note = "Unidad configurada para esta métrica."
        if factor is None:
            basis = point.get("basis", point.get("sample_id"))
            if basis not in self.scales:
                self.scales[basis] = self.infer(point)
            factor = self.scales[basis]
            note = "Escala de la tabla pública MRTG; no mide la capacidad total del servidor."
        if factor is None:
            return {
                **point,
                "display_note": "Unidad pendiente de confirmar en la configuración MRTG.",
            }
        return {
            **point,
            "display_bytes": point["value"] * factor,
            "display_factor": factor,
            "display_note": note,
        }

    def infer(self, point):
        sample_id = point.get("sample_id")
        sample = self.db.get(MrtgObservation, sample_id) if sample_id else None
        if not sample:
            return None
        points = sample.values
        if not any("display_value" in p for p in points) and sample.raw_encrypted:
            try:
                points = parse_detail(
                    get_settings().cipher().decrypt(sample.raw_encrypted.encode()).decode()
                )["values"]
            except Exception:
                return None
        parts = point.get("basis", "").split(":")
        channel = parts[2] if len(parts) > 2 else None
        for p in points:
            if p.get("channel") != channel or p.get("window") != "d":
                continue
            visible = p.get("display_value")
            suffix = p.get("display_unit", "")
            if p.get("source") == "table" and "normalized_value" not in p:
                suffix = p.get("source_unit") or ""
                # correlate() already applies the visible SI prefix to table rows.
                if re.fullmatch(r"[kMGT]?(?:bytes|B)?", suffix) and suffix:
                    return 1
            match = re.fullmatch(r"([kMGT]?)(?:bytes|B)?", suffix)
            if visible is None or not match or not suffix or not p["value"]:
                continue
            scaled = visible * {"": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[match[1]]
            ratio = scaled / p["value"]
            # Allow display rounding only; never manufacture an arbitrary conversion.
            for candidate in (1, 1000, 1024, 1e6, 1024**2):
                if math.isclose(ratio, candidate, rel_tol=0.01):
                    return candidate
        return None
