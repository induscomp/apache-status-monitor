from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ConnectorDescriptor:
    kind: str
    name: str
    description: str
    implemented: bool = False


@dataclass(frozen=True)
class CollectionResult:
    metrics: dict
    capabilities: tuple[str, ...]
    warnings: tuple[str, ...]


class Connector(Protocol):
    """Future implementations must receive the shared, DNS-pinned safe transport.

    No network collectors are registered or invoked in SMON-001.
    """

    def collect(self, configuration: dict, transport: object) -> CollectionResult: ...


CONNECTORS = {
    "apache_status": ConnectorDescriptor(
        "apache_status", "Apache Status", "Workers, dominios y actividad observada de Apache."
    ),
    "mrtg": ConnectorDescriptor(
        "mrtg", "MRTG", "Índice → enlaces de imágenes → estadísticas de las páginas de detalle."
    ),
}
