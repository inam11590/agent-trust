"""Discovery connectors registry and factory (Step 29)."""

from typing import Any, Dict, Optional, Type

from app.models.discovery import DiscoverySourceType
from app.services.discovery.connectors.base import BaseDiscoveryConnector, DiscoveredResource
from app.services.discovery.connectors.cicd import CicdDiscoveryConnector
from app.services.discovery.connectors.cloud import CloudDiscoveryConnector
from app.services.discovery.connectors.container import ContainerPlatformDiscoveryConnector
from app.services.discovery.connectors.import_feed import ImportDiscoveryConnector
from app.services.discovery.connectors.kubernetes import KubernetesDiscoveryConnector
from app.services.discovery.connectors.repository import SourceRepositoryDiscoveryConnector
from app.services.discovery.connectors.telemetry import TelemetryDiscoveryConnector


CONNECTOR_REGISTRY: Dict[str, Type[BaseDiscoveryConnector]] = {
    DiscoverySourceType.KUBERNETES.value: KubernetesDiscoveryConnector,
    DiscoverySourceType.CONTAINER_PLATFORM.value: ContainerPlatformDiscoveryConnector,
    DiscoverySourceType.CLOUD.value: CloudDiscoveryConnector,
    DiscoverySourceType.CI_CD.value: CicdDiscoveryConnector,
    DiscoverySourceType.SOURCE_REPOSITORY.value: SourceRepositoryDiscoveryConnector,
    DiscoverySourceType.GATEWAY_TELEMETRY.value: TelemetryDiscoveryConnector,
    DiscoverySourceType.SIDECAR_TELEMETRY.value: TelemetryDiscoveryConnector,
    DiscoverySourceType.RUNTIME_SIGNAL.value: TelemetryDiscoveryConnector,
    DiscoverySourceType.IMPORT.value: ImportDiscoveryConnector,
}


def get_connector(
    source_type: str,
    configuration: Dict[str, Any],
    credential_value: Optional[str] = None,
) -> BaseDiscoveryConnector:
    """Instantiate the appropriate connector for the given source type."""
    cls = CONNECTOR_REGISTRY.get(source_type)
    if not cls:
        raise ValueError(f"Unsupported discovery source type: {source_type}")
    return cls(configuration=configuration, credential_value=credential_value)


__all__ = [
    "BaseDiscoveryConnector",
    "DiscoveredResource",
    "KubernetesDiscoveryConnector",
    "ContainerPlatformDiscoveryConnector",
    "CloudDiscoveryConnector",
    "CicdDiscoveryConnector",
    "SourceRepositoryDiscoveryConnector",
    "TelemetryDiscoveryConnector",
    "ImportDiscoveryConnector",
    "get_connector",
]
