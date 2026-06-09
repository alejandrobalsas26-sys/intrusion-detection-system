from dataclasses import dataclass, field
from typing import Any, Dict  # noqa: F401, UP035


@dataclass
class DetectionEvent:
    level: str
    module_source: str
    detector_name: str
    message: str
    timestamp: float
    context: dict[str, Any] = field(default_factory=dict)
