from dataclasses import dataclass, field
from typing import Dict, Any

@dataclass
class DetectionEvent:
    level: str
    module_source: str
    detector_name: str
    message: str
    timestamp: float
    context: Dict[str, Any] = field(default_factory=dict)
    