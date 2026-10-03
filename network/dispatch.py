"""Shared structured audit envelope for live capture and offline replay."""

import socket


def log_detection(event, logger) -> None:
    context = dict(event.context or {})
    context.update(detector_name=event.detector_name, timestamp=event.timestamp)
    context.setdefault("host_id", socket.gethostname())
    log_func = getattr(logger, event.level.lower(), logger.info)
    log_func(
        f"DetectionEvent: {event.level} from {event.detector_name} - {event.message}",
        extra={"context": context},
    )
