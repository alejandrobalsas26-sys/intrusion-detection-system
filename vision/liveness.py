"""Pure blink-based liveness state logic (no OpenCV dependency).

Extracted from the experimental camera prototype so the decision logic is
unit-testable without a webcam. A naive blink counter is NOT robust
anti-spoofing: a photo with cut-out eyes or a video replay defeats it. Treat
any "live" verdict from this heuristic as a demo signal, not a security
control.
"""

from dataclasses import dataclass


@dataclass
class LivenessState:
    """Frame-by-frame blink tracker: a blink is an open -> closed transition."""

    blink_count: int = 0
    eyes_were_open: bool = False
    is_live: bool = False

    def observe(self, eyes_visible: bool) -> None:
        """Feeds one frame observation (were eyes detected in this frame?)."""
        if eyes_visible:
            self.eyes_were_open = True
        elif self.eyes_were_open:
            self.blink_count += 1
            self.eyes_were_open = False
            self.is_live = True
