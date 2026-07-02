"""Pure liveness state-machine tests — no camera, no OpenCV import."""

import unittest

from vision.liveness import LivenessState


class LivenessStateTestCase(unittest.TestCase):
    def test_initial_state_is_not_live(self):
        state = LivenessState()
        self.assertEqual(state.blink_count, 0)
        self.assertFalse(state.is_live)

    def test_open_then_closed_counts_one_blink(self):
        state = LivenessState()
        state.observe(True)
        state.observe(False)
        self.assertEqual(state.blink_count, 1)
        self.assertTrue(state.is_live)

    def test_eyes_never_seen_is_never_live(self):
        state = LivenessState()
        for _ in range(10):
            state.observe(False)
        self.assertEqual(state.blink_count, 0)
        self.assertFalse(state.is_live)

    def test_eyes_always_open_is_never_live(self):
        # A printed photo with visible eyes must not pass the blink gate.
        state = LivenessState()
        for _ in range(10):
            state.observe(True)
        self.assertEqual(state.blink_count, 0)
        self.assertFalse(state.is_live)

    def test_multiple_blinks_accumulate(self):
        state = LivenessState()
        for _ in range(3):
            state.observe(True)
            state.observe(False)
        self.assertEqual(state.blink_count, 3)
        self.assertTrue(state.is_live)

    def test_consecutive_closed_frames_count_a_single_blink(self):
        state = LivenessState()
        state.observe(True)
        state.observe(False)
        state.observe(False)
        self.assertEqual(state.blink_count, 1)


if __name__ == "__main__":
    unittest.main()
