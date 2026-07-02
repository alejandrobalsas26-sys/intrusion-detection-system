"""EXPERIMENTAL webcam prototype — not a production security control.

Haar-cascade face/eye detection with naive blink counting. The blink gate is a
demo heuristic, not anti-spoofing: photos with cut-out eyes or video replays
defeat it, and Haar cascades misfire under poor lighting. Requires a webcam
and ``opencv-python`` (intentionally absent from requirements.txt). Run
manually with: python -m vision.engine
"""

import cv2

from logs.logger import get_logger
from vision.liveness import LivenessState

logger = get_logger("vision_engine")


def run_security_camera():
    logger.info("Starting vision engine (OpenCV Pure) with Liveness Detection...")
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        logger.critical("Failed to open camera.")
        return

    # Load OpenCV's built-in, pre-trained Haar Cascades
    face_cascade = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    )
    eye_cascade = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_eye_tree_eyeglasses.xml"
    )

    state = LivenessState()

    logger.info("Vision AI loaded. Press 'q' to exit.")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        # OpenCV Haar Cascades require grayscale images to process
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Detect faces in the frame
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.3, minNeighbors=5)

        status_text = "STATUS: SEARCHING FOR FACE"
        color = (0, 255, 255)  # Yellow

        for (x, y, w, h) in faces:
            # Draw a bounding box around the face
            cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 2)

            # Create a Region of Interest (ROI) for the eyes (eyes are inside the face)
            roi_gray = gray[y:y + h, x:x + w]
            roi_color = frame[y:y + h, x:x + w]

            # Detect eyes within the face ROI
            eyes = eye_cascade.detectMultiScale(roi_gray, scaleFactor=1.1, minNeighbors=3)

            # Liveness Logic (Blink Detection) — pure state machine in vision.liveness
            if len(eyes) >= 1:
                # Draw boxes around the eyes
                for (ex, ey, ew, eh) in eyes:
                    cv2.rectangle(roi_color, (ex, ey), (ex + ew, ey + eh), (0, 255, 0), 2)
            state.observe(len(eyes) >= 1)

            if state.is_live:
                status_text = "STATUS: HUMAN DETECTED (LIVE)"
                color = (0, 255, 0)  # Green
            else:
                status_text = "STATUS: ALERT - WAITING FOR BLINK"
                color = (0, 0, 255)  # Red

        # Render UI
        cv2.putText(frame, status_text, (20, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.8, color, 2)
        cv2.putText(
            frame,
            f"Blinks: {state.blink_count}",
            (20, 80),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (255, 255, 255),
            2,
        )

        cv2.imshow("Antigravity-IDS: Facial Detection (OpenCV Pure)", frame)

        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    run_security_camera()
