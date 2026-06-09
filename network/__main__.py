import time

from dotenv import load_dotenv

load_dotenv()

from network.sensor import start_sensor  # noqa: E402


def main():
    print("[*] Starting Antigravity-IDS network sensor. Press Ctrl+C to stop.")
    thread = start_sensor()
    if thread is None:
        print("[-] Sensor failed to start. Check NETWORK_MONITOR_CONSENT and privileges.")
        return
    try:
        while thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Sensor stopped by user.")


if __name__ == "__main__":
    main()
