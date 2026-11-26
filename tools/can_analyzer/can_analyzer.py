
import time
from collections import Counter
from typing import Sequence

import can

from tools.anomaly_detector.anomaly_detector import detect_frequency_anomaly
from tools.anomaly_detector.replay_detector import detect_replay_attack
from models.security_event import SecurityEvent


def capture_can_messages(window_seconds=5, channel="vcan0"):
    bus = can.interface.Bus(
        channel=channel,
        interface="socketcan"
    )

    print(f"Listening on {channel} for {window_seconds} seconds...")

    messages = []
    start_time = time.time()

    try:
        while time.time() - start_time < window_seconds:
            message = bus.recv(timeout=1)

            if message is not None:
                messages.append(message)

    finally:
        bus.shutdown()

    return messages


def analyze_can_messages(
    messages: Sequence[can.Message],
    window_seconds=5,
    threshold=100,
    channel="vcan0",
) -> list[SecurityEvent]:
    counts = Counter(
        hex(message.arbitration_id)
        for message in messages
    )

    detections = []

    # 1. Détection des anomalies de fréquence
    print("\n=== CAN TRAFFIC ===")

    for can_id, count in counts.items():
        print(f"{can_id} -> {count} messages")

        detection = detect_frequency_anomaly(
            can_id=can_id,
            count=count,
            window_seconds=window_seconds,
            threshold=threshold
        )
        detection.channel = channel

        print("Frequency detection:", detection)
        detections.append(detection)

    # 2. Détection des répétitions suspectes (Replay Detector)
    print("\n=== REPLAY DETECTION ===")

    replay_event = detect_replay_attack(
        messages=messages,
        channel=channel
    )

    if replay_event is not None:
        print("Replay suspicion detected!")
        print(f"CAN ID: {replay_event.can_id}")
        print(f"Attack type: {replay_event.attack_type}")
        print(f"Repeated frames: {replay_event.message_count}")

        for evidence in replay_event.evidence:
            print(f"  - {evidence}")

        detections.append(replay_event)

    else:
        print("No suspicious consecutive frame repetition detected.")

    for detection in detections:
        detection.metadata["data_provenance"] = (
            "LIVE_CAPTURE" if channel == "vcan0" else "SYNTHETIC_TEST_FIXTURE"
        )

    return detections


def analyze_can_traffic(window_seconds=5, threshold=100):
    messages = capture_can_messages(window_seconds=window_seconds)
    return analyze_can_messages(
        messages,
        window_seconds=window_seconds,
        threshold=threshold,
        channel="vcan0",
    )