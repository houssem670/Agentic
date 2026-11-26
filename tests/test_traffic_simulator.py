"""Tests du simulateur de trafic CAN synthétique."""

import tempfile
import unittest
from pathlib import Path

from tools.traffic_simulator.simulator import (
    ATTACK_LABELS,
    NORMAL_PERIODS,
    TrafficSimulator,
)


class TestTrafficSimulator(unittest.TestCase):
    def test_same_seed_generates_identical_records(self):
        first = TrafficSimulator(duration=2.0, seed=17).generate()
        second = TrafficSimulator(duration=2.0, seed=17).generate()

        self.assertEqual(first, second)

    def test_csv_round_trip_preserves_records(self):
        simulator = TrafficSimulator(duration=2.0, seed=23)
        records = simulator.generate()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traffic.csv"
            simulator.save_csv(path)
            self.assertEqual(TrafficSimulator.load_csv(path), records)

    def test_requested_attacks_have_their_labels(self):
        records = TrafficSimulator(duration=2.0, seed=5).generate(ATTACK_LABELS)

        self.assertEqual(
            {record.label for record in records}.difference({"normal"}),
            set(ATTACK_LABELS),
        )

    def test_records_are_sorted_by_timestamp(self):
        records = TrafficSimulator(duration=2.0, seed=11).generate()

        self.assertEqual(
            [record.timestamp for record in records],
            sorted(record.timestamp for record in records),
        )

    def test_normal_frames_approximately_follow_configured_periods(self):
        records = TrafficSimulator(duration=5.0, seed=31).generate(attacks=())

        for can_id, period in NORMAL_PERIODS.items():
            timestamps = [
                record.timestamp
                for record in records
                if record.can_id == can_id and record.label == "normal"
            ]
            intervals = [
                later - earlier
                for earlier, later in zip(timestamps, timestamps[1:])
            ]
            self.assertTrue(intervals, f"Aucune période mesurable pour {can_id:#x}")
            for interval in intervals:
                self.assertAlmostEqual(interval, period, delta=period * 0.1)


if __name__ == "__main__":
    unittest.main()
