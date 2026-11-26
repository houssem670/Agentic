"""Génération hors ligne et émission en direct de trafic CAN synthétique."""

from __future__ import annotations

import argparse
import csv
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping


NORMAL_PERIODS: dict[int, float] = {
    0x100: 0.010,
    0x200: 0.020,
    0x300: 0.050,
    0x400: 0.100,
    0x500: 0.200,
    0x600: 0.500,
}
ATTACK_LABELS = ("flooding", "replay", "spoofing", "fuzzing")
_LABELS = frozenset(("normal", *ATTACK_LABELS))
_CSV_FIELDS = ("timestamp", "can_id", "dlc", "data", "label")


@dataclass(frozen=True)
class CanRecord:
    """Une trame CAN accompagnée de son étiquette et de son temps simulé."""

    timestamp: float
    can_id: int
    dlc: int
    data: bytes
    label: str


class TrafficSimulator:
    """Construit un trafic CAN déterministe avec des fenêtres d'attaque."""

    def __init__(
        self,
        duration: float = 10.0,
        seed: int | None = None,
        attack_windows: Mapping[str, tuple[float, float]] | None = None,
    ) -> None:
        if duration <= 0:
            raise ValueError("La durée doit être strictement positive.")
        self.duration = duration
        self.seed = seed
        self.attack_windows = dict(attack_windows or {})
        self.records: list[CanRecord] = []

    def generate(
        self, attacks: Iterable[str] = ATTACK_LABELS
    ) -> list[CanRecord]:
        """Génère les trames en mémoire, sans attente ni interface CAN."""
        selected = set(attacks)
        unknown = selected.difference(ATTACK_LABELS)
        if unknown:
            raise ValueError(f"Attaques inconnues : {', '.join(sorted(unknown))}")

        rng = random.Random(self.seed)
        records = self._normal_traffic(rng)
        normal_records = list(records)
        windows = self._windows(selected)

        for attack in ATTACK_LABELS:
            if attack not in selected:
                continue
            start, end = windows[attack]
            if attack == "flooding":
                records.extend(self._flooding(start, end))
            elif attack == "replay":
                records.extend(self._replay(start, end, normal_records))
            elif attack == "spoofing":
                records.extend(self._spoofing(start, end))
            else:
                records.extend(self._fuzzing(start, end, rng))

        self.records = sorted(records, key=lambda record: record.timestamp)
        return list(self.records)

    def save_csv(self, path: str | Path) -> None:
        """Enregistre le trafic courant dans un CSV lisible."""
        with Path(path).open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=_CSV_FIELDS)
            writer.writeheader()
            for record in self.records:
                writer.writerow(
                    {
                        "timestamp": repr(record.timestamp),
                        "can_id": record.can_id,
                        "dlc": record.dlc,
                        "data": record.data.hex(),
                        "label": record.label,
                    }
                )

    @staticmethod
    def load_csv(path: str | Path) -> list[CanRecord]:
        """Relit un CSV créé par le simulateur."""
        records: list[CanRecord] = []
        with Path(path).open(newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            if reader.fieldnames != list(_CSV_FIELDS):
                raise ValueError("En-tête CSV invalide.")
            for row in reader:
                data = bytes.fromhex(row["data"])
                record = CanRecord(
                    timestamp=float(row["timestamp"]),
                    can_id=int(row["can_id"]),
                    dlc=int(row["dlc"]),
                    data=data,
                    label=row["label"],
                )
                if record.dlc != len(record.data) or record.label not in _LABELS:
                    raise ValueError("Enregistrement CAN invalide dans le CSV.")
                records.append(record)
        return records

    def send_live(self, attacks: Iterable[str] = ATTACK_LABELS) -> None:
        """Émet le trafic sur vcan0 au rythme du temps réel."""
        records = self.generate(attacks)
        try:
            import can
        except ImportError as exc:
            raise RuntimeError("Le mode live nécessite le paquet python-can.") from exc

        try:
            bus = can.Bus(interface="socketcan", channel="vcan0")
        except (can.CanError, OSError) as exc:
            raise RuntimeError(
                "Impossible d'ouvrir vcan0. Vérifiez que l'interface SocketCAN "
                "existe et que python-can peut y accéder."
            ) from exc

        started = time.monotonic()
        try:
            for record in records:
                remaining = record.timestamp - (time.monotonic() - started)
                if remaining > 0:
                    time.sleep(remaining)
                message = can.Message(
                    arbitration_id=record.can_id,
                    data=record.data,
                    is_extended_id=False,
                )
                try:
                    bus.send(message)
                except (can.CanError, OSError) as exc:
                    raise RuntimeError("Échec d'envoi d'une trame sur vcan0.") from exc
        finally:
            bus.shutdown()

    def _normal_traffic(self, rng: random.Random) -> list[CanRecord]:
        records: list[CanRecord] = []
        for can_id, period in NORMAL_PERIODS.items():
            counter = 0
            signal_value = 100
            index = 0
            while True:
                timestamp = (
                    0.0
                    if index == 0
                    else index * period + rng.gauss(0.0, period * 0.02)
                )
                if timestamp >= self.duration:
                    break
                if timestamp >= 0:
                    signal_value = min(200, max(0, signal_value + rng.randint(-2, 2)))
                    data = bytes((counter, signal_value)) + bytes((can_id & 0xFF,)) * 6
                    records.append(CanRecord(timestamp, can_id, 8, data, "normal"))
                    counter = (counter + 1) % 16
                index += 1
        return records

    def _windows(self, attacks: set[str]) -> dict[str, tuple[float, float]]:
        count = len(ATTACK_LABELS)
        windows = {
            attack: (self.duration * index / count, self.duration * (index + 1) / count)
            for index, attack in enumerate(ATTACK_LABELS)
        }
        for attack, window in self.attack_windows.items():
            if attack not in ATTACK_LABELS:
                raise ValueError(f"Fenêtre définie pour une attaque inconnue : {attack}")
            start, end = window
            if start < 0 or end < start or end > self.duration:
                raise ValueError(f"Fenêtre invalide pour l'attaque {attack}.")
            windows[attack] = window
        return {attack: windows[attack] for attack in attacks}

    @staticmethod
    def _flooding(start: float, end: float) -> list[CanRecord]:
        return [
            CanRecord(timestamp, 0x000, 8, b"\x00" * 8, "flooding")
            for timestamp in _timestamps(start, end, 0.001)
        ]

    @staticmethod
    def _replay(
        start: float, end: float, normal_records: list[CanRecord]
    ) -> list[CanRecord]:
        sequence = normal_records[:3]
        result: list[CanRecord] = []
        for index, timestamp in enumerate(_timestamps(start, end, 0.001)):
            original = sequence[index % len(sequence)]
            result.append(
                CanRecord(timestamp, original.can_id, original.dlc, original.data, "replay")
            )
        return result

    @staticmethod
    def _spoofing(start: float, end: float) -> list[CanRecord]:
        data = bytes((0, 255)) + bytes((0x300 & 0xFF,)) * 6
        return [
            CanRecord(timestamp, 0x300, 8, data, "spoofing")
            for timestamp in _timestamps(start, end, 0.005)
        ]

    @staticmethod
    def _fuzzing(
        start: float, end: float, rng: random.Random
    ) -> list[CanRecord]:
        records: list[CanRecord] = []
        for timestamp in _timestamps(start, end, 0.002):
            can_id = rng.randint(0, 0x7FF)
            data = bytes(rng.randrange(256) for _ in range(8))
            records.append(CanRecord(timestamp, can_id, 8, data, "fuzzing"))
        return records


def _timestamps(start: float, end: float, period: float) -> Iterable[float]:
    index = 0
    while True:
        timestamp = start + index * period
        if timestamp >= end:
            return
        yield timestamp
        index += 1


def main() -> None:
    """Lance le simulateur depuis la ligne de commande."""
    parser = argparse.ArgumentParser(description="Simulateur de trafic CAN")
    parser.add_argument("--mode", choices=("offline", "live"), default="offline")
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, default=Path("can_traffic.csv"))
    parser.add_argument("--attacks", default=",".join(ATTACK_LABELS))
    args = parser.parse_args()

    attacks = tuple(filter(None, (item.strip() for item in args.attacks.split(","))))
    unknown = set(attacks).difference(ATTACK_LABELS)
    if unknown:
        parser.error(f"attaques inconnues : {', '.join(sorted(unknown))}")

    simulator = TrafficSimulator(duration=args.duration, seed=args.seed)
    if args.mode == "live":
        try:
            simulator.send_live(attacks)
        except RuntimeError as exc:
            parser.error(str(exc))
    else:
        try:
            records = simulator.generate(attacks)
        except ValueError as exc:
            parser.error(str(exc))
        simulator.save_csv(args.output)
        print(f"{len(records)} trames enregistrées dans {args.output}.")


if __name__ == "__main__":
    main()
