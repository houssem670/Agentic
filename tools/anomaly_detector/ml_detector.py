"""Détection non supervisée d'anomalies dans le trafic CAN."""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Sequence

from sklearn.ensemble import IsolationForest

from tools.traffic_simulator.simulator import CanRecord


_DATA_BYTE_COUNT = 8
FEATURE_NAMES = (
    "frame_count",
    "interval_mean",
    "interval_std",
    "distinct_payloads",
    "payload_entropy",
    *(f"byte_{index}_mean" for index in range(_DATA_BYTE_COUNT)),
    *(f"byte_{index}_std" for index in range(_DATA_BYTE_COUNT)),
)


@dataclass(frozen=True)
class WindowFeatures:
    """Vecteur descriptif d'un CAN ID dans une fenêtre."""

    window_index: int
    can_id: int
    values: tuple[float, ...]


@dataclass(frozen=True)
class WindowPrediction:
    """Prédiction et score regroupés par fenêtre temporelle."""

    window_index: int
    start: float
    end: float
    is_anomaly: bool
    anomaly_score: float
    anomalous_can_ids: tuple[int, ...]


def extract_features(
    records: Sequence[CanRecord], window_seconds: float = 1.0
) -> list[WindowFeatures]:
    """Calcule les caractéristiques de chaque ID et fenêtre."""
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("La fenêtre doit être finie et strictement positive.")

    grouped: dict[tuple[int, int], list[CanRecord]] = defaultdict(list)
    for record in records:
        if not math.isfinite(record.timestamp) or record.timestamp < 0:
            raise ValueError("Les timestamps doivent être finis et positifs ou nuls.")
        window_index = int(record.timestamp // window_seconds)
        grouped[(window_index, record.can_id)].append(record)

    features: list[WindowFeatures] = []
    for (window_index, can_id), frames in sorted(grouped.items()):
        frames.sort(key=lambda frame: frame.timestamp)
        intervals = [
            later.timestamp - earlier.timestamp
            for earlier, later in zip(frames, frames[1:])
        ]
        payload_counts = Counter(
            byte for frame in frames for byte in frame.data[:_DATA_BYTE_COUNT]
        )
        payload_size = sum(payload_counts.values())
        entropy = (
            -sum(
                (count / payload_size) * math.log2(count / payload_size)
                for count in payload_counts.values()
            )
            if payload_size
            else 0.0
        )

        values = [
            float(len(frames)),
            statistics.fmean(intervals) if intervals else 0.0,
            statistics.pstdev(intervals) if len(intervals) > 1 else 0.0,
            float(len({frame.data for frame in frames})),
            entropy,
        ]
        byte_values = [
            [frame.data[index] for frame in frames if len(frame.data) > index]
            for index in range(_DATA_BYTE_COUNT)
        ]
        values.extend(statistics.fmean(items) if items else 0.0 for items in byte_values)
        values.extend(
            statistics.pstdev(items) if len(items) > 1 else 0.0
            for items in byte_values
        )
        features.append(
            WindowFeatures(window_index, can_id, tuple(float(value) for value in values))
        )
    return features


class MLAnomalyDetector:
    """Apprend un modèle IsolationForest normal distinct pour chaque CAN ID."""

    def __init__(
        self,
        window_seconds: float = 1.0,
        contamination: str | float = 0.001,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("La fenêtre doit être finie et strictement positive.")
        if n_estimators < 1:
            raise ValueError("n_estimators doit être strictement positif.")
        self.window_seconds = window_seconds
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self._models: dict[int, IsolationForest] = {}
        self._normal_stats: dict[
            int, tuple[tuple[float, ...], tuple[float, ...]]
        ] = {}

    def fit(self, records: Sequence[CanRecord]) -> MLAnomalyDetector:
        """Entraîne exclusivement sur les trames étiquetées normales."""
        normal_records = [record for record in records if record.label == "normal"]
        if not normal_records:
            raise ValueError("L'entraînement requiert des trames normales.")

        by_can_id: dict[int, list[WindowFeatures]] = defaultdict(list)
        for sample in extract_features(normal_records, self.window_seconds):
            by_can_id[sample.can_id].append(sample)

        models: dict[int, IsolationForest] = {}
        normal_stats: dict[
            int, tuple[tuple[float, ...], tuple[float, ...]]
        ] = {}
        for can_id, samples in by_can_id.items():
            if len(samples) < 2:
                raise ValueError(
                    f"Au moins deux fenêtres normales sont requises pour {can_id:#x}."
                )
            model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state + can_id,
            )
            model.fit([sample.values for sample in samples])
            models[can_id] = model
            columns = list(zip(*(sample.values for sample in samples)))
            normal_stats[can_id] = (
                tuple(statistics.median(column) for column in columns),
                tuple(statistics.pstdev(column) for column in columns),
            )

        self._models = models
        self._normal_stats = normal_stats
        return self

    def most_deviant_features(
        self,
        records: Sequence[CanRecord],
        can_id: int,
        limit: int = 3,
    ) -> list[str]:
        """Describe window features furthest from this ID's normal training data."""
        if limit < 1:
            raise ValueError("limit doit être strictement positif.")

        stats = getattr(self, "_normal_stats", {}).get(can_id)
        if stats is None:
            return []

        sample = next(
            (
                item
                for item in extract_features(records, self.window_seconds)
                if item.can_id == can_id
            ),
            None,
        )
        if sample is None:
            return []

        medians, standard_deviations = stats
        deviations = sorted(
            (
                (
                    abs(value - median) / max(standard_deviation, 1e-9),
                    name,
                    value,
                    median,
                )
                for name, value, median, standard_deviation in zip(
                    FEATURE_NAMES,
                    sample.values,
                    medians,
                    standard_deviations,
                )
            ),
            reverse=True,
        )
        return [
            f"{name}={value:.3f} (médiane normale={median:.3f}, "
            f"écart normalisé={distance:.2f})"
            for distance, name, value, median in deviations[:limit]
        ]

    def predict(self, records: Sequence[CanRecord]) -> list[WindowPrediction]:
        """Prédit une anomalie par fenêtre et fournit un score croissant."""
        if not self._models:
            raise RuntimeError("Le détecteur doit être entraîné avant predict().")

        grouped: dict[int, list[tuple[int, bool, float]]] = defaultdict(list)
        for sample in extract_features(records, self.window_seconds):
            model = self._models.get(sample.can_id)
            if model is None:
                grouped[sample.window_index].append(
                    (sample.can_id, True, 1.0)
                )
                continue

            vector = [sample.values]
            predicted_anomaly = int(model.predict(vector)[0]) == -1
            anomaly_score = -float(model.decision_function(vector)[0])
            grouped[sample.window_index].append(
                (sample.can_id, predicted_anomaly, anomaly_score)
            )

        predictions: list[WindowPrediction] = []
        for window_index, samples in sorted(grouped.items()):
            anomalous_ids = tuple(
                sorted(can_id for can_id, is_anomaly, _ in samples if is_anomaly)
            )
            predictions.append(
                WindowPrediction(
                    window_index=window_index,
                    start=window_index * self.window_seconds,
                    end=(window_index + 1) * self.window_seconds,
                    is_anomaly=bool(anomalous_ids),
                    anomaly_score=max(score for _, _, score in samples),
                    anomalous_can_ids=anomalous_ids,
                )
            )
        return predictions
