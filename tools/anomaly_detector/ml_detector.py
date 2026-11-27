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
    unseen_can_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class FeatureDeviation:
    """Écart d'une caractéristique à son profil normal appris."""

    name: str
    value: float
    median: float
    normalized_deviation: float | None
    outside_zero_variance_baseline: bool


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
        self._calibrated_thresholds: dict[int, float] = {}
        self._calibration_status = "not_independently_calibrated"
        self._calibration_target_false_positive_rate: float | None = None
        self._calibration_sample_counts: dict[int, int] = {}
        self._training_capture_id: str | None = None

    def fit(
        self,
        records: Sequence[CanRecord],
        training_capture_id: str | None = None,
    ) -> MLAnomalyDetector:
        """Entraîne exclusivement sur les trames étiquetées normales."""
        normal_records = [record for record in records if record.label == "normal"]
        if not normal_records:
            raise ValueError("L'entraînement requiert des trames normales.")

        return self.fit_features(
            extract_features(normal_records, self.window_seconds),
            training_capture_id=training_capture_id,
        )

    def fit_features(
        self,
        samples: Sequence[WindowFeatures],
        training_capture_id: str | None = None,
    ) -> MLAnomalyDetector:
        """Fit from precomputed windows derived from normal-only traffic."""
        if not samples:
            raise ValueError("L'entraînement requiert des fenêtres normales.")
        if training_capture_id is not None and (
            not isinstance(training_capture_id, str)
            or not training_capture_id.strip()
        ):
            raise ValueError("L'identifiant de capture d'entraînement est vide.")

        by_can_id: dict[int, list[WindowFeatures]] = defaultdict(list)
        for sample in samples:
            if len(sample.values) != len(FEATURE_NAMES) or not all(
                math.isfinite(value) for value in sample.values
            ):
                raise ValueError("Vecteur de caractéristiques invalide.")
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
        self._calibrated_thresholds = {}
        self._calibration_status = "not_independently_calibrated"
        self._calibration_target_false_positive_rate = None
        self._calibration_sample_counts = {}
        self._training_capture_id = training_capture_id
        return self

    def calibrate_thresholds(
        self,
        normal_validation_samples: Sequence[WindowFeatures],
        target_false_positive_rate: float,
        *,
        validation_capture_id: str,
    ) -> MLAnomalyDetector:
        """Calibrate per-ID thresholds from independent normal-only samples.

        Calibration data must be independent of training and contain only normal
        traffic. Thresholds use the finite-sample upper-tail order statistic of
        the detector's anomaly scores. This method is opt-in; fitting alone never
        activates calibrated thresholds. Per-ID calibration does not guarantee
        the same false-positive rate for a window-level OR across multiple IDs.
        """
        if not self._models:
            raise RuntimeError("Le détecteur doit être entraîné avant calibration.")
        if (
            not isinstance(validation_capture_id, str)
            or not validation_capture_id.strip()
        ):
            raise ValueError("L'identifiant de capture de validation est vide.")
        training_capture_id = getattr(self, "_training_capture_id", None)
        if training_capture_id is None:
            raise ValueError(
                "L'identifiant de capture d'entraînement est requis pour vérifier "
                "l'indépendance."
            )
        if validation_capture_id == training_capture_id:
            raise ValueError(
                "La calibration doit provenir d'une capture indépendante de "
                "l'entraînement."
            )
        if (
            not math.isfinite(target_false_positive_rate)
            or not 0.0 < target_false_positive_rate < 1.0
        ):
            raise ValueError("Le taux cible doit être strictement entre 0 et 1.")
        if not normal_validation_samples:
            raise ValueError("La calibration requiert des fenêtres normales.")

        by_can_id: dict[int, list[WindowFeatures]] = defaultdict(list)
        for sample in normal_validation_samples:
            if len(sample.values) != len(FEATURE_NAMES) or not all(
                math.isfinite(value) for value in sample.values
            ):
                raise ValueError("Vecteur de caractéristiques invalide.")
            if sample.can_id not in self._models:
                raise ValueError(
                    f"ID CAN {sample.can_id:#x} absent des modèles entraînés."
                )
            by_can_id[sample.can_id].append(sample)

        for can_id, samples in by_can_id.items():
            window_indices = [sample.window_index for sample in samples]
            if len(window_indices) != len(set(window_indices)):
                raise ValueError(
                    f"Fenêtre de calibration dupliquée pour l'ID CAN {can_id:#x}."
                )

        minimum_samples = math.ceil(1.0 / target_false_positive_rate) - 1
        if set(by_can_id) != set(self._models):
            missing = sorted(set(self._models).difference(by_can_id))
            formatted = ", ".join(f"{can_id:#x}" for can_id in missing)
            raise ValueError(f"Fenêtres de calibration manquantes pour les IDs: {formatted}")
        if any(len(samples) < minimum_samples for samples in by_can_id.values()):
            insufficient = sorted(
                can_id
                for can_id, samples in by_can_id.items()
                if len(samples) < minimum_samples
            )
            formatted = ", ".join(f"{can_id:#x}" for can_id in insufficient)
            raise ValueError(
                f"Au moins {minimum_samples} fenêtres de calibration sont "
                f"requises par ID pour la résolution cible; insuffisant pour: {formatted}"
            )

        thresholds: dict[int, float] = {}
        sample_counts: dict[int, int] = {}
        for can_id, samples in by_can_id.items():
            model = self._models[can_id]
            scores = sorted(
                -float(score)
                for score in model.decision_function(
                    [sample.values for sample in samples]
                )
            )
            rank = math.ceil(
                (len(scores) + 1) * (1.0 - target_false_positive_rate)
            )
            thresholds[can_id] = scores[min(rank - 1, len(scores) - 1)]
            sample_counts[can_id] = len(samples)

        self._calibrated_thresholds = thresholds
        self._calibration_status = "calibrated_from_independent_normal_data"
        self._calibration_target_false_positive_rate = target_false_positive_rate
        self._calibration_sample_counts = sample_counts
        return self

    def feature_deviations(
        self, sample: WindowFeatures, can_id: int
    ) -> list[FeatureDeviation]:
        """Return stable deviations from the fitted per-ID normal profile."""
        stats = getattr(self, "_normal_stats", {}).get(can_id)
        if stats is None or sample.can_id != can_id:
            return []

        medians, standard_deviations = stats
        deviations = []
        for name, value, median, standard_deviation in zip(
            FEATURE_NAMES,
            sample.values,
            medians,
            standard_deviations,
        ):
            scale_floor = max(abs(median), 1.0) * 1e-12
            if standard_deviation <= scale_floor:
                changed = value != median
                deviations.append(
                    FeatureDeviation(
                        name=name,
                        value=value,
                        median=median,
                        normalized_deviation=None,
                        outside_zero_variance_baseline=changed,
                    )
                )
            else:
                distance = abs(value - median) / standard_deviation
                deviations.append(
                    FeatureDeviation(
                        name=name,
                        value=value,
                        median=median,
                        normalized_deviation=(
                            distance if math.isfinite(distance) else float("inf")
                        ),
                        outside_zero_variance_baseline=False,
                    )
                )
        return sorted(
            deviations,
            key=lambda item: (
                item.outside_zero_variance_baseline,
                item.normalized_deviation or 0.0,
            ),
            reverse=True,
        )

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

        deviations = self.feature_deviations(sample, can_id)
        return [self._format_feature_deviation(item) for item in deviations[:limit]]

    @staticmethod
    def _format_feature_deviation(deviation: FeatureDeviation) -> str:
        if deviation.outside_zero_variance_baseline:
            detail = "différent du profil normal à variance nulle"
        else:
            normalized = deviation.normalized_deviation
            detail = (
                f"écart normalisé={normalized:.2f}"
                if normalized is not None and math.isfinite(normalized)
                else "écart normalisé non fini"
            )
        return (
            f"{deviation.name}={deviation.value:.3f} "
            f"(médiane normale={deviation.median:.3f}, {detail})"
        )

    def predict(self, records: Sequence[CanRecord]) -> list[WindowPrediction]:
        """Prédit une anomalie par fenêtre et fournit un score croissant."""
        return self.predict_features(extract_features(records, self.window_seconds))

    def predict_features(
        self, samples: Sequence[WindowFeatures]
    ) -> list[WindowPrediction]:
        """Predict from precomputed windows, batching each per-ID forest."""
        if not self._models:
            raise RuntimeError("Le détecteur doit être entraîné avant predict().")

        grouped: dict[int, list[tuple[int, bool, float]]] = defaultdict(list)
        unseen_by_window: dict[int, set[int]] = defaultdict(set)
        by_can_id: dict[int, list[WindowFeatures]] = defaultdict(list)
        for sample in samples:
            if len(sample.values) != len(FEATURE_NAMES) or not all(
                math.isfinite(value) for value in sample.values
            ):
                raise ValueError("Vecteur de caractéristiques invalide.")
            by_can_id[sample.can_id].append(sample)

        for can_id, id_samples in by_can_id.items():
            model = self._models.get(can_id)
            if model is None:
                for sample in id_samples:
                    unseen_by_window[sample.window_index].add(can_id)
                continue

            vectors = [sample.values for sample in id_samples]
            scores = model.decision_function(vectors)
            calibrated_threshold = getattr(
                self, "_calibrated_thresholds", {}
            ).get(can_id)
            predictions = (
                model.predict(vectors)
                if calibrated_threshold is None
                else [
                    -1 if -float(score) > calibrated_threshold else 1
                    for score in scores
                ]
            )
            for sample, score, prediction in zip(id_samples, scores, predictions):
                anomaly_score = -float(score)
                grouped[sample.window_index].append(
                    (can_id, int(prediction) == -1, anomaly_score)
                )

        predictions: list[WindowPrediction] = []
        all_window_indices = set(grouped).union(unseen_by_window)
        for window_index in sorted(all_window_indices):
            samples = grouped.get(window_index, [])
            anomalous_ids = tuple(
                sorted(can_id for can_id, is_anomaly, _ in samples if is_anomaly)
            )
            predictions.append(
                WindowPrediction(
                    window_index=window_index,
                    start=window_index * self.window_seconds,
                    end=(window_index + 1) * self.window_seconds,
                    is_anomaly=bool(anomalous_ids),
                    anomaly_score=max(
                        (score for _, _, score in samples),
                        default=0.0,
                    ),
                    anomalous_can_ids=anomalous_ids,
                    unseen_can_ids=tuple(sorted(unseen_by_window.get(window_index, ()))),
                )
            )
        return predictions
