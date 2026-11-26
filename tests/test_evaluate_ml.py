"""Tests de l'agrégation des métriques multi-graines."""

import unittest

from scripts.evaluate_ml import mean_and_std, parse_seeds


class TestEvaluateML(unittest.TestCase):
    def test_seed_parsing_and_metric_summary(self):
        self.assertEqual(parse_seeds("42, 43,44"), (42, 43, 44))
        mean, standard_deviation = mean_and_std([0.0, 1.0])
        self.assertEqual(mean, 0.5)
        self.assertEqual(standard_deviation, 0.5)


if __name__ == "__main__":
    unittest.main()
