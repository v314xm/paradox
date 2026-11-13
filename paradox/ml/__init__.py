"""Минимальный ML-слой Paradox — без внешних зависимостей.

Здесь только то, что нельзя взять из scikit-learn, не раздув сборку:
детерминированный Isolation Forest для статистических выбросов.
"""
from paradox.ml.isolation_forest import IsolationForest

__all__ = ["IsolationForest"]
