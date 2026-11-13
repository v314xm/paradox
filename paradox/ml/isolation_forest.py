"""Изолирующий лес (Isolation Forest) без внешних зависимостей.

Детерминированная реализация Liu, Ting, Zhou (2008) для поиска
статистических выбросов в наборе строк-признаков.

Зачем свой, а не scikit-learn: Paradox собирается в одиночный exe
(Paradox.spec), а sklearn тянет numpy/scipy/joblib/threadpoolctl —
десятки мегабайт нативного кода ради одного дерева, которое на
нескольких тысячах строк x ~15 признаков считается за миллисекунды.
Здесь нет ни одной зависимости за пределами stdlib.

API намеренно минимален и детерминирован:

    forest = IsolationForest(seed=42)
    forest.fit(X)                  # X: список строк фиксированной длины
    scores = forest.anomaly_scores(X)   # [0, 1], выше = аномальнее

В отличие от прототипа A-Detector (который берёт только бинарный
``predict`` и потому не имеет confidence) здесь используется
непрерывный anomaly-score: средняя глубина изоляции, нормированная
на ожидаемую глубину c(n). Его и отображает behavioural-слой в
confidence находки.
"""
from __future__ import annotations

import math
import random

# Константа Эйлера—Маскерони для c(n) (ожидаемая глубина листа).
_EULER_GAMMA = 0.5772156649015328606


def _expected_path_length(n: int) -> float:
    """c(n) — средняя длина пути неуспешного поиска в BST из n узлов."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    # H(n-1) ~= ln(n-1) + gamma
    return 2.0 * (math.log(n - 1) + _EULER_GAMMA) - 2.0 * (n - 1) / n


def _feature_ranges(points: list[list[float]]) -> list[tuple[float, float]]:
    """(min, max) по каждому признаку. Пусто — нет точек."""
    if not points:
        return []
    width = len(points[0])
    lo = list(points[0])
    hi = list(points[0])
    for p in points[1:]:
        for i in range(width):
            if p[i] < lo[i]:
                lo[i] = p[i]
            if p[i] > hi[i]:
                hi[i] = p[i]
    return list(zip(lo, hi, strict=True))


class IsolationForest:
    """Детерминированный изолирующий лес над строками-признаками."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: int = 256,
        seed: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.seed = seed
        # Стандартный потолок глубины: точка изолируется за log2(psi)
        # шагов; дальше строить дерево бессмысленно.
        self.max_depth = int(math.ceil(math.log2(max(self.max_samples, 2))))
        self._trees: list = []
        self._sample_size: int = 0

    def fit(self, X: list[list[float]]) -> None:
        """Построить лес. X не мутируется."""
        self._trees = []
        if not X:
            self._sample_size = 0
            return
        # Нормировка в anomaly_scores идёт на фактический размер
        # субвыборки, а не на max_samples: на захвате < max_samples
        # сессий иначе оценка съедет.
        self._sample_size = min(len(X), self.max_samples)
        # rng создаётся здесь, а не в __init__: fit() детерминирован
        # независимо от порядка вызовов на одном инстансе.
        rng = random.Random(self.seed)
        self._trees = [
            self._build_tree(X, rng) for _ in range(self.n_estimators)
        ]

    def _build_tree(self, X: list[list[float]], rng: random.Random) -> tuple:
        """Одно дерево на субвыборке фиксированного размера."""
        if len(X) <= self.max_samples:
            sample = X
        else:
            sample = rng.sample(X, self.max_samples)
        return self._grow(sample, 0, rng)

    def _grow(self, points: list[list[float]], depth: int, rng: random.Random):
        """Рекурсивный сплит. Лист — ("leaf", size), иначе — кортеж split."""
        n = len(points)
        if n <= 1 or depth >= self.max_depth:
            return ("leaf", n)

        ranges = _feature_ranges(points)
        splittable = [i for i, (lo, hi) in enumerate(ranges) if hi > lo]
        if not splittable:
            return ("leaf", n)

        feature = rng.choice(splittable)
        lo, hi = ranges[feature]
        threshold = rng.uniform(lo, hi)  # uniform в [lo, hi)

        left = [p for p in points if p[feature] < threshold]
        right = [p for p in points if p[feature] >= threshold]
        # Страховка от вырождения (все точки по одну сторону split).
        if not left or not right:
            return ("leaf", n)

        return (
            "split", feature, threshold,
            self._grow(left, depth + 1, rng),
            self._grow(right, depth + 1, rng),
        )

    def anomaly_scores(self, X: list[list[float]]) -> list[float]:
        """Оценка аномальности каждой строки: [0, 1], выше = аномальнее.

        0.5 — средняя, 1.0 — точка изолировалась на минимальной глубине
        (сильный выброс), ~0 — точка «утонула» в плотном кластере.
        """
        if not self._trees or not X:
            return [0.0] * len(X)
        c = _expected_path_length(self._sample_size)
        out = []
        for x in X:
            total = 0.0
            for tree in self._trees:
                total += self._path_length(x, tree)
            avg = total / len(self._trees)
            out.append(2.0 ** (-avg / c))
        return out

    def _path_length(self, x: list[float], node) -> float:
        """Длина пути до листа + поправка c(size) для внешнего узла."""
        if node[0] == "leaf":
            size = node[1]
            return 0.0 if size <= 1 else _expected_path_length(size)
        _, feature, threshold, left, right = node
        if x[feature] < threshold:
            return 1.0 + self._path_length(x, left)
        return 1.0 + self._path_length(x, right)
