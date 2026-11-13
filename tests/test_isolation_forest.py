"""Тесты чистого Isolation Forest (paradox/ml/isolation_forest.py)."""
from paradox.ml.isolation_forest import IsolationForest


def test_deterministic():
    X = [[float(i), float(i % 13)] for i in range(200)]
    X.append([1000.0, 1000.0])  # выброс
    a = IsolationForest(seed=7)
    b = IsolationForest(seed=7)
    a.fit(X)
    b.fit(X)
    assert a.anomaly_scores(X) == b.anomaly_scores(X)


def test_different_seed_may_differ_but_stays_stable():
    X = [[float(i), float(i % 13)] for i in range(200)]
    X.append([1000.0, 1000.0])
    a = IsolationForest(seed=1)
    a.fit(X)
    first = a.anomaly_scores(X)
    second = a.anomaly_scores(X)
    # повторный вызов anomaly_scores на том же лесе не меняет результат
    assert first == second


def test_outlier_gets_highest_score():
    X = [[float(i), float(i % 13)] for i in range(100)]
    X.append([5000.0, 5000.0])
    forest = IsolationForest(seed=1)
    forest.fit(X)
    scores = forest.anomaly_scores(X)
    assert max(range(len(scores)), key=lambda i: scores[i]) == len(X) - 1


def test_scores_in_unit_interval():
    X = [[float(i), float((i * 37) % 11)] for i in range(50)]
    forest = IsolationForest(seed=2)
    forest.fit(X)
    scores = forest.anomaly_scores(X)
    assert all(0.0 <= s <= 1.0 for s in scores)


def test_empty_fit_and_scores():
    forest = IsolationForest()
    forest.fit([])
    assert forest.anomaly_scores([]) == []


def test_identical_points_have_equal_scores():
    X = [[1.0, 2.0, 3.0] for _ in range(20)]
    forest = IsolationForest(seed=3)
    forest.fit(X)
    scores = forest.anomaly_scores(X)
    assert len({round(s, 6) for s in scores}) == 1


def test_small_input_uses_actual_sample_size():
    """На 3 точках (меньше max_samples) нормировка не должна упасть."""
    X = [[1.0, 1.0], [2.0, 2.0], [999.0, 999.0]]
    forest = IsolationForest(seed=4)
    forest.fit(X)
    scores = forest.anomaly_scores(X)
    assert len(scores) == 3
    assert all(0.0 <= s <= 1.0 for s in scores)
    assert max(range(3), key=lambda i: scores[i]) == 2
