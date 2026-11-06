"""HistoryDB: запись, чтение и обрезка старых прогонов."""
from paradox_gui.storage import HistoryDB


def _report(path: str) -> dict:
    return {
        "provenance": {"pcap_path": path, "pcap_sha256": "x"},
        "summary": {"findings": 1, "contradictions": 0},
    }


def test_insert_and_load(tmp_path):
    db = HistoryDB(tmp_path / "history.db")

    run_id = db.insert(_report("a.pcap"))

    assert run_id is not None
    loaded = db.load_recent(limit=10)
    assert len(loaded) == 1
    assert loaded[0][2]["provenance"]["pcap_path"] == "a.pcap"


def test_old_rows_are_pruned(tmp_path):
    db = HistoryDB(tmp_path / "history.db")

    for i in range(HistoryDB.MAX_ROWS + 5):
        db.insert(_report(f"{i}.pcap"))

    loaded = db.load_recent(limit=HistoryDB.MAX_ROWS + 100)

    assert len(loaded) == HistoryDB.MAX_ROWS
    # Свежий прогон на месте, самые старые удалены.
    assert loaded[0][2]["provenance"]["pcap_path"] == f"{HistoryDB.MAX_ROWS + 4}.pcap"
    paths = {r[2]["provenance"]["pcap_path"] for r in loaded}
    assert "0.pcap" not in paths


def test_update_report_and_clear(tmp_path):
    db = HistoryDB(tmp_path / "history.db")
    run_id = db.insert(_report("a.pcap"))

    updated = _report("a.pcap")
    updated["summary"]["findings"] = 7
    db.update_report(run_id, updated, enriched=True)

    loaded = db.load_recent(limit=1)
    assert loaded[0][2]["summary"]["findings"] == 7

    db.clear()
    assert db.load_recent() == []
