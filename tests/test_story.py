"""Тесты анализа истории хоста."""
from pcap_triage.analyzers.story import build_host_story


def test_story_empty():
    report = {}
    res = build_host_story(report, "10.0.0.1")
    assert res["target_ip"] == "10.0.0.1"
    assert res["events"] == []
    assert res["summary"]["total_events"] == 0


def test_story_events_sorted():
    report = {
        "flows": {
            "top_by_bytes": [
                {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "first_ts": 100},
                {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "first_ts": 50},
            ]
        },
        "findings": [
            {"type": "dga", "src_ip": "10.0.0.1", "first_seen": 75}
        ]
    }

    res = build_host_story(report, "10.0.0.1")

    assert res["summary"]["total_events"] == 3
    assert res["summary"]["flows_count"] == 2
    assert res["summary"]["findings_count"] == 1
    assert res["summary"]["unique_contacts"] == 2

    # Проверка сортировки: 50 -> 75 -> 100
    assert res["events"][0]["ts"] == 50
    assert res["events"][0]["type"] == "flow"

    assert res["events"][1]["ts"] == 75
    assert res["events"][1]["type"] == "finding"

    assert res["events"][2]["ts"] == 100
    assert res["events"][2]["type"] == "flow"
