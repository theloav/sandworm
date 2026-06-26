"""Real-time evidence streaming via EvidenceStore pub/sub (#8)."""

from __future__ import annotations

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.pipeline import analyze_sample
from sandworm.core.sample import Sample
from sandworm.reporting.stream import StreamFeed, format_event


def _ev(**over):
    base = dict(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
               subject={"a": "x"}, object={"import": "RegCreateKey"}, confidence=0.4)
    base.update(over)
    return EvidenceItem(**base)


def test_subscriber_fires_once_per_new_item_in_order():
    store = EvidenceStore()
    seen: list[str] = []
    store.subscribe(lambda it: seen.append(it.object.get("import") or it.object.get("value", "?")))
    store.append(_ev(object={"import": "A"}))
    store.append(_ev(object={"import": "B"}))
    store.append(_ev(object={"import": "A"}))   # duplicate id → not re-notified
    assert seen == ["A", "B"]


def test_high_signal_findings_are_flagged_alert():
    netw = _ev(source="static.common", artifact="network", operation="connect",
               object={"kind": "ipv4", "value": "9.9.9.9", "host": "9.9.9.9"}, details={"ioc": True}, confidence=0.85)
    benign = _ev(object={"import": "GetTickCount"}, confidence=0.25)
    assert format_event(netw).startswith("ALERT")
    assert "C2 / network egress" in format_event(netw)
    assert not format_event(benign).startswith("ALERT")


def test_stream_feed_counts_alerts_and_buffers_lines():
    feed = StreamFeed()
    feed(_ev(source="static.common", artifact="network", operation="connect",
             object={"value": "evil.ru", "host": "evil.ru"}, details={"ioc": True}, confidence=0.8))
    feed(_ev(object={"import": "RegCreateKey"}))
    assert len(feed.lines) == 2
    assert feed.alerts == 1


def test_streaming_through_a_real_run_emits_before_completion():
    # The feed is populated during analyze_sample (subscribed before analyzers run),
    # so it is non-empty and ordered the same as the final store.
    feed = StreamFeed()
    sample = Sample.from_bytes("shell.php", b"<?php system($_REQUEST['c']); // x\n")
    sample.format_hint = "php"
    result = analyze_sample(sample, enable_dynamic=False, on_evidence=feed)
    assert feed.lines                                   # streamed during the run
    assert len(feed.lines) == len(result.store)         # every item was emitted once
    assert any(line.startswith("ALERT") for line in feed.lines)  # the system() sink alerted
