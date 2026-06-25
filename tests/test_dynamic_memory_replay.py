"""Phase 2: dynamic (CAPE) + memory (vol3) evidence via offline replay.

The central safety property under test: replaying a *recorded* report ingests
prior evidence and executes nothing, so it runs WITHOUT the isolation gate — yet
the resulting dynamic/memory evidence still upgrades technique standing
inferred → observed, populates the runtime view, and flips evidence maturity.
"""

from __future__ import annotations

from pathlib import Path

from sandworm.core.evidence import EvidenceItem, EvidenceStore
from sandworm.core.pipeline import analyze_sample
from sandworm.core.sample import Sample
from sandworm.reconstruct.attack_map import map_evidence
from sandworm.reconstruct.narrative import build_narrative
from sandworm.reconstruct.runtime import build_runtime_view
from sandworm.reporting.summary import build_summary


def _run(samples_dir: Path):
    sample = Sample.from_path(samples_dir / "benign_dropper.sh")
    return analyze_sample(
        sample,
        enable_dynamic=False,  # isolation NOT verified — proves replay is ungated
        cape_report=str(samples_dir / "recorded_cape_report.json"),
        memory_report=str(samples_dir / "recorded_vol3_report.json"),
    )


def test_replay_runs_offline_without_isolation(samples_dir):
    result = _run(samples_dir)
    assert result.isolated is False  # never detonated
    sources = {it.source for it in result.store}
    assert "dynamic.windows.cape" in sources  # recorded dynamic evidence ingested
    assert "memory.vol3" in sources            # recorded memory evidence ingested
    assert any("replay" in n for n in result.notes)


def test_dynamic_evidence_upgrades_injection_to_observed(samples_dir):
    result = _run(samples_dir)
    inj = [m for m in result.mappings if m.technique_id == "T1055"][0]
    assert inj.status == "observed"  # CAPE API stats + memory malfind confirm it


def test_runtime_view_builds_process_tree(samples_dir):
    result = _run(samples_dir)
    rv = build_runtime_view(result.store)
    assert rv.observed is True
    flat = rv.flatten()
    names = {n.name for n in flat}
    assert {"loader.exe", "notepad.exe"} <= names
    # notepad.exe is a child of loader.exe (parent→child wiring)
    loader = [n for n in rv.process_tree if n.name == "loader.exe"]
    assert loader and any(c.name == "notepad.exe" for c in loader[0].children)
    assert "notepad.exe" in rv.injected      # malfind RWX region
    assert "185.234.218.42" in rv.network


def test_evidence_maturity_flips_with_replay(samples_dir):
    result = _run(samples_dir)
    summary = build_summary(result.store, result.mappings, result.phases, isolated=False)
    maturity = dict(summary.evidence_maturity)
    assert maturity["dynamic"] == "complete"
    assert maturity["memory"] == "complete"
    assert summary.runtime_observed is True


def test_runtime_rules_counted_when_observed(samples_dir):
    result = _run(samples_dir)
    cov = result.coverage
    assert cov.observed_techniques >= 1
    assert cov.runtime_coverage is not None       # no longer N/A
    assert cov.inventory.runtime_rules >= 1       # rules now cover observed techniques


def test_static_only_run_has_no_runtime(samples_dir):
    # Same sample, no recorded reports → runtime view stays pending (placeholder).
    sample = Sample.from_path(samples_dir / "benign_dropper.sh")
    result = analyze_sample(sample, enable_dynamic=False)
    rv = build_runtime_view(result.store)
    assert rv.observed is False
    assert rv.process_tree == []
    cov = result.coverage
    assert cov.runtime_coverage is None
    assert cov.inventory.runtime_rules == 0


def test_lifecycle_assigns_each_technique_to_one_phase():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="string", operation="decode",
                 subject={"a": "x"}, object={"layer": 1, "function": "xor"}, confidence=0.8))
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                 subject={"a": "x"}, object={"import": "WriteProcessMemory"}, confidence=0.6))
    phases = build_narrative(map_evidence(store))
    placement = {p.name: [t.technique_id for t in p.techniques] for p in phases if p.reached}
    # T1027 (obfuscation) only under unpack; T1055 (injection) only under injection.
    assert "T1027" in placement.get("unpack/deobfuscate", [])
    assert "T1027" not in placement.get("injection", [])
    assert placement.get("injection", []) == ["T1055"]


def test_memory_malfind_attributes_injection():
    # A recorded memory report's malfind row alone attributes T1055 (observed).
    from sandworm.analyzers.base import Context
    from sandworm.analyzers.memory.vol3 import normalize_memory_report

    ctx = Context(run_id="r")
    report = [{"plugin": "windows.malfind.Malfind",
               "rows": [{"PID": 2604, "Process": "notepad.exe", "Protection": "PAGE_EXECUTE_READWRITE"}]}]
    store = EvidenceStore()
    store.extend(list(normalize_memory_report(report, ctx, "sample:abc")))
    m = [x for x in map_evidence(store) if x.technique_id == "T1055"]
    assert m and m[0].status == "observed"


def test_family_attribution_is_medium_when_static_only():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="string", operation="read",
                 subject={"a": "x"}, object={"value": ".wnry"}, confidence=0.7))
    summary = build_summary(store, map_evidence(store), build_narrative(map_evidence(store)), isolated=False)
    assert summary.family_hint == "WannaCry"
    assert summary.family_confidence == 0.95
    assert summary.family_confidence_label == "Medium"  # static markers only
