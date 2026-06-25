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


def _pe_sample() -> Sample:
    # A minimal PE-format sample (MZ magic) so the Windows replay reports are a
    # format match and get ingested (a Windows report for a non-PE sample is
    # refused as belonging to a different binary).
    return Sample.from_bytes("loader.exe", b"MZ" + b"\x00" * 256)


def _run(samples_dir: Path):
    return analyze_sample(
        _pe_sample(),
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


def test_observed_evidence_scores_higher_than_inferred():
    # Same injection capability: confidence-weighted scoring must rank the
    # runtime-observed version above the static-only inference.
    def store_with(source: str, conf: float) -> EvidenceStore:
        s = EvidenceStore()
        for api in ("WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"):
            s.append(EvidenceItem(run_id="r", source=source, artifact="api_call", operation="exec",
                     subject={"a": "x"}, object={"api": api}, confidence=conf))
        return s

    static = store_with("static.pe", 0.7)
    observed = store_with("dynamic.windows.cape", 0.9)
    s_static = build_summary(static, map_evidence(static), build_narrative(map_evidence(static)), isolated=False)
    s_obs = build_summary(observed, map_evidence(observed), build_narrative(map_evidence(observed)), isolated=True)
    assert s_obs.maliciousness_score > s_static.maliciousness_score
    # the injection factor names its standing in both cases
    assert any("observed" in label for label, _ in s_obs.score_factors)
    assert any("inferred" in label for label, _ in s_static.score_factors)


def test_score_factors_credit_distinct_capability_axes():
    # A backdoor with persistence + discovery + C2 (no injection/ransomware) must
    # now credit each axis, not sit at a floor — the old model ignored these.
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.common", artifact="network", operation="resolve",
                 subject={"a": "x"}, object={"kind": "domain", "value": "c2.evil.ru"}, details={"ioc": True}, confidence=0.6))
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                 subject={"a": "x"}, object={"import": "CreateService"}, details={"attack_hint": "T1543.003", "why": "svc"}, confidence=0.55))
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                 subject={"a": "x"}, object={"import": "GetAdaptersInfo"}, details={"attack_hint": "T1016", "why": "disc"}, confidence=0.4))
    summary = build_summary(store, map_evidence(store), build_narrative(map_evidence(store)), isolated=False)
    labels = " ".join(label for label, _ in summary.score_factors)
    assert "Persistence" in labels and "Network / C2" in labels and "discovery" in labels.lower()
    assert summary.maliciousness_score >= 35  # credited for real capability, not stuck at a floor


def test_score_uses_diminishing_returns_not_a_flat_ceiling():
    # A heavily-stacked sample (ransomware + injection + persistence + C2 + ...)
    # must NOT simply pin to 100 — the diminishing-returns curve compresses the
    # top so the high band keeps differentiating, shown as an explicit factor.
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.common", artifact="file", operation="write",
                 subject={"a": "x"}, object={"capability": "ransomware", "indicators": [".wnry"]}, confidence=0.8))
    for api in ("WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"):
        store.append(EvidenceItem(run_id="r", source="dynamic.windows.cape", artifact="api_call", operation="exec",
                     subject={"a": "x"}, object={"api": api}, confidence=0.9))
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                 subject={"a": "x"}, object={"import": "CreateService"}, details={"attack_hint": "T1543.003", "why": "svc"}, confidence=0.55))
    store.append(EvidenceItem(run_id="r", source="dynamic.windows.cape", artifact="network", operation="connect",
                 subject={"a": "x"}, object={"kind": "ipv4", "value": "9.9.9.9", "host": "9.9.9.9"},
                 details={"ioc": True}, confidence=0.85))
    summary = build_summary(store, map_evidence(store), build_narrative(map_evidence(store)), isolated=True)
    positive = sum(p for _, p in summary.score_factors if p > 0)
    dr = [p for label, p in summary.score_factors if "Diminishing returns" in label]
    assert positive > 100                             # the additive signals exceed the ceiling
    assert dr and dr[0] < 0                            # compression is applied as a negative factor
    assert summary.maliciousness_score < 100          # and the final score lands below the ceiling
    assert sum(p for _, p in summary.score_factors) == summary.maliciousness_score


def test_low_scores_are_untouched_by_diminishing_returns():
    # A single-capability sample sits below the knee, so its score is unchanged
    # and carries no diminishing-returns factor.
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="api_call", operation="resolve",
                 subject={"a": "x"}, object={"import": "WriteProcessMemory"}, details={"why": "x"}, confidence=0.7))
    summary = build_summary(store, map_evidence(store), build_narrative(map_evidence(store)), isolated=False)
    assert not any("Diminishing returns" in label for label, _ in summary.score_factors)


def test_mismatched_windows_report_on_php_is_refused():
    # A Windows/PE report must NOT be folded into a benign PHP sample's verdict —
    # otherwise the file is falsely rated for injection it never did.
    base = Path(__file__).resolve().parent.parent / "samples"
    result = analyze_sample(
        Sample.from_path(base / "benign" / "contact_form.php"), enable_dynamic=False,
        cape_report=str(base / "synthetic" / "recorded_cape_report.json"),
        memory_report=str(base / "synthetic" / "recorded_vol3_report.json"),
    )
    assert any("refused" in n.lower() for n in result.notes)
    # the bogus Windows evidence is NOT in the store, and the verdict stays Low
    assert not any(it.source.startswith(("dynamic.", "memory.")) for it in result.store)
    assert "T1055" not in {m.technique_id for m in result.mappings}
    summary = build_summary(result.store, result.mappings, result.phases, isolated=False)
    assert summary.risk == "Low"


def test_family_attribution_is_medium_when_static_only():
    store = EvidenceStore()
    store.append(EvidenceItem(run_id="r", source="static.pe", artifact="string", operation="read",
                 subject={"a": "x"}, object={"value": ".wnry"}, confidence=0.7))
    summary = build_summary(store, map_evidence(store), build_narrative(map_evidence(store)), isolated=False)
    assert summary.family_hint == "WannaCry"
    assert summary.family_confidence == 0.95
    assert summary.family_confidence_label == "Medium"  # static markers only
