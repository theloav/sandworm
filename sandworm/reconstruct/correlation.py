"""Annotate runtime evidence with matching statically decoded functions.

The correlator is deliberately conservative: a runtime address must identify the
analyzed module by SHA-256 or basename, and must fall inside a decoded instruction
range. Merely sharing an address-shaped value is never enough.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.evidence import EvidenceItem, EvidenceLocation, EvidenceStore
from ..core.sample import Sample

_MAX_CORRELATIONS = 10_000


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str):
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _basename(value: object) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


@dataclass(frozen=True)
class _FunctionRecord:
    item: EvidenceItem
    name: str
    rva_ranges: tuple[tuple[int, int], ...]
    va_ranges: tuple[tuple[int, int], ...]
    location: EvidenceLocation

    def contains_rva(self, address: int) -> bool:
        return any(start <= address < end for start, end in self.rva_ranges)

    def contains_va(self, address: int) -> bool:
        return any(start <= address < end for start, end in self.va_ranges)

    @property
    def span(self) -> int:
        ranges = self.rva_ranges or self.va_ranges
        return sum(end - start for start, end in ranges)


def _valid_range(start: object, end: object) -> tuple[int, int] | None:
    first, last = _integer(start), _integer(end)
    if first is None or last is None or last <= first:
        return None
    return first, last


def _function_record(item: EvidenceItem) -> _FunctionRecord | None:
    if item.source != "static.disasm" or item.artifact != "function" or not item.locations:
        return None
    location = item.locations[0]
    name = str(item.object.get("function") or location.function or "")
    if not name:
        return None
    rva_ranges: list[tuple[int, int]] = []
    va_ranges: list[tuple[int, int]] = []
    ranges = item.details.get("address_ranges")
    if isinstance(ranges, list):
        for row in ranges:
            if not isinstance(row, dict):
                continue
            if pair := _valid_range(row.get("start_rva"), row.get("end_rva")):
                rva_ranges.append(pair)
            if pair := _valid_range(row.get("start_va"), row.get("end_va")):
                va_ranges.append(pair)
    size = _integer(item.details.get("size")) or location.size or 1
    if not rva_ranges and location.rva is not None:
        rva_ranges.append((location.rva, location.rva + max(size, 1)))
    if not va_ranges and location.virtual_address is not None:
        va_ranges.append(
            (location.virtual_address, location.virtual_address + max(size, 1))
        )
    if not rva_ranges and not va_ranges:
        return None
    return _FunctionRecord(
        item=item,
        name=name,
        rva_ranges=tuple(rva_ranges),
        va_ranges=tuple(va_ranges),
        location=location,
    )


def _sample_names(sample: Sample) -> set[str]:
    return {
        name
        for value in (sample.name, sample.origin_path)
        if (name := _basename(value))
    }


def _belongs_to_sample(
    item: EvidenceItem,
    location: EvidenceLocation,
    sample: Sample,
    sample_names: set[str],
) -> bool:
    if location.artifact_sha256:
        return location.artifact_sha256.lower() == sample.sha256.lower()
    # An explicit caller module takes precedence over the hosting process:
    # calls inside a DLL must not be attributed to the executable's functions.
    if location.module:
        return _basename(location.module) in sample_names
    if item.details.get("module_path"):
        return _basename(item.details["module_path"]) in sample_names
    candidates = {
        _basename(location.module),
        _basename(item.details.get("module_path")),
        _basename(item.subject.get("name")),
        _basename(item.subject.get("process")),
        _basename(item.object.get("process")),
    }
    candidates.discard("")
    return bool(candidates & sample_names)


def _match_function(
    functions: list[_FunctionRecord],
    location: EvidenceLocation,
) -> tuple[_FunctionRecord, str, int] | None:
    if location.rva is not None:
        matches = [function for function in functions if function.contains_rva(location.rva)]
        if matches:
            return min(matches, key=lambda function: function.span), "module_rva", location.rva
        return None
    if location.module_base is not None:
        return None
    address = location.instruction_address
    if address is not None:
        matches = [function for function in functions if function.contains_va(address)]
        if matches:
            return min(matches, key=lambda function: function.span), "preferred_va", address
    return None


def _correlation_record(
    function: _FunctionRecord,
    runtime: EvidenceItem,
    *,
    basis: str,
    matched_address: int,
) -> dict[str, Any]:
    factor = 0.98 if basis == "module_rva" else 0.9
    confidence = round(min(function.item.confidence, runtime.confidence) * factor, 3)
    runtime_label = str(
        runtime.object.get("api")
        or runtime.object.get("hooked")
        or runtime.object.get("name")
        or f"{runtime.artifact}:{runtime.operation}"
    )
    return {
        "function": function.name,
        "match_basis": basis,
        "matched_address": matched_address,
        "static_evidence_id": function.item.id,
        "confidence": confidence,
        "runtime_event": runtime_label,
        "why": (
            f"runtime event {runtime_label} at {hex(matched_address)} falls inside decoded "
            f"function {function.name}; module identity matches the analyzed sample"
        ),
    }


def annotate_runtime_addresses(
    static_store: EvidenceStore,
    runtime_items: list[EvidenceItem],
    sample: Sample,
) -> tuple[list[EvidenceItem], int]:
    """Return runtime items with exact function annotations and a match count.

    Annotation happens before runtime evidence is appended to the store, keeping
    the store append-only and preserving the analyzer/consumer boundary.
    """
    functions = [
        record
        for item in static_store
        if (record := _function_record(item)) is not None
    ]
    if not functions:
        return runtime_items, 0
    names = _sample_names(sample)
    annotated: list[EvidenceItem] = []
    total = 0

    for runtime in runtime_items:
        if not runtime.source.startswith(("dynamic.", "memory.")):
            annotated.append(runtime)
            continue
        locations: list[EvidenceLocation] = []
        records: list[dict[str, Any]] = []
        static_refs: list[str] = []
        seen_matches: set[tuple[str, str, int]] = set()
        for location in runtime.locations:
            if total >= _MAX_CORRELATIONS or location.instruction_address is None:
                locations.append(location)
                continue
            if not _belongs_to_sample(runtime, location, sample, names):
                locations.append(location)
                continue
            matched = _match_function(functions, location)
            if matched is None:
                locations.append(location)
                continue
            function, basis, address = matched
            match_key = (function.item.id, basis, address)
            if match_key in seen_matches:
                locations.append(location.model_copy(update={"function": function.name}))
                continue
            seen_matches.add(match_key)
            locations.append(location.model_copy(update={"function": function.name}))
            records.append(
                _correlation_record(
                    function,
                    runtime,
                    basis=basis,
                    matched_address=address,
                )
            )
            static_refs.append(f"evidence:{function.item.id}")
            total += 1
        if records:
            annotated.append(
                runtime.model_copy(
                    update={
                        "details": {**runtime.details, "address_correlations": records},
                        "evidence_refs": list(
                            dict.fromkeys([*runtime.evidence_refs, *static_refs])
                        ),
                        "locations": locations,
                    }
                )
            )
        else:
            annotated.append(runtime)
    return annotated, total
