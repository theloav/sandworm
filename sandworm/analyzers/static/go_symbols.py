"""Bounded Go 1.18/1.20-layout pclntab recovery from ELF section metadata.

Names/ranges are compiler-declared metadata, not independently decoded coverage.
No program execution, dependency installation or guessed raw-byte table search.
"""
from __future__ import annotations

import struct

from ...core.evidence import EvidenceLocation
from ..base import BaseAnalyzer


def elf_sections(data: bytes) -> dict[str, dict]:
    if data[:4] != b"\x7fELF" or len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError("unsupported ELF header")
    bits, endian = (64 if data[4] == 2 else 32), ("<" if data[5] == 1 else ">")
    if bits == 64 and len(data) < 64:
        raise ValueError("truncated ELF header")
    table = struct.unpack_from(endian + ("Q" if bits == 64 else "I"), data, 40 if bits == 64 else 32)[0]
    stride, count, names_index = struct.unpack_from(endian + "HHH", data, 58 if bits == 64 else 46)
    if table < (64 if bits == 64 else 52) or not 1 <= count <= 8192 or names_index >= count or stride < (64 if bits == 64 else 40) or table + stride * count > len(data):
        raise ValueError("unsupported or invalid ELF section table")

    def section(index):
        position = table + stride * index
        name, kind = struct.unpack_from(endian + "II", data, position)
        flags, address, offset, size = struct.unpack_from(endian + ("QQQQ" if bits == 64 else "IIII"), data, position + 8)
        if kind != 8 and offset + size > len(data):
            raise ValueError("ELF section outside file")
        return {"name_offset": name, "kind": kind, "flags": flags, "address": address, "offset": offset, "size": size}

    names = section(names_index)
    if names["kind"] != 3:
        raise ValueError("section names are not a string table")
    start, end = names["offset"], names["offset"] + names["size"]
    sections = {}
    for index in range(count):
        row = section(index)
        position = start + row["name_offset"]
        stop = data.find(b"\0", position, min(end, position + 256))
        if not start <= position < end or stop < 0:
            raise ValueError("invalid section name")
        name = data[position:stop].decode("ascii", "replace")
        if name in sections and name in {".text", ".gopclntab", ".data.rel.ro.gopclntab"}:
            raise ValueError("ambiguous duplicate Go section")
        sections[name] = row
    return sections


def parse_pclntab(table: bytes, text: dict, *, max_functions: int = 10000) -> dict:
    if not 1 <= max_functions <= 100000:
        raise ValueError("invalid function limit")
    if len(table) < 8 or table[4:6] != b"\0\0" or table[6] not in (1, 2, 4) or table[7] not in (4, 8):
        raise ValueError("invalid pclntab header")
    layouts = {0xFFFFFFF0: "go1.18", 0xFFFFFFF1: "go1.20"}
    endian = "<" if int.from_bytes(table[:4], "little") in layouts else ">"
    magic = struct.unpack_from(endian + "I", table)[0]
    if magic not in layouts:
        raise ValueError("unsupported pclntab layout; only Go 1.18/1.20 layouts")
    pointer = table[7]
    if len(table) < 8 + pointer * 8:
        raise ValueError("truncated pclntab header")
    words = struct.unpack_from(endian + ("Q" if pointer == 8 else "I") * 8, table, 8)
    count, _, text_start, names, cutab, filetab, pctab, functions = words
    offsets = [names, cutab, filetab, pctab, functions]
    if not 0 < count <= 100000 or offsets != sorted(offsets) or names < 8 + pointer * 8 or functions >= len(table):
        raise ValueError("invalid pclntab counts or offsets")
    if not text["address"] <= text_start < text["address"] + text["size"]:
        raise ValueError("unresolved or out-of-section text base")
    table_size = (count * 2 + 1) * 4
    if functions + table_size > len(table):
        raise ValueError("truncated function table")
    recovered = []
    for index in range(min(count, max_functions)):
        entry, function_offset, next_entry = struct.unpack_from(endian + "III", table, functions + index * 8)
        start, end = text_start + entry, text_start + next_entry
        metadata = functions + function_offset
        if not text["address"] <= start < end <= text["address"] + text["size"]:
            raise ValueError("function range outside executable text")
        if function_offset < table_size or metadata + 8 > len(table):
            raise ValueError("invalid function metadata offset")
        declared_entry, name_offset = struct.unpack_from(endian + "II", table, metadata)
        if declared_entry != entry:
            raise ValueError("function entry disagrees with table")
        position = names + name_offset
        stop = table.find(b"\0", position, min(cutab, position + 1024))
        if not names <= position < cutab or stop <= position:
            raise ValueError("invalid function name offset")
        name = table[position:stop].decode("utf-8", "strict")
        if not name.isprintable():
            raise ValueError("invalid function name characters")
        recovered.append({"name": name, "start_va": start, "end_va": end,
                          "file_offset": text["offset"] + start - text["address"]})
    return {"layout": layouts[magic], "declared_functions": count, "truncated": count > max_functions, "functions": recovered}


def recover_go_functions(data: bytes, *, max_functions: int = 10000) -> dict | None:
    sections = elf_sections(data)
    table = sections.get(".gopclntab") or sections.get(".data.rel.ro.gopclntab")
    text = sections.get(".text")
    if not table:
        return None
    if not text or not text["flags"] & 4 or text["kind"] == 8 or table["kind"] == 8:
        raise ValueError("Go recovery needs file-backed executable text and pclntab")
    if table["size"] > 64 * 1024**2:
        raise ValueError("pclntab exceeds 64 MiB bound")
    return parse_pclntab(data[table["offset"]:table["offset"] + table["size"]], text, max_functions=max_functions)


class GoSymbolsAnalyzer(BaseAnalyzer):
    name = "static.go_symbols"
    handles = {"elf"}

    def run(self, sample, ctx):
        try:
            report = recover_go_functions(sample.data)
        except (ValueError, struct.error) as exc:
            return [ctx.ev(source=self.name, artifact="module", operation="read", confidence=0.0,
                           object={"format": "Go metadata"}, details={"status": "unavailable", "reason": str(exc)})]
        if report is None:
            return []
        return [ctx.ev(source=self.name, artifact="function", operation="resolve", confidence=0.8,
                       object={"function": row["name"]},
                       locations=[EvidenceLocation(virtual_address=row["start_va"], file_offset=row["file_offset"], function=row["name"])],
                       details={"metadata_range": {"start_va": row["start_va"], "end_va": row["end_va"]},
                                "layout": report["layout"], "truncated": report["truncated"],
                                "why": "pclntab-declared function; not decoded instruction coverage or behavior proof"},
                       evidence_refs=["sample:" + sample.sha256]) for row in report["functions"]]


def register(registry):
    registry.register(GoSymbolsAnalyzer())
