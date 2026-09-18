"""Mach-O segment/dependency/entry-point inventory, including universal slices."""

from __future__ import annotations

import struct

from ...core.evidence import EvidenceLocation
from ..base import BaseAnalyzer


def parse_macho(data: bytes, origin: int = 0) -> list[dict]:
    if data[:4] == b"\xca\xfe\xba\xbe" and len(data) >= 8:
        count = struct.unpack_from(">I", data, 4)[0]
        if count > 32 or 8 + count * 20 > len(data):
            raise ValueError("invalid universal binary table")
        result = []
        for i in range(count):
            _, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + i * 20)
            if offset < 8 + count * 20 or offset + size > len(data):
                raise ValueError("invalid Mach-O slice bounds")
            if data[offset:offset + 4] == b"\xca\xfe\xba\xbe":
                raise ValueError("nested universal binaries are not supported")
            result.extend(parse_macho(data[offset:offset + size], origin + offset))
        return result
    magic = data[:4]
    if magic not in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"}:
        return []
    endian = "<" if magic[0] in (0xCE, 0xCF) else ">"
    bits = 64 if magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"} else 32
    header = 32 if bits == 64 else 28
    if len(data) < header:
        return []
    cpu, subtype, kind, count, size, flags = struct.unpack_from(endian + "6I", data, 4)
    if count > 4096 or header + size > len(data):
        raise ValueError("invalid Mach-O load commands")
    result = [{"kind": "header", "cpu": cpu, "bits": bits, "file_type": kind, "flags": flags, "offset": origin}]
    pos = header
    for _ in range(count):
        if pos + 8 > header + size:
            raise ValueError("truncated load command")
        cmd, length = struct.unpack_from(endian + "II", data, pos)
        if length < 8 or pos + length > header + size:
            raise ValueError("invalid load command bounds")
        if cmd in (1, 0x19) and length >= (72 if cmd == 0x19 else 56):
            name = data[pos + 8:pos + 24].split(b"\x00")[0].decode("ascii", "replace")
            va, vs, fo, fs, maximum, initial = struct.unpack_from(endian + ("4Q2I" if cmd == 0x19 else "6I"), data, pos + 24)
            result.append({"kind": "segment", "name": name, "va": va, "size": vs, "file_offset": origin + fo,
                           "file_size": fs, "writable_executable": initial & 6 == 6, "offset": origin + pos})
        elif cmd in (0xC, 0x80000018, 0x8000001F) and length >= 24:
            start = struct.unpack_from(endian + "I", data, pos + 8)[0]
            if 24 <= start < length:
                name = data[pos + start:pos + length].split(b"\x00")[0].decode("utf-8", "replace")
                result.append({"kind": "dependency", "name": name, "offset": origin + pos})
        elif cmd == 0x80000028 and length >= 24:
            entry, stack = struct.unpack_from(endian + "QQ", data, pos + 8)
            result.append({"kind": "entry", "entry_offset": origin + entry, "stack_size": stack, "offset": origin + pos})
        pos += length
    return result


class MachoAnalyzer(BaseAnalyzer):
    name = "static.macho"
    handles = {"macho"}

    def run(self, sample, ctx):
        return [ctx.ev(source=self.name, artifact=row["kind"], operation="inspect", object=row,
                       details={"why": "Mach-O structural metadata; not runtime behavior"}, confidence=0.9,
                       locations=[EvidenceLocation(file_offset=row["offset"])]) for row in parse_macho(sample.data)]


def register(registry):
    registry.register(MachoAnalyzer())
