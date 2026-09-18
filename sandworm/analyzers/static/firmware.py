"""UEFI firmware-volume and FFS inventory. Does not infer bootkit infection."""

from __future__ import annotations

import struct
import uuid

from ...core.evidence import EvidenceLocation
from ..base import BaseAnalyzer


def firmware_volumes(data: bytes) -> list[dict]:
    result: list[dict] = []
    search = 0
    while len(result) < 256:
        magic = data.find(b"_FVH", search)
        if magic < 0:
            break
        search = magic + 4
        start = magic - 40
        if start < 0 or start + 56 > len(data):
            continue
        length = struct.unpack_from("<Q", data, start + 32)[0]
        header_len = struct.unpack_from("<H", data, start + 48)[0]
        if header_len < 56 or header_len % 2 or length < header_len or start + length > len(data):
            continue
        words = struct.unpack_from("<" + "H" * (header_len // 2), data, start)
        row = {"offset": start, "size": length, "header_checksum_valid": sum(words) & 0xFFFF == 0,
               "filesystem_guid": str(uuid.UUID(bytes_le=data[start + 16:start + 32])), "files": []}
        pos = (start + header_len + 7) & ~7
        while pos + 24 <= start + length and len(row["files"]) < 4096:
            if data[pos:pos + 24] in (b"\xff" * 24, b"\x00" * 24):
                break
            size = int.from_bytes(data[pos + 20:pos + 23], "little")
            if size < 24 or size == 0xFFFFFF or pos + size > start + length:
                break
            row["files"].append({"guid": str(uuid.UUID(bytes_le=data[pos:pos + 16])), "type": data[pos + 18],
                                 "offset": pos, "size": size, "state": data[pos + 23]})
            pos = (pos + size + 7) & ~7
        result.append(row)
    return result


class FirmwareAnalyzer(BaseAnalyzer):
    name = "static.firmware"
    handles = {"firmware"}

    def run(self, sample, ctx):
        return [ctx.ev(source=self.name, artifact="firmware_volume", operation="inspect", object=row,
                       details={"why": "UEFI volume inventory; authenticity, compressed modules and SMM behavior require additional analysis"},
                       confidence=0.9, locations=[EvidenceLocation(file_offset=row["offset"], size=row["size"])])
                for row in firmware_volumes(sample.data)]


def register(registry):
    registry.register(FirmwareAnalyzer())
