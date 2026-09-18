"""Bounded JAR/APK structure and code-string analysis, without extraction to disk."""

from __future__ import annotations

import io
import struct
import zipfile

from ...core.evidence import EvidenceLocation
from ..base import BaseAnalyzer
from .common import extract_iocs


def class_strings(data: bytes) -> list[str]:
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return []
    count, pos, index = struct.unpack_from(">H", data, 8)[0], 10, 1
    out = []
    sizes = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    while index < count and pos < len(data):
        tag = data[pos]
        pos += 1
        if tag == 1:
            if pos + 2 > len(data):
                break
            length = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            if pos + length > len(data):
                break
            out.append(data[pos:pos + length].decode("utf-8", "replace"))
            pos += length
        elif tag in sizes:
            pos += sizes[tag]
        else:
            break
        index += 2 if tag in (5, 6) else 1
    return out


def dex_strings(data: bytes) -> list[str]:
    if len(data) < 112 or not data.startswith(b"dex\n"):
        return []
    count, offset = struct.unpack_from("<II", data, 56)
    if count > 100000 or offset + count * 4 > len(data):
        raise ValueError("invalid DEX string table")
    out = []
    for i in range(count):
        pos = struct.unpack_from("<I", data, offset + i * 4)[0]
        for _ in range(5):  # bounded ULEB128 character count
            if pos >= len(data):
                break
            byte = data[pos]
            pos += 1
            if byte < 128:
                end = data.find(b"\x00", pos, min(pos + 4096, len(data)))
                if end >= pos:
                    out.append(data[pos:end].decode("utf-8", "replace"))
                break
    return out


class ContainerAnalyzer(BaseAnalyzer):
    name = "static.container"
    handles = {"jar", "apk"}

    def run(self, sample, ctx):
        items = []
        budget = 32 * 1024**2
        with zipfile.ZipFile(io.BytesIO(sample.data)) as archive:
            members = archive.infolist()
            if len(members) > 4096:
                raise ValueError("archive contains too many members")
            for member in members:
                if member.is_dir() or member.file_size > 8 * 1024**2 or member.file_size > budget:
                    continue
                name = member.filename
                if not name.endswith((".class", ".dex", ".xml", ".MF", ".RSA", ".SF")):
                    continue
                with archive.open(member) as fh:
                    data = fh.read(min(budget, 8 * 1024**2) + 1)
                if len(data) > min(budget, 8 * 1024**2):
                    raise ValueError("archive expansion limit exceeded")
                budget -= len(data)
                loc = EvidenceLocation(file_offset=member.header_offset, section=name)
                if name.endswith(".class"):
                    strings = class_strings(data)
                elif name.endswith(".dex"):
                    strings = dex_strings(data)
                else:
                    strings = [data.decode("utf-8", "replace")[:65536]]
                items.append(ctx.ev(source=self.name, artifact="file", operation="inspect",
                                    object={"member": name, "size": len(data)}, confidence=0.95,
                                    details={"strings": len(strings), "signature_verification": "not performed"}, locations=[loc]))
                joined = "\n".join(strings)
                for marker in ("java/lang/Runtime", "java/lang/ProcessBuilder", "DexClassLoader", "getDeviceId", "android.permission.READ_SMS", "android.permission.RECORD_AUDIO", "android.permission.REQUEST_INSTALL_PACKAGES"):
                    if marker in joined:
                        items.append(ctx.ev(source=self.name, artifact="api_call", operation="reference",
                                            object={"api": marker, "member": name}, confidence=0.5,
                                            details={"why": "code/manifest reference; execution and permission grants not established"}, locations=[loc]))
                for kind, value, confidence, risk in extract_iocs(joined)[:300]:
                    items.append(ctx.ev(source=self.name, artifact="string", operation="read",
                                        object={"kind": kind, "value": value}, confidence=confidence,
                                        details={"ioc": True, "false_positive_risk": risk, "member": name}, locations=[loc]))
        return items


def register(registry):
    registry.register(ContainerAnalyzer())
