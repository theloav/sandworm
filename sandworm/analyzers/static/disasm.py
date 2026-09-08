"""Bounded, address-aware native-code discovery using optional Capstone.

The analyzer starts at the binary entry point, follows direct calls into
executable regions, identifies basic-block boundaries, and emits functions and
call edges with exact file/RVA/VA coordinates. It never executes sample bytes.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ...core.evidence import EvidenceItem, EvidenceLocation
from ...core.sample import Sample
from ..base import BaseAnalyzer, Context
from .elf import _PF_X, _PT_LOAD, parse_elf_headers
from .pe import _SCN_MEM_EXECUTE, parse_pe_headers

_MAX_FUNCTIONS = 256
_MAX_INSTRUCTIONS = 8192
_MAX_FUNCTION_BYTES = 0x4000


def capstone_available() -> bool:
    try:
        import capstone  # noqa: F401

        return True
    except ImportError:
        return False


@dataclass(frozen=True)
class CodeRegion:
    name: str
    file_offset: int
    virtual_address: int
    data: bytes
    rva: int | None = None

    @property
    def end(self) -> int:
        return self.virtual_address + len(self.data)

    def contains(self, address: int) -> bool:
        return self.virtual_address <= address < self.end

    def location(self, address: int, *, size: int | None = None) -> EvidenceLocation:
        delta = address - self.virtual_address
        return EvidenceLocation(
            file_offset=self.file_offset + delta,
            rva=self.rva + delta if self.rva is not None else None,
            virtual_address=address,
            section=self.name,
            instruction_address=address,
            size=size,
        )


@dataclass(frozen=True)
class BinaryLayout:
    format: str
    architecture: str
    bits: int
    endian: str
    entrypoint: int
    regions: tuple[CodeRegion, ...]

    def region_for(self, address: int) -> CodeRegion | None:
        return next((region for region in self.regions if region.contains(address)), None)


@dataclass(frozen=True)
class Instruction:
    address: int
    size: int
    mnemonic: str
    operands: str
    location: EvidenceLocation


@dataclass(frozen=True)
class Function:
    address: int
    name: str
    instructions: tuple[Instruction, ...]
    basic_blocks: tuple[int, ...]

    @property
    def size(self) -> int:
        if not self.instructions:
            return 0
        last = self.instructions[-1]
        return last.address + last.size - self.address


@dataclass(frozen=True)
class CallEdge:
    caller: int
    callee: int
    callsite: int
    location: EvidenceLocation


@dataclass(frozen=True)
class Disassembly:
    layout: BinaryLayout
    functions: tuple[Function, ...] = field(default_factory=tuple)
    calls: tuple[CallEdge, ...] = field(default_factory=tuple)

    @property
    def instruction_count(self) -> int:
        return sum(len(function.instructions) for function in self.functions)


def _bounded_region(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0 or offset >= len(data):
        return b""
    return data[offset:min(len(data), offset + size)]


def pe_layout(data: bytes) -> BinaryLayout | None:
    headers = parse_pe_headers(data)
    if not headers or not headers.get("entry_rva"):
        return None
    machine = headers["machine"]
    architectures = {0x14C: ("x86", 32), 0x8664: ("x86", 64), 0xAA64: ("arm64", 64)}
    architecture = architectures.get(machine)
    if architecture is None:
        return None
    image_base = int(headers.get("image_base") or 0)
    regions: list[CodeRegion] = []
    for section in headers["sections"]:
        if not section["characteristics"] & _SCN_MEM_EXECUTE:
            continue
        raw = _bounded_region(data, section["raw_ptr"], section["raw_size"])
        if raw:
            regions.append(
                CodeRegion(
                    name=section["name"] or "<unnamed>",
                    file_offset=section["raw_ptr"],
                    virtual_address=image_base + section["vaddr"],
                    rva=section["vaddr"],
                    data=raw,
                )
            )
    entrypoint = image_base + int(headers["entry_rva"])
    if not any(region.contains(entrypoint) for region in regions):
        return None
    return BinaryLayout(
        format="PE",
        architecture=architecture[0],
        bits=architecture[1],
        endian="little",
        entrypoint=entrypoint,
        regions=tuple(regions),
    )


def elf_layout(data: bytes) -> BinaryLayout | None:
    headers = parse_elf_headers(data)
    if not headers or not headers.get("entry_va"):
        return None
    machine = headers["machine"]
    architectures = {
        3: ("x86", 32),
        62: ("x86", 64),
        40: ("arm", 32),
        183: ("arm64", 64),
    }
    architecture = architectures.get(machine)
    if architecture is None:
        return None
    regions: list[CodeRegion] = []
    for index, segment in enumerate(headers["segments"]):
        if segment["type"] != _PT_LOAD or not segment["flags"] & _PF_X:
            continue
        raw = _bounded_region(data, int(segment["offset"]), int(segment["filesz"]))
        if raw:
            regions.append(
                CodeRegion(
                    name=f"PT_LOAD[{index}]",
                    file_offset=int(segment["offset"]),
                    virtual_address=int(segment["vaddr"]),
                    data=raw,
                )
            )
    entrypoint = int(headers["entry_va"])
    if not any(region.contains(entrypoint) for region in regions):
        return None
    return BinaryLayout(
        format="ELF",
        architecture=architecture[0],
        bits=architecture[1],
        endian=headers["endian"],
        entrypoint=entrypoint,
        regions=tuple(regions),
    )


def layout_for(sample: Sample) -> BinaryLayout | None:
    if sample.format_hint == "pe":
        return pe_layout(sample.data)
    if sample.format_hint == "elf":
        return elf_layout(sample.data)
    return None


def _capstone_engine(layout: BinaryLayout):
    import capstone

    if layout.architecture == "x86":
        mode = capstone.CS_MODE_64 if layout.bits == 64 else capstone.CS_MODE_32
        engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
    elif layout.architecture == "arm":
        endian = capstone.CS_MODE_BIG_ENDIAN if layout.endian == "big" else capstone.CS_MODE_LITTLE_ENDIAN
        engine = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | endian)
    elif layout.architecture == "arm64":
        endian = capstone.CS_MODE_BIG_ENDIAN if layout.endian == "big" else capstone.CS_MODE_LITTLE_ENDIAN
        engine = capstone.Cs(capstone.CS_ARCH_ARM64, endian)
    else:  # pragma: no cover - layouts reject unsupported architectures
        return None
    engine.detail = True
    return engine


def discover(sample: Sample) -> Disassembly | None:
    """Recursively discover entry-reachable functions and direct call edges."""
    if not capstone_available():
        return None
    layout = layout_for(sample)
    if layout is None:
        return None
    import capstone

    engine = _capstone_engine(layout)
    if engine is None:
        return None

    queued = deque([layout.entrypoint])
    seen_functions: set[int] = set()
    claimed_instructions: set[int] = set()
    functions: list[Function] = []
    calls: dict[tuple[int, int, int], CallEdge] = {}
    total_instructions = 0

    while queued and len(functions) < _MAX_FUNCTIONS and total_instructions < _MAX_INSTRUCTIONS:
        start = queued.popleft()
        if start in seen_functions:
            continue
        region = layout.region_for(start)
        if region is None:
            continue
        seen_functions.add(start)
        instructions: list[Instruction] = []
        basic_blocks: set[int] = {start}
        block_queue = deque([start])
        local_instructions: set[int] = set()

        while block_queue and total_instructions < _MAX_INSTRUCTIONS:
            block_start = block_queue.popleft()
            block_region = layout.region_for(block_start)
            if block_region is None or block_start in local_instructions:
                continue
            delta = block_start - block_region.virtual_address
            code = block_region.data[delta:delta + _MAX_FUNCTION_BYTES]

            for decoded in engine.disasm(
                code,
                block_start,
                count=_MAX_INSTRUCTIONS - total_instructions,
            ):
                if decoded.address in local_instructions or decoded.address in claimed_instructions:
                    break
                local_instructions.add(decoded.address)
                total_instructions += 1
                location = block_region.location(decoded.address, size=decoded.size)
                instructions.append(
                    Instruction(
                        address=decoded.address,
                        size=decoded.size,
                        mnemonic=decoded.mnemonic,
                        operands=decoded.op_str,
                        location=location,
                    )
                )

                target = None
                if decoded.operands and decoded.operands[0].type == capstone.CS_OP_IMM:
                    target = int(decoded.operands[0].imm)
                if decoded.group(capstone.CS_GRP_CALL) and target is not None:
                    calls[(start, target, decoded.address)] = CallEdge(
                        caller=start,
                        callee=target,
                        callsite=decoded.address,
                        location=location,
                    )
                    if layout.region_for(target) is not None and target not in seen_functions:
                        queued.append(target)
                if decoded.group(capstone.CS_GRP_JUMP):
                    fallthrough = decoded.address + decoded.size
                    unconditional = decoded.mnemonic.lower() in {"jmp", "b", "br"}
                    if target is not None and layout.region_for(target) is not None:
                        basic_blocks.add(target)
                        block_queue.append(target)
                    if not unconditional and layout.region_for(fallthrough) is not None:
                        basic_blocks.add(fallthrough)
                    if unconditional:
                        break
                if decoded.group(capstone.CS_GRP_RET):
                    break
                if total_instructions >= _MAX_INSTRUCTIONS:
                    break

        if instructions:
            instructions.sort(key=lambda instruction: instruction.address)
            claimed_instructions.update(local_instructions)
            name = "entry" if start == layout.entrypoint else f"sub_{start:x}"
            functions.append(
                Function(
                    address=start,
                    name=name,
                    instructions=tuple(instructions),
                    basic_blocks=tuple(sorted(basic_blocks)),
                )
            )

    return Disassembly(layout=layout, functions=tuple(functions), calls=tuple(calls.values()))


class DisassemblyAnalyzer(BaseAnalyzer):
    name = "static.disasm"
    handles = {"pe", "elf"}
    requires_isolation = False

    def run(self, sample: Sample, ctx: Context) -> list[EvidenceItem]:
        result = discover(sample)
        if result is None:
            return []
        ref = f"sample:{sample.sha256}"
        function_names = {function.address: function.name for function in result.functions}
        entry_region = result.layout.region_for(result.layout.entrypoint)
        if entry_region is None:  # pragma: no cover - layout validates this
            return []

        items: list[EvidenceItem] = [
            ctx.ev(
                source=self.name,
                artifact="module",
                operation="read",
                subject={"analyzer": self.name},
                object={"analysis": "disassembly", "entrypoint": hex(result.layout.entrypoint)},
                details={
                    "format": result.layout.format,
                    "architecture": result.layout.architecture,
                    "bits": result.layout.bits,
                    "function_count": len(result.functions),
                    "call_count": len(result.calls),
                    "instruction_count": result.instruction_count,
                    "engine": "capstone",
                },
                confidence=0.95,
                evidence_refs=[ref],
                locations=[entry_region.location(result.layout.entrypoint)],
            )
        ]
        for function in result.functions:
            first = function.instructions[0]
            location = first.location.model_copy(update={"function": function.name})
            items.append(
                ctx.ev(
                    source=self.name,
                    artifact="function",
                    operation="read",
                    subject={"analyzer": self.name},
                    object={"function": function.name, "address": hex(function.address)},
                    details={
                        "size": function.size,
                        "instruction_count": len(function.instructions),
                        "basic_block_count": len(function.basic_blocks),
                        "preview": [
                            {
                                "address": hex(instruction.address),
                                "mnemonic": instruction.mnemonic,
                                "operands": instruction.operands,
                            }
                            for instruction in function.instructions[:24]
                        ],
                    },
                    confidence=0.9,
                    evidence_refs=[ref],
                    locations=[location],
                )
            )
        for call in result.calls:
            caller = function_names.get(call.caller, f"sub_{call.caller:x}")
            callee = function_names.get(call.callee, f"sub_{call.callee:x}")
            location = call.location.model_copy(update={"function": caller})
            items.append(
                ctx.ev(
                    source=self.name,
                    artifact="call",
                    operation="call",
                    subject={"function": caller, "address": hex(call.caller)},
                    object={"function": callee, "address": hex(call.callee)},
                    details={"callsite": hex(call.callsite), "direct": True},
                    confidence=0.95,
                    evidence_refs=[ref],
                    locations=[location],
                )
            )
        return items


def register(registry) -> None:
    registry.register(DisassemblyAnalyzer())
