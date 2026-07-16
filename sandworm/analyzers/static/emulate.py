"""Emulation-assisted unpacking (optional, Unicorn-backed).

Static unpacking can *detect* a packer (see ``unpack.py``) but cannot recover the
unpacked bytes — the code is only revealed when the unpacking stub runs. This
module bridges that gap **without a live detonation**: it emulates the PE entry
point in a Unicorn CPU with **no OS, no syscalls, no real memory** and watches for
the tell-tale behaviour of a packer stub — *writes into an executable region*,
i.e. the stub decompressing the real code into memory (self-modification).

It is deliberately conservative and safe:

* No imports/APIs are provided, so the sample cannot call out to anything; the
  emulation runs until it faults, hits the instruction budget, or the stub jumps
  somewhere unmapped. Every fault is caught.
* Execution is bounded (instruction count + mapped memory only). This is CPU
  emulation of the sample's own bytes, not execution on the host — it needs no
  isolation gate, exactly like the recorded-report replay path.
* When Unicorn is absent the whole module no-ops (``emulate_unpack`` returns
  ``None``) and the static ``unpack.py`` "requires emulation" layer stands.

The recovered bytes are surfaced as a **decode layer** (parent → child of the
packed layer) so downstream IOC/behaviour extraction can read the real code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_MAX_INSTRUCTIONS = 200_000
_PAGE = 0x1000
_STACK_SIZE = 0x10000


def unicorn_available() -> bool:
    try:  # pragma: no cover - trivial import probe
        import unicorn  # noqa: F401

        return True
    except ImportError:
        return False


@dataclass
class EmuResult:
    unpacked_bytes: bytes                 # concatenated bytes written into exec regions
    write_count: int                      # number of writes into executable memory
    self_modifying: bool                  # did the stub write into executable memory?
    instructions: int                     # instructions actually executed
    regions: list[tuple[int, int]] = field(default_factory=list)  # (addr, size) modified exec ranges
    note: str = ""


def _align_down(v: int) -> int:
    return v - (v % _PAGE)


def _align_up(v: int) -> int:
    return (v + _PAGE - 1) & ~(_PAGE - 1)


def emulate_unpack(data: bytes, headers: dict) -> EmuResult | None:
    """Emulate the PE entry point and report self-modifying (unpacking) writes.

    Returns ``None`` when Unicorn is unavailable or the PE lacks the structure
    needed to emulate (no entry point / sections). Never raises — any emulation
    fault is caught and reflected in the result."""
    if not unicorn_available():
        return None
    sections = headers.get("sections") or []
    entry_rva = headers.get("entry_rva") or 0
    base = headers.get("image_base") or 0x400000
    if not sections or not entry_rva:
        return None

    import unicorn as uc
    import unicorn.x86_const as x86

    is64 = bool(headers.get("pe32_plus"))
    mode = uc.UC_MODE_64 if is64 else uc.UC_MODE_32
    try:
        mu = uc.Uc(uc.UC_ARCH_X86, mode)
    except Exception:
        return None

    # Executable-section address ranges (image_base + vaddr .. +vsize) — writes
    # into these are the "unpacking" signal.
    _SCN_EXEC = 0x20000000
    exec_ranges: list[tuple[int, int]] = []

    # Map the image: one padded region per section at its virtual address.
    mapped: list[tuple[int, int]] = []

    def _map(addr: int, size: int) -> None:
        a = _align_down(addr)
        s = _align_up(size + (addr - a))
        for ma, ms in mapped:
            if a < ma + ms and ma < a + s:  # overlaps an existing mapping
                return
        try:
            mu.mem_map(a, s)
            mapped.append((a, s))
        except Exception:
            pass

    try:
        for sec in sections:
            vaddr = sec.get("vaddr") or 0
            vsize = max(sec.get("vsize") or 0, sec.get("raw_size") or 0, _PAGE)
            addr = base + vaddr
            _map(addr, vsize)
            raw = data[sec["raw_ptr"]: sec["raw_ptr"] + sec["raw_size"]] if sec.get("raw_ptr") else b""
            if raw:
                try:
                    mu.mem_write(addr, raw)
                except Exception:
                    pass
            if sec.get("characteristics", 0) & _SCN_EXEC:
                exec_ranges.append((addr, base + vaddr + vsize))

        # Stack, well away from the image.
        stack = 0x200000 if base != 0x200000 else 0x300000
        _map(stack, _STACK_SIZE)
        sp = stack + _STACK_SIZE // 2
        mu.reg_write(x86.UC_X86_REG_RSP if is64 else x86.UC_X86_REG_ESP, sp)
    except Exception:
        return None

    writes: list[tuple[int, int]] = []

    def _in_exec(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in exec_ranges)

    def _on_write(_mu, _access, address, size, _value, _user):  # noqa: ANN001
        if _in_exec(address):
            writes.append((address, size))

    counter = {"n": 0}

    def _on_code(_mu, _address, _size, _user):  # noqa: ANN001
        counter["n"] += 1
        if counter["n"] >= _MAX_INSTRUCTIONS:
            _mu.emu_stop()

    try:
        mu.hook_add(uc.UC_HOOK_MEM_WRITE, _on_write)
        mu.hook_add(uc.UC_HOOK_CODE, _on_code)
    except Exception:
        return None

    start = base + entry_rva
    try:
        mu.emu_start(start, start + 0x100000, count=_MAX_INSTRUCTIONS)
    except Exception:
        # A fault is expected (no APIs/imports); we keep whatever writes occurred.
        pass

    # Collect the modified executable bytes as the recovered layer.
    recovered = b""
    modified_regions: list[tuple[int, int]] = []
    if writes:
        lo = min(a for a, _ in writes)
        hi = max(a + s for a, s in writes)
        hi = min(hi, lo + (1 << 20))  # cap the dump at 1 MiB
        try:
            recovered = bytes(mu.mem_read(lo, hi - lo))
            modified_regions.append((lo, hi - lo))
        except Exception:
            recovered = b""

    return EmuResult(
        unpacked_bytes=recovered,
        write_count=len(writes),
        self_modifying=bool(writes),
        instructions=counter["n"],
        regions=modified_regions,
        note="emulated entry point; writes into executable memory indicate an unpacking stub"
        if writes else "no self-modifying writes observed within the instruction budget",
    )
