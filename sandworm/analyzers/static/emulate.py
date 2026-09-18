"""Emulation-assisted unpacking (optional, Unicorn-backed).

Static unpacking can *detect* a packer (see ``unpack.py``) but cannot recover the
unpacked bytes — the code is only revealed when the unpacking stub runs. This
module bridges that gap **without a live detonation**: it emulates the PE entry
point in a Unicorn CPU with **no OS, no syscalls, no real memory** and watches for
the tell-tale behaviour of a packer stub — *writes into an executable region*,
i.e. the stub decompressing the real code into memory (self-modification).

It is deliberately conservative and safe:

* Only bounded, memory-only allocation/protection/copy API models are provided;
  no calls are forwarded to the host. Unknown imports fault. Every fault is caught.
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
    modeled_api_calls: list[str] = field(default_factory=list)


def _align_down(v: int) -> int:
    return v - (v % _PAGE)


def _align_up(v: int) -> int:
    return (v + _PAGE - 1) & ~(_PAGE - 1)


def emulate_unpack(data: bytes, headers: dict, *, imports: dict[int, str] | None = None) -> EmuResult | None:
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
        if s > 64 * 1024**2 or sum(ms for _, ms in mapped) + s > 256 * 1024**2:
            return
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

    # Model a small documented set of memory-only Win32 APIs. Unknown imports
    # still fault; no socket, filesystem, process or host OS APIs are forwarded.
    if imports is None:
        imports = {}
        try:
            import pefile
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:64]:
                for imp in entry.imports[:256]:
                    if imp.name:
                        imports[imp.address] = imp.name.decode("ascii", "replace")
            pe.close()
        except Exception:
            imports = {}
    arities = {"VirtualAlloc": 4, "VirtualAllocEx": 5, "VirtualProtect": 4,
               "VirtualProtectEx": 5, "memcpy": 3, "memmove": 3, "memset": 3,
               "RtlMoveMemory": 3, "Sleep": 1, "ExitProcess": 1}
    thunks: dict[int, str] = {}
    thunk_base = 0x70000000
    _map(thunk_base, 0x10000)
    api_calls: list[str] = []
    heap_next = [0x60000000]
    ptr_size = 8 if is64 else 4
    for index, (iat, name) in enumerate(list(imports.items())[:1024]):
        if name not in arities:
            continue
        address = thunk_base + index * 16
        try:
            mu.mem_write(iat, address.to_bytes(ptr_size, "little"))
            # x86 Win32 calls use stdcall; C runtime memory helpers use cdecl.
            cleanup = arities[name] * 4 if not is64 and name not in {"memcpy", "memmove", "memset"} else 0
            mu.mem_write(address, b"\xc2" + cleanup.to_bytes(2, "little") if cleanup else b"\xc3")
            thunks[address] = name
        except Exception:
            continue

    def _arguments(count: int) -> list[int]:
        sp = mu.reg_read(x86.UC_X86_REG_RSP if is64 else x86.UC_X86_REG_ESP)
        if is64:
            regs = [x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9]
            return [mu.reg_read(regs[i]) if i < 4 else int.from_bytes(mu.mem_read(sp + 40 + (i - 4) * 8, 8), "little") for i in range(count)]
        return [int.from_bytes(mu.mem_read(sp + 4 + i * 4, 4), "little") for i in range(count)]

    def _model_api(name: str) -> None:
        args = _arguments(arities[name])
        returned = 0
        if name.startswith("VirtualAlloc"):
            if name.endswith("Ex"):
                args = args[1:]
            requested, size, _, protection = args
            if 0 < size <= 16 * 1024**2:
                addr = requested or heap_next[0]
                _map(addr, size)
                if any(a <= addr and addr + size <= a + s for a, s in mapped):
                    returned = addr
                    heap_next[0] = _align_up(addr + size)
                    if protection & 0xF0:
                        exec_ranges.append((addr, addr + size))
        elif name.startswith("VirtualProtect"):
            if name.endswith("Ex"):
                args = args[1:]
            address, size, protection, old = args
            if 0 < size <= 16 * 1024**2 and any(a <= address and address + size <= a + s for a, s in mapped):
                if protection & 0xF0:
                    exec_ranges.append((address, address + size))
                if old:
                    mu.mem_write(old, (4).to_bytes(4, "little"))
                returned = 1
        elif name in {"memcpy", "memmove", "RtlMoveMemory", "memset"}:
            dest, source, size = args
            if size > 1024**2:
                mu.emu_stop()
                return
            content = bytes([source & 255]) * size if name == "memset" else bytes(mu.mem_read(source, size))
            mu.mem_write(dest, content)
            writes.append((dest, size))
            returned = dest
        elif name == "ExitProcess":
            mu.emu_stop()
        api_calls.append(name)
        mu.reg_write(x86.UC_X86_REG_RAX if is64 else x86.UC_X86_REG_EAX, returned)

    def _in_exec(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in exec_ranges)

    def _on_write(_mu, _access, address, size, _value, _user):  # noqa: ANN001
        if len(writes) < _MAX_INSTRUCTIONS:
            writes.append((address, size))

    counter = {"n": 0}

    def _on_code(_mu, _address, _size, _user):  # noqa: ANN001
        counter["n"] += 1
        if counter["n"] >= _MAX_INSTRUCTIONS:
            _mu.emu_stop()
        if _address in thunks:
            try:
                _model_api(thunks[_address])
            except Exception:
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
    writes = [(a, s) for a, s in writes if _in_exec(a)]
    ranges: list[tuple[int, int]] = []
    for address, size in sorted(writes):
        if ranges and address <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], address + size))
        else:
            ranges.append((address, address + size))
    for lo, hi in ranges:
        remaining = (1 << 20) - len(recovered)
        if remaining <= 0:
            break
        hi = min(hi, lo + remaining)
        try:
            recovered += bytes(mu.mem_read(lo, hi - lo))
            modified_regions.append((lo, hi - lo))
        except Exception:
            continue

    return EmuResult(
        unpacked_bytes=recovered,
        write_count=len(writes),
        self_modifying=bool(writes),
        instructions=counter["n"],
        regions=modified_regions,
        note="emulated entry point; writes into executable memory indicate an unpacking stub"
        if writes else "no self-modifying writes observed within the instruction budget",
        modeled_api_calls=api_calls,
    )
