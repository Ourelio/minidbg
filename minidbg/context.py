from __future__ import annotations

import sys
from typing import Optional, TextIO

from . import constants as C
from .minidump import MiniDump, Thread

MASK64 = (1 << 64) - 1


class CommandError(Exception):
    pass


def human_size(n: int) -> str:
    for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("kB", 1 << 10)):
        if n >= div:
            return f"{n / div:8.3f} {unit}"
    return f"{n:8d} B "


def fmt_time(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "-"


def windows_name(major: int, minor: int, build: int) -> str:
    if major == 10:
        return "Windows 11" if build >= 22000 else "Windows 10"
    return {(6, 3): "Windows 8.1", (6, 2): "Windows 8", (6, 1): "Windows 7", (6, 0): "Windows Vista",
            (5, 2): "Windows Server 2003 / XP x64", (5, 1): "Windows XP"}.get((major, minor), "Windows")


class _Expression:
    """WinDbg-style expressions: hex, 0n decimal, + and -, poi(), @reg, @$peb, module, module!export."""

    def __init__(self, ctx: Context, text: str):
        self.ctx = ctx
        self.text = text.replace("`", "")
        self.pos = 0

    def parse(self) -> int:
        value = self._sum()
        self._skip()
        if self.pos != len(self.text):
            raise CommandError(f"couldn't parse expression '{self.text}'")
        return value & MASK64

    def _skip(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def _expect(self, ch: str) -> None:
        self._skip()
        if self.text[self.pos:self.pos + 1] != ch:
            raise CommandError(f"expected '{ch}' in '{self.text}'")
        self.pos += 1

    def _sum(self) -> int:
        value = self._term()
        while True:
            self._skip()
            op = self.text[self.pos:self.pos + 1]
            if op not in ("+", "-") or not op:
                return value
            self.pos += 1
            rhs = self._term()
            value = value + rhs if op == "+" else value - rhs

    def _term(self) -> int:
        self._skip()
        text = self.text
        if text[self.pos:self.pos + 4].lower() == "poi(":
            self.pos += 4
            inner = self._sum()
            self._expect(")")
            return self.ctx.dump.read_pointer(inner & MASK64)
        if text[self.pos:self.pos + 1] == "(":
            self.pos += 1
            inner = self._sum()
            self._expect(")")
            return inner
        if text[self.pos:self.pos + 1] == "-":
            self.pos += 1
            return -self._term()
        start = self.pos
        while self.pos < len(text) and text[self.pos] not in "+-() \t":
            self.pos += 1
        atom = text[start:self.pos]
        if not atom:
            raise CommandError(f"expected a value in '{text}'")
        return self.ctx.resolve_atom(atom)


class Context:
    """What every plugin gets: the dump, the output, the selected thread and address helpers."""

    def __init__(self, dump: MiniDump, out: TextIO = sys.stdout, thread_index: Optional[int] = None,
                 thread_id: Optional[int] = None, exception_context: bool = False):
        self.dump = dump
        self.out = out
        self.thread_index = self._pick_thread(thread_index, thread_id)
        self.context_override: Optional[dict[str, int]] = None
        if exception_context:
            exc = dump.exception
            if exc is None:
                raise CommandError("--ecxr needs a crash dump with an exception stream; this dump has none")
            if exc.context is None:
                raise CommandError("the exception stream has no usable register context")
            self.context_override = exc.context

    def _pick_thread(self, index: Optional[int], thread_id: Optional[int]) -> int:
        threads = self.dump.threads
        if thread_id is not None:
            thread = self.dump.thread_by_id(thread_id)
            if thread is None:
                raise CommandError(f"no thread with id {thread_id:#x}")
            return thread.index
        if index is not None:
            if not 0 <= index < len(threads):
                raise CommandError(f"no thread {index} (this dump has {len(threads)} threads)")
            return index
        if self.dump.exception is not None:
            thread = self.dump.thread_by_id(self.dump.exception.thread_id)
            if thread is not None:
                return thread.index
        return 0

    def print(self, text: str = "") -> None:
        self.out.write(text + "\n")

    @property
    def thread(self) -> Optional[Thread]:
        return self.dump.threads[self.thread_index] if self.dump.threads else None

    @property
    def registers(self) -> dict[str, int]:
        if self.context_override is not None:
            return self.context_override
        thread = self.thread
        return thread.context if thread is not None and thread.context else {}

    def fmt(self, value: int) -> str:
        if self.dump.pointer_size == 8:
            s = f"{value & MASK64:016x}"
            return f"{s[:8]}`{s[8:]}"
        return f"{value & 0xFFFFFFFF:08x}"

    def describe(self, address: int) -> str:
        """Address plus module!export+offset when it points into a module."""
        symbol = self.dump.symbolize(address)
        return f"{self.fmt(address)} ({symbol})" if symbol else self.fmt(address)

    def resolve_atom(self, atom: str) -> int:
        lowered = atom.lower()
        if lowered.startswith("@") or lowered.startswith("$"):
            name = lowered.lstrip("@")
            regs = self.registers
            if name in regs:
                return regs[name]
            arch = self.dump.architecture
            # WinDbg spells these @$peb etc.; the $ is optional here because shells expand $peb
            pseudo = {
                "peb": self.dump.peb_address,
                "teb": self.thread.teb if self.thread else None,
                "ip": regs.get(C.INSTRUCTION_POINTER.get(arch, "")),
                "csp": regs.get(C.STACK_POINTER.get(arch, "")),
            }
            value = pseudo.get(name.lstrip("$"))
            if value is not None:
                return value
            raise CommandError(f"unknown or unavailable register '{atom}'")
        if "!" in atom:
            module_name, _, export = atom.partition("!")
            address = self.dump.resolve_symbol(module_name, export)
            if address is None:
                raise CommandError(f"couldn't resolve symbol '{atom}' (only exports are known)")
            return address
        module = self.dump.module_by_name(atom)
        if module is not None:
            return module.base
        try:
            if lowered.startswith("0n"):
                return int(lowered[2:], 10)
            return int(lowered[2:] if lowered.startswith("0x") else lowered, 16)
        except ValueError:
            raise CommandError(f"couldn't resolve '{atom}'") from None

    def evaluate(self, text: str) -> int:
        return _Expression(self, text).parse()

    def parse_range(self, start_text: str, extent: Optional[str], default_count: int, unit: int,
                    allow_end: bool = True) -> tuple[int, int]:
        """START plus optional 'L<count>', 'L?<count>' or END -> (start, length in bytes)."""
        start = self.evaluate(start_text)
        if extent is None:
            return start, default_count * unit
        if extent[:1] in ("l", "L") and len(extent) > 1:
            spec = extent[1:]
            return start, self.evaluate(spec[1:] if spec.startswith("?") else spec) * unit
        if not allow_end:
            raise CommandError(f"expected L<count> after the address, got '{extent}'")
        end = self.evaluate(extent)
        if end <= start:
            raise CommandError("range end must be above the start address")
        return start, end - start

    def thread_line(self, thread: Thread) -> str:
        exception_thread = self.dump.exception is not None and self.dump.exception.thread_id == thread.thread_id
        marker = "." if thread.index == self.thread_index else ("#" if exception_thread else " ")
        pid = self.dump.process_id or 0
        parts = [f"{marker}{thread.index:3d}  Id: {pid:x}.{thread.thread_id:x} Suspend: {thread.suspend_count} "
                 f"Teb: {self.fmt(thread.teb)}"]
        ip_name = C.INSTRUCTION_POINTER.get(self.dump.architecture)
        if thread.context and ip_name in thread.context:
            ip = thread.context[ip_name]
            parts.append(f"Ip: {self.dump.symbolize(ip) or self.fmt(ip)}")
        if thread.info and thread.info.start_address:
            start = thread.info.start_address
            parts.append(f"Start: {self.dump.symbolize(start) or self.fmt(start) + ' (not in any module)'}")
        if thread.name:
            parts.append(f'"{thread.name}"')
        return "  ".join(parts)
