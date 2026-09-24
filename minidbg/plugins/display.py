from typing import Optional

from ..context import CommandError
from ..minidump import MemoryNotCaptured
from ..plugin import Plugin

MAX_DISPLAY = 16 * 1024 * 1024


class _Display(Plugin):
    unit = 1
    per_line = 16
    default_count = 0x80
    allow_end = True

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("address", help="start address expression, e.g. 7ffe0000, @rsp, ntdll+1000, poi(@$peb+20)")
        parser.add_argument("extent", nargs="?", metavar="L<count>" + ("|END" if cls.allow_end else ""),
                            help=f"how much to show: L<count> in {cls.unit}-byte units"
                                 + (", or an end address" if cls.allow_end else "")
                                 + f" (default {cls.default_count:#x} units)")

    def run(self) -> None:
        start, length = self.ctx.parse_range(self.args.address, self.args.extent, self.default_count, self.unit,
                                             allow_end=self.allow_end)
        if length > MAX_DISPLAY:
            raise CommandError(f"{length:#x} bytes is too much to display; use writemem to save it to a file")
        self.show(start, length)

    def show(self, start: int, length: int) -> None:
        values = self.dump.read_partial(start, length)
        for line_off in range(0, len(values), self.unit * self.per_line):
            items = []
            for off in range(line_off, min(line_off + self.unit * self.per_line, len(values)), self.unit):
                items.append(self.format_unit(values[off:off + self.unit]))
            self.print(f"{self.ctx.fmt(start + line_off)}  " + " ".join(items))

    def format_unit(self, chunk: list[Optional[int]]) -> str:
        width = self.unit * 2 + (1 if self.unit == 8 else 0)
        if len(chunk) < self.unit or None in chunk:
            return "?" * width
        s = f"{int.from_bytes(bytes(chunk), 'little'):0{self.unit * 2}x}"
        return f"{s[:8]}`{s[8:]}" if self.unit == 8 else s


class Db(_Display):
    name = "db"
    help = "memory as bytes and ASCII"

    def show(self, start: int, length: int) -> None:
        values = self.dump.read_partial(start, length)
        for off in range(0, len(values), 16):
            chunk = values[off:off + 16]
            hexes = ["??" if b is None else f"{b:02x}" for b in chunk]
            hex_part = " ".join(hexes[:8]) + ("-" + " ".join(hexes[8:]) if len(hexes) > 8 else "")
            text = "".join("?" if b is None else (chr(b) if 0x20 <= b < 0x7F else ".") for b in chunk)
            self.print(f"{self.ctx.fmt(start + off)}  {hex_part:<47}  {text}")


class Dw(_Display):
    name = "dw"
    help = "memory as 16-bit words"
    unit, per_line, default_count = 2, 8, 0x40


class Dd(_Display):
    name = "dd"
    help = "memory as 32-bit dwords"
    unit, per_line, default_count = 4, 4, 0x20


class Dq(_Display):
    name = "dq"
    help = "memory as 64-bit qwords"
    unit, per_line, default_count = 8, 2, 0x10


class Dps(_Display):
    name = "dps"
    aliases = ("dqs", "dds")
    help = "pointer-sized values, each followed by module!export if it points into a module"
    unit, per_line, default_count = 8, 1, 0x10

    def run(self) -> None:
        self.unit = self.dump.pointer_size
        super().run()

    def show(self, start: int, length: int) -> None:
        ps = self.unit
        values = self.dump.read_partial(start, length)
        for off in range(0, len(values) - ps + 1, ps):
            chunk = values[off:off + ps]
            if None in chunk:
                self.print(f"{self.ctx.fmt(start + off)}  {'?' * len(self.ctx.fmt(0))}")
                continue
            value = int.from_bytes(bytes(chunk), "little")
            symbol = self.dump.symbolize(value)
            self.print(f"{self.ctx.fmt(start + off)}  {self.ctx.fmt(value)}" + (f"  {symbol}" if symbol else ""))


class Da(_Display):
    name = "da"
    help = "an ASCII string (L<count> = maximum bytes)"
    unit, default_count, allow_end = 1, 0x100, False
    wide = False

    def show(self, start: int, length: int) -> None:
        if self.dump.find_range(start) is None:
            raise MemoryNotCaptured(start)
        self.print(f'{self.ctx.fmt(start)}  "{self.dump.read_cstring(start, length, wide=self.wide)}"')


class Du(Da):
    name = "du"
    help = "a UTF-16 string (L<count> = maximum bytes)"
    default_count = 0x200
    wide = True
