from ..context import CommandError
from ..plugin import Plugin


class WriteMem(Plugin):
    name = "writemem"
    aliases = (".writemem",)
    help = "save a range of memory to a file (uncaptured bytes become zeros)"

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("file", help="output file")
        parser.add_argument("address", help="start address expression")
        parser.add_argument("extent", metavar="L<size>|END", help="how many bytes (L<size>) or an end address")

    def run(self) -> None:
        start, length = self.ctx.parse_range(self.args.address, self.args.extent, 0, 1)
        if length <= 0:
            raise CommandError("give a size, e.g. writemem out.bin 2aed6000000 L?4db000")
        if length > 1 << 32:
            raise CommandError("refusing to write more than 4 GB")
        data = self.dump.read(start, length, pad=True)
        captured = self.dump.captured_bytes(start, start + length)
        with open(self.args.file, "wb") as f:
            f.write(data)
        note = f" ({length - captured:#x} uncaptured bytes written as zeros)" if captured < length else ""
        self.print(f"Wrote {length:#x} bytes from {self.ctx.fmt(start)} to {self.args.file}{note}")
