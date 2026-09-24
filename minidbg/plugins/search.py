import struct

from ..context import CommandError
from ..plugin import Plugin

MODES = [("-a", "a", "ASCII text"), ("-u", "u", "UTF-16 text"), ("-b", "b", "hex bytes (the default)"),
         ("-w", "w", "16-bit values"), ("-d", "d", "32-bit values"), ("-q", "q", "64-bit values")]


class Search(Plugin):
    name = "s"
    aliases = ("search",)
    help = "search memory for text, bytes or values"

    @classmethod
    def add_arguments(cls, parser):
        group = parser.add_mutually_exclusive_group()
        for flag, mode, text in MODES:
            group.add_argument(flag, dest="mode", action="store_const", const=mode, help=text)
        parser.set_defaults(mode="b")
        parser.add_argument("pattern", nargs="+", help="what to find, e.g. -a 'flag{'  or  -b 4d 5a 90 00")
        parser.add_argument("-r", "--range", metavar="RANGE",
                            help="where to look: 'START L<len>', 'START END' or a module name "
                                 "(default: all captured memory)")
        parser.add_argument("-n", "--max-hits", type=int, default=1000, metavar="N",
                            help="stop after N matches (default 1000)")

    def pattern_bytes(self) -> bytes:
        mode, tokens = self.args.mode, self.args.pattern
        if mode == "a":
            return " ".join(tokens).encode("utf-8")
        if mode == "u":
            return " ".join(tokens).encode("utf-16-le")
        if mode == "b":
            out = bytearray()
            for token in tokens:
                token = token.lower().removeprefix("0x")
                try:
                    out += bytes.fromhex(token if len(token) % 2 == 0 else "0" + token)
                except ValueError:
                    raise CommandError(f"bad byte value '{token}'") from None
            return bytes(out)
        fmt = {"w": "<H", "d": "<I", "q": "<Q"}[mode]
        mask = (1 << (struct.calcsize(fmt) * 8)) - 1
        return b"".join(struct.pack(fmt, self.ctx.evaluate(t) & mask) for t in tokens)

    def search_range(self) -> tuple[int, int]:
        if not self.args.range:
            return 0, 1 << 64
        tokens = self.args.range.split()
        if len(tokens) == 1:
            module = self.dump.module_by_name(tokens[0])
            if module is None:
                raise CommandError("--range needs 'START L<len>', 'START END' or a module name")
            return module.base, module.end
        if len(tokens) != 2:
            raise CommandError("--range needs 'START L<len>', 'START END' or a module name")
        start, length = self.ctx.parse_range(tokens[0], tokens[1], 0, 1)
        return start, start + length

    def run(self) -> None:
        pattern = self.pattern_bytes()
        start, end = self.search_range()
        hits = 0
        for hit in self.dump.search(pattern, start, end):
            values = self.dump.read_partial(hit, 16)
            hexes = " ".join("??" if b is None else f"{b:02x}" for b in values)
            text = "".join("?" if b is None else (chr(b) if 0x20 <= b < 0x7F else ".") for b in values)
            symbol = self.dump.symbolize(hit)
            self.print(f"{self.ctx.fmt(hit)}  {hexes}  {text}" + (f"  {symbol}" if symbol else ""))
            hits += 1
            if hits >= self.args.max_hits:
                self.print(f"... stopped after {hits} matches (raise it with -n)")
                break
        if hits == 0:
            self.print("no matches")
