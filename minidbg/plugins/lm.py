import fnmatch

from ..context import fmt_time
from ..minidump import time_t_to_datetime
from ..plugin import Plugin


class Lm(Plugin):
    name = "lm"
    help = "loaded and unloaded modules (DLLs and the EXE)"

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("pattern", nargs="?", help="only modules whose short name matches, e.g. 'kernel*'")
        parser.add_argument("-v", "--verbose", action="store_true",
                            help="path, timestamp, checksum, versions and PDB for each module")

    def run(self) -> None:
        pattern = self.args.pattern.lower() if self.args.pattern else None

        def wanted(name: str) -> bool:
            return pattern is None or fnmatch.fnmatch(name.lower(), pattern)

        ctx = self.ctx
        self.print(f"{'start':<17} {'end':<17}   module name")
        for m in self.dump.modules:
            if not wanted(m.name):
                continue
            if not self.args.verbose:
                self.print(f"{ctx.fmt(m.base)} {ctx.fmt(m.end)}   {m.name:<24} {m.file_version or '':<18} {m.path}")
                continue
            self.print(f"{ctx.fmt(m.base)} {ctx.fmt(m.end)}   {m.name}")
            self.print(f"    Image path: {m.path}")
            self.print(f"    Image name: {m.image_name}")
            self.print(f"    Timestamp:  {m.time_date_stamp:08X}  {fmt_time(time_t_to_datetime(m.time_date_stamp))}"
                       "  (may be a reproducible-build hash, not a date)")
            self.print(f"    CheckSum:   {m.checksum:08X}")
            self.print(f"    ImageSize:  {m.size:08X}")
            if m.file_version:
                self.print(f"    File version:     {m.file_version}")
                self.print(f"    Product version:  {m.product_version}")
            if m.codeview:
                self.print(f"    PDB:        {m.codeview.pdb_name}  ({m.codeview.signature}, "
                           f"symbol server key {m.codeview.symbol_key})")
            self.print()
        unloaded = [u for u in self.dump.unloaded_modules
                    if wanted(u.path.rsplit("\\", 1)[-1].rsplit(".", 1)[0])]
        if unloaded:
            self.print()
            self.print("Unloaded modules:")
            for u in unloaded:
                self.print(f"{ctx.fmt(u.base)} {ctx.fmt(u.end)}   {u.path}")
