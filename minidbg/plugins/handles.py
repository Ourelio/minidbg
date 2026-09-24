from ..context import CommandError
from ..plugin import Plugin


class Handles(Plugin):
    name = "handles"
    aliases = ("!handle", "handle")
    help = "open handles: files, registry keys, mutexes, processes, ..."

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("type", nargs="?", help="only this object type, e.g. File, Key, Mutant, Process")
        parser.add_argument("-s", "--summary", action="store_true", help="count handles per type")

    def run(self) -> None:
        handles = self.dump.handles
        if not handles:
            raise CommandError("this dump has no HandleDataStream (taken without MiniDumpWithHandleData)")
        if self.args.summary:
            counts: dict[str, int] = {}
            for h in handles:
                counts[h.type_name or "<no type>"] = counts.get(h.type_name or "<no type>", 0) + 1
            for type_name, count in sorted(counts.items(), key=lambda kv: -kv[1]):
                self.print(f"    {type_name:<24} {count}")
            self.print(f"{len(handles)} handles")
            return
        wanted = self.args.type.lower() if self.args.type else None
        self.print(f"{'Handle':>8}  {'Type':<20} {'Access':>8} {'Handles':>7} {'Pointers':>8}  Name")
        shown = 0
        for h in handles:
            if wanted and h.type_name.lower() != wanted:
                continue
            self.print(f"{h.handle:8x}  {h.type_name:<20} {h.granted_access:08x} {h.handle_count:7d} "
                       f"{h.pointer_count:8d}  {h.object_name}")
            shown += 1
        self.print(f"{shown} handle(s)")
