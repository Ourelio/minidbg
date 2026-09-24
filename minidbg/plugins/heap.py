from ..context import CommandError
from ..heap import NT_HEAP, heap_class, heap_flag_names, list_heaps
from ..plugin import Plugin


class Heap(Plugin):
    name = "heap"
    aliases = ("!heap",)
    help = "list the process heaps (PEB.ProcessHeaps): NT or Segment heap, flags, default heap"

    def run(self) -> None:
        ctx, dump = self.ctx, self.dump
        peb = dump.peb_address
        if peb is None:
            raise CommandError("PEB not available (no TEB memory captured in this dump)")
        heaps = list_heaps(dump)
        if not heaps:
            raise CommandError("couldn't read PEB.ProcessHeaps (NumberOfHeaps or the array isn't captured)")

        width = max(len(ctx.fmt(0)), len("Heap Address"))
        self.print(f"{'#':>3}  {'Heap Address':<{width}}  {'Type':<14} {'Flags':<8}  {'Class':<18} Flag names")
        for h in heaps:
            flags, klass, names = "-", "-", ""
            if h.kind == NT_HEAP:
                kind = h.kind
                flags, klass, names = f"{h.flags:08x}", heap_class(h.flags), heap_flag_names(h.flags)
            elif h.kind is not None:
                kind = h.kind
            elif not h.captured:
                kind = "<not captured>"
            else:
                kind = "unrecognised"
                names = f"(signature dword is {h.signature:08x})"
            mark = "*" if h.default else " "
            self.print(f"{h.index:>3}{mark} {ctx.fmt(h.address):<{width}}  {kind:<14} {flags:<8}  {klass:<18} {names}".rstrip())
        self.print(f"{len(heaps)} heap(s) in PEB.ProcessHeaps; * = PEB.ProcessHeap (what GetProcessHeap() returns)")
