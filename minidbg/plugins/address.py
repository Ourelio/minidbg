from typing import Callable

from .. import constants as C
from ..context import CommandError, human_size
from ..minidump import Region
from ..plugin import Plugin

USAGE_FILTERS = {"image": "Image", "stack": "Stack", "heap": "Heap", "teb": "TEB", "peb": "PEB",
                 "free": "Free", "mappedfile": "MappedFile", "unknown": "Unknown", "<unknown>": "Unknown"}


def region_filter(filters: list[str]) -> Callable[[Region], bool]:
    protect_names = {name.lower(): value for value, name in C.PAGE_PROTECTIONS.items()}
    modifier_names = {name.lower(): value for value, name in C.PAGE_MODIFIERS.items()}
    type_names = {name.lower(): value for value, name in C.MEMORY_TYPES.items()}
    state_names = {name.lower(): value for value, name in C.MEMORY_STATES.items()}
    protects, modifiers, types, states, usages = set(), set(), set(), set(), set()
    for f in filters:
        key = f.lower()
        if key in protect_names:
            protects.add(protect_names[key])
        elif key in modifier_names:
            modifiers.add(modifier_names[key])
        elif key in type_names:
            types.add(type_names[key])
        elif key in state_names:
            states.add(state_names[key])
        elif key in USAGE_FILTERS:
            usages.add(USAGE_FILTERS[key])
        else:
            raise CommandError(f"unknown filter '{f}' (PAGE_*, MEM_*, Image, Stack, Heap, TEB, PEB, Free, "
                               "MappedFile, Unknown)")

    # OR inside one kind of filter, AND across kinds: PAGE_READWRITE,MEM_PRIVATE means both
    def match(region: Region) -> bool:
        info = region.info
        if (protects or modifiers) and not ((info.protect & 0xFF) in protects
                                            or any(info.protect & m for m in modifiers)):
            return False
        if types and info.type not in types:
            return False
        if states and info.state not in states:
            return False
        return not usages or bool(region.categories & usages)
    return match


class Address(Plugin):
    name = "address"
    aliases = ("!address",)
    help = "map of every memory region: type, state, protection, usage, how much was captured"

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("address", nargs="?", help="describe only the region containing this address")
        parser.add_argument("-f", "--filter", action="append", default=[], metavar="F1,F2",
                            help="keep matching regions: PAGE_*, MEM_*, Image, Stack, Heap, TEB, PEB, Free, "
                                 "MappedFile, Unknown. Same kind = OR, different kinds = AND")
        parser.add_argument("-s", "--summary", "-summary", action="store_true",
                            help="totals by usage, type, state and protection")

    def run(self) -> None:
        dump = self.dump
        if not dump.memory_info:
            raise CommandError("this dump has no MemoryInfoListStream (taken without MiniDumpWithFullMemoryInfo)")
        regions = dump.classify_regions()
        if self.args.address:
            self.detail(regions, self.ctx.evaluate(self.args.address))
            return
        filters = [f.strip() for value in self.args.filter for f in value.lstrip(":").split(",") if f.strip()]
        if filters:
            match = region_filter(filters)
            regions = [r for r in regions if match(r)]
        if self.args.summary:
            self.summary(regions)
            return
        fmt = self.ctx.fmt
        w = len(fmt(0))
        self.print(f"  {'BaseAddress':>{w}} {'EndAddress+1':>{w}} {'RegionSize':>{w}} {'Type':<12} {'State':<12} "
                   f"{'Protect':<28} {'Captured':<8} Usage")
        self.print("-" * (w * 3 + 80))
        for region in regions:
            info = region.info
            marker = "+" if info.base_address == info.allocation_base and info.state != C.MEM_FREE else " "
            self.print(f"{marker} {fmt(info.base_address)} {fmt(info.end)} {fmt(info.region_size)} "
                       f"{C.MEMORY_TYPES.get(info.type, ''):<12} {C.MEMORY_STATES.get(info.state, hex(info.state)):<12} "
                       f"{C.protect_name(info.protect):<28} {self.captured_text(region):<8} {region.usage}")
        self.print(f"{len(regions)} region(s)")

    def captured_text(self, region: Region) -> str:
        info = region.info
        if info.state != C.MEM_COMMIT:
            return "-"
        captured = self.dump.captured_bytes(info.base_address, info.end)
        if captured == info.region_size:
            return "all"
        return "none" if captured == 0 else f"{100 * captured // info.region_size}%"

    def detail(self, regions: list[Region], address: int) -> None:
        fmt = self.ctx.fmt
        region = next((r for r in regions if r.info.base_address <= address < r.info.end), None)
        if region is None:
            self.print(f"{fmt(address)} is not inside any region the dump describes")
            return
        info = region.info
        captured = self.dump.captured_bytes(info.base_address, info.end)
        rows = [
            ("Usage:", region.usage),
            ("Base Address:", fmt(info.base_address)),
            ("End Address:", fmt(info.end)),
            ("Region Size:", f"{fmt(info.region_size)} ({human_size(info.region_size)})"),
            ("State:", f"{info.state:08x}          {C.MEMORY_STATES.get(info.state, '')}"),
            ("Protect:", f"{info.protect:08x}          {C.protect_name(info.protect)}"),
            ("Type:", f"{info.type:08x}          {C.MEMORY_TYPES.get(info.type, '')}"),
            ("Allocation Base:", fmt(info.allocation_base)),
            ("Allocation Protect:", f"{info.allocation_protect:08x}          {C.protect_name(info.allocation_protect)}"),
            ("Captured in dump:", f"{captured:#x} of {info.region_size:#x} bytes"),
        ]
        symbol = self.dump.symbolize(address)
        if symbol:
            rows.append(("Symbol:", symbol))
        for label, value in rows:
            self.print(f"{label:<24}{value}")

    def summary(self, regions: list[Region]) -> None:
        busy_total = sum(r.info.region_size for r in regions if r.info.state != C.MEM_FREE) or 1
        grand_total = sum(r.info.region_size for r in regions) or 1

        def table(title: str, key: Callable[[Region], str]) -> None:
            groups: dict[str, list[int]] = {}
            for r in regions:
                stats = groups.setdefault(key(r), [0, 0, 0])  # count, total size, non-free size
                stats[0] += 1
                stats[1] += r.info.region_size
                if r.info.state != C.MEM_FREE:
                    stats[2] += r.info.region_size
            self.print(f"--- {title:<24} RgnCount ----------- Total Size -------- %ofBusy %ofTotal")
            for name, (count, size, busy_size) in sorted(groups.items(), key=lambda kv: -kv[1][1]):
                busy = f"{100 * busy_size / busy_total:7.2f}%" if busy_size else ""
                self.print(f"{name:<28} {count:8d} {self.ctx.fmt(size)} ({human_size(size)}) "
                           f"{busy:>8} {100 * size / grand_total:7.2f}%")
            self.print()

        table("Usage Summary", lambda r: sorted(r.categories)[0])
        table("Type Summary", lambda r: C.MEMORY_TYPES.get(r.info.type, "") or "MEM_FREE")
        table("State Summary", lambda r: C.MEMORY_STATES.get(r.info.state, hex(r.info.state)))
        table("Protect Summary", lambda r: C.protect_name(r.info.protect) or "<none>")
