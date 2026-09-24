import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from minidump.minidumpfile import MinidumpFile  # skelsec's reference implementation
from minidbg import MiniDump


def enum_value(x):
    if x is None:
        return 0
    return x.value if hasattr(x, "value") else int(x)


def check(label, ours, theirs):
    ok = ours == theirs
    print(f"  [{'OK' if ok else 'MISMATCH'}] {label}" + ("" if ok else f"\n      ours:   {str(ours)[:300]}\n      theirs: {str(theirs)[:300]}"))
    return ok


def main(path):
    print(f"== {path}")
    ref = MinidumpFile.parse(path)
    dump = MiniDump(path)
    results = []

    results.append(check("modules (base, size, path)",
        sorted((m.base, m.size, m.path) for m in dump.modules),
        sorted((m.baseaddress, m.size, m.name) for m in ref.modules.modules)))

    results.append(check("threads (tid, teb, stack start, stack size)",
        [(t.thread_id, t.teb, t.stack_start, t.stack_size) for t in dump.threads],
        [(t.ThreadId, t.Teb, t.Stack.StartOfMemoryRange, t.Stack.MemoryLocation.DataSize) for t in ref.threads.threads]))

    results.append(check("thread rip/rsp",
        [(t.context["rip"], t.context["rsp"]) for t in dump.threads],
        [(t.ContextObject.Rip, t.ContextObject.Rsp) for t in ref.threads.threads]))

    ref_segments = ref.memory_segments_64.memory_segments if ref.memory_segments_64 else ref.memory_segments.memory_segments
    results.append(check(f"memory ranges (start, size, file offset) x{len(ref_segments)}",
        [(r.start, r.size, r.rva) for r in dump.memory_ranges],
        [(s.start_virtual_address, s.size, s.start_file_address) for s in ref_segments]))

    # skelsec's Protect enum can't hold combined values like PAGE_READWRITE|PAGE_GUARD (0x104) and yields None,
    # so compare those regions' protection as 0 on our side too
    results.append(check(f"memory info regions x{len(ref.memory_info.infos)}",
        [(r.base_address, r.allocation_base, r.region_size, r.state, r.protect if r.protect <= 0xFF else 0, r.type)
         for r in dump.memory_info],
        sorted((i.BaseAddress, i.AllocationBase, i.RegionSize, enum_value(i.State), enum_value(i.Protect), enum_value(i.Type))
               for i in ref.memory_info.infos)))

    if ref.handles:
        results.append(check(f"handles x{len(ref.handles.handles)} (value, type, name, access)",
            [(h.handle, h.type_name, h.object_name, h.granted_access) for h in dump.handles],
            [(h.Handle, h.TypeName or "", h.ObjectName or "", h.GrantedAccess) for h in ref.handles.handles]))

    results.append(check("system info (arch, build, procs)",
        (dump.system_info.processor_architecture, dump.system_info.build_number, dump.system_info.number_of_processors),
        (int(ref.sysinfo.ProcessorArchitecture.value), ref.sysinfo.BuildNumber, ref.sysinfo.NumberOfProcessors)))

    results.append(check("process id", dump.process_id, ref.misc_info.ProcessId))

    reader = ref.get_reader()
    rng = random.Random(1337)
    mismatches = 0
    for _ in range(2000):
        seg = rng.choice(ref_segments)
        addr = seg.start_virtual_address + rng.randrange(0, max(seg.size - 64, 1))
        size = min(64, seg.end_virtual_address - addr)
        if dump.read(addr, size) != reader.read(addr, size):
            mismatches += 1
    results.append(check("2000 random memory reads byte-for-byte", mismatches, 0))
    print(f"  => {sum(results)}/{len(results)} checks passed\n")
    return all(results)


if __name__ == "__main__":
    sys.exit(0 if all([main(p) for p in sys.argv[1:]]) else 1)
