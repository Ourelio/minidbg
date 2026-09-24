"""Windows user-mode heaps (step 1: finding them and telling the two heap managers apart).

Every process keeps a list of its heaps in PEB.ProcessHeaps (NumberOfHeaps entries).
Each entry is the address of a heap header, and the header starts with a signature:

    NT heap       _HEAP.SegmentSignature  0xFFEEFFEE   (+ _HEAP.Signature 0xEEFFEEFF further in)
    Segment heap  _SEGMENT_HEAP.Signature 0xDDEEDDEE

Both signatures sit at the same offset (two pointers in), which is how ntdll itself
decides which heap manager a HANDLE from HeapCreate/GetProcessHeap belongs to.
"""

from dataclasses import dataclass
from typing import Optional

from .minidump import MiniDump, MiniDumpError

NT_HEAP = "NT Heap"
SEGMENT_HEAP = "Segment Heap"

NT_SEGMENT_SIGNATURE = 0xFFEEFFEE   # _HEAP_SEGMENT.SegmentSignature (every segment has one)
NT_HEAP_SIGNATURE = 0xEEFFEEFF      # _HEAP.Signature (only the heap header has this)
SEGMENT_HEAP_SIGNATURE = 0xDDEEDDEE


# Offsets into the heap headers, by pointer size. Checked against Volatility's ISF files:
# 8 x64 files (7 kernels + ntdll, one predating the segment heap) agree on every x64 value, and the
# one x86 file gives the x86 _HEAP values. No x86 file had _SEGMENT_HEAP; its Signature
# follows EnvHandle (RTL_HP_ENV_HANDLE = 2 pointers), so +0x08 is derived, not checked.
@dataclass(frozen=True)
class HeapOffsets:
    heap_segment_signature: int     # _HEAP.SegmentSignature
    heap_flags: int                 # _HEAP.Flags
    heap_signature: int             # _HEAP.Signature
    segment_heap_signature: int     # _SEGMENT_HEAP.Signature


HEAP_OFFSETS = {
    8: HeapOffsets(heap_segment_signature=0x10, heap_flags=0x70, heap_signature=0x98,
                   segment_heap_signature=0x10),
    4: HeapOffsets(heap_segment_signature=0x08, heap_flags=0x40, heap_signature=0x64,
                   segment_heap_signature=0x08),
}

# HEAP_* flags from winnt.h / ntrtl.h, as stored in _HEAP.Flags.
HEAP_FLAGS = {
    0x00000001: "NO_SERIALIZE",
    0x00000002: "GROWABLE",
    0x00000004: "GENERATE_EXCEPTIONS",
    0x00000008: "ZERO_MEMORY",
    0x00000010: "REALLOC_IN_PLACE_ONLY",
    0x00000020: "TAIL_CHECKING_ENABLED",
    0x00000040: "FREE_CHECKING_ENABLED",
    0x00000080: "DISABLE_COALESCE_ON_FREE",
    0x00010000: "CREATE_ALIGN_16",
    0x00020000: "CREATE_ENABLE_TRACING",
    0x00040000: "CREATE_ENABLE_EXECUTE",
    0x08000000: "CAPTURE_STACK_BACKTRACES",
    0x10000000: "SKIP_VALIDATION_CHECKS",
    0x20000000: "VALIDATE_ALL_ENABLED",
    0x40000000: "VALIDATE_PARAMETERS_ENABLED",
    0x80000000: "LOCK_USER_ALLOCATED",
}

# Bits 12-15 of the flags: who created the heap (HEAP_CLASS_0 .. HEAP_CLASS_8 in ntrtl.h).
HEAP_CLASS_MASK = 0x0000F000
HEAP_CLASSES = {
    0: "process heap",
    1: "private heap",
    2: "kernel heap",
    3: "GDI heap",
    4: "User heap",
    5: "console heap",
    6: "User desktop heap",
    7: "CSR shared heap",
    8: "CSR port heap",
}


def heap_class(flags: int) -> str:
    number = (flags & HEAP_CLASS_MASK) >> 12
    return f"{number} {HEAP_CLASSES.get(number, 'unknown class')}"


def heap_flag_names(flags: int) -> str:
    names = [name for bit, name in HEAP_FLAGS.items() if flags & bit]
    rest = flags & ~HEAP_CLASS_MASK & ~sum(HEAP_FLAGS)
    if rest:
        names.append(f"{rest:#x}")
    return " | ".join(names)


@dataclass
class HeapInfo:
    index: int                  # position in PEB.ProcessHeaps
    address: int                # the heap HANDLE is just the header's address
    kind: Optional[str]         # NT_HEAP, SEGMENT_HEAP, or None if not recognised
    default: bool               # PEB.ProcessHeap, i.e. what GetProcessHeap() returns
    captured: bool              # was the header's first page saved in the dump?
    signature: Optional[int]    # the dword at the signature offset
    flags: Optional[int]        # _HEAP.Flags (NT heaps only)


def heap_offsets(dump: MiniDump) -> HeapOffsets:
    return HEAP_OFFSETS[dump.pointer_size]


def identify_heap(dump: MiniDump, address: int) -> tuple[Optional[str], Optional[int], Optional[int]]:
    """(kind, signature dword, NT heap flags). kind is None when the header isn't a heap
    we recognise or isn't captured; signature is None only in the second case."""
    off = heap_offsets(dump)
    try:
        if dump.read_u32(address + off.segment_heap_signature) == SEGMENT_HEAP_SIGNATURE:
            return SEGMENT_HEAP, SEGMENT_HEAP_SIGNATURE, None
        signature = dump.read_u32(address + off.heap_segment_signature)
    except MiniDumpError:
        return None, None, None
    if signature != NT_SEGMENT_SIGNATURE:
        return None, signature, None
    try:
        if dump.read_u32(address + off.heap_signature) != NT_HEAP_SIGNATURE:
            return None, signature, None   # a heap *segment*, but not a heap header
        return NT_HEAP, signature, dump.read_u32(address + off.heap_flags)
    except MiniDumpError:
        return None, signature, None


def list_heaps(dump: MiniDump) -> list[HeapInfo]:
    peb = dump.peb_address
    if peb is None:
        return []
    try:
        default = dump.read_pointer(peb + dump.offsets.peb_process_heap)
    except MiniDumpError:
        default = None
    heaps = []
    for index, address in enumerate(dump.process_heaps()):
        kind, signature, flags = identify_heap(dump, address)
        heaps.append(HeapInfo(index=index, address=address, kind=kind, default=address == default,
                              captured=signature is not None, signature=signature, flags=flags))
    return heaps
