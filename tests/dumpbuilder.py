"""Builds small synthetic minidumps so the parser can be tested against known answers."""
import struct
import uuid

ST_THREAD_LIST, ST_MODULE_LIST, ST_EXCEPTION, ST_SYSTEM_INFO = 3, 4, 6, 7
ST_MEMORY64_LIST, ST_COMMENT_W, ST_HANDLE_DATA, ST_UNLOADED = 9, 11, 12, 14
ST_MISC_INFO, ST_MEMORY_INFO, ST_THREAD_INFO, ST_THREAD_NAMES = 15, 16, 17, 24

MEM_COMMIT, MEM_FREE, MEM_PRIVATE, MEM_IMAGE = 0x1000, 0x10000, 0x20000, 0x1000000
PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE = 0x01, 0x02, 0x04
PAGE_EXECUTE_READ, PAGE_EXECUTE_WRITECOPY = 0x20, 0x80

PDB_GUID = uuid.UUID("12345678-9abc-def0-1122-334455667788")


class DumpBuilder:
    def __init__(self, directory_slots: int = 16):
        self.slots = directory_slots
        self.buf = bytearray(32 + directory_slots * 12)
        self.streams: list[tuple[int, int, int]] = []

    def add(self, blob: bytes, align: int = 4) -> int:
        while len(self.buf) % align:
            self.buf.append(0)
        rva = len(self.buf)
        self.buf += blob
        return rva

    def string(self, text: str) -> int:
        data = text.encode("utf-16-le")
        return self.add(struct.pack("<I", len(data)) + data + b"\0\0")

    def stream(self, stream_type: int, blob: bytes) -> int:
        rva = self.add(blob)
        self.streams.append((stream_type, len(blob), rva))
        return rva

    def memory64(self, ranges: list[tuple[int, bytes]]) -> None:
        while len(self.buf) % 4:
            self.buf.append(0)
        header_size = 16 + 16 * len(ranges)
        base_rva = len(self.buf) + header_size
        blob = struct.pack("<QQ", len(ranges), base_rva)
        blob += b"".join(struct.pack("<QQ", start, len(data)) for start, data in ranges)
        self.stream(ST_MEMORY64_LIST, blob)
        for _, data in ranges:
            self.add(data, align=1)

    def build(self, flags: int = 0x421826, signature: bytes = b"MDMP", timestamp: int = 0x69000000) -> bytes:
        self.buf[0:32] = struct.pack("<4sIIIIIQ", signature, 0xA793, self.slots, 32, 0, timestamp, flags)
        for i, (stream_type, size, rva) in enumerate(self.streams):
            self.buf[32 + i * 12:44 + i * 12] = struct.pack("<III", stream_type, size, rva)
        return bytes(self.buf)


def put(buf: bytearray, offset: int, fmt: str, *values) -> None:
    struct.pack_into(fmt, buf, offset, *values)


def unicode_string(buf: bytearray, offset: int, buffer_va: int, text: str, pointer_size: int) -> None:
    length = len(text.encode("utf-16-le"))
    put(buf, offset, "<HH", length, length + 2)
    put(buf, offset + pointer_size, "<Q" if pointer_size == 8 else "<I", buffer_va)


def pe_with_exports(size: int, exports: dict[str, int]) -> bytearray:
    """A PE32+ header whose export directory lists the given name -> RVA pairs."""
    image = bytearray(size)
    image[0:2] = b"MZ"
    put(image, 0x3C, "<I", 0x80)
    image[0x80:0x84] = b"PE\0\0"
    put(image, 0x80 + 4 + 16, "<H", 0xF0)       # SizeOfOptionalHeader
    put(image, 0x98, "<H", 0x20B)               # PE32+ magic
    put(image, 0x98 + 0x70, "<II", 0x200, 0x100)  # export data directory
    names = sorted(exports)
    put(image, 0x200, "<IIHHIIIIIII", 0, 0, 0, 0, 0x2F0, 1, len(names), len(names), 0x230, 0x240, 0x250)
    for i, name in enumerate(names):
        put(image, 0x230 + 4 * i, "<I", exports[name])
        put(image, 0x240 + 4 * i, "<I", 0x260 + 0x10 * i)
        put(image, 0x250 + 2 * i, "<H", i)
        image[0x260 + 0x10 * i:0x260 + 0x10 * i + len(name)] = name.encode()
    return image


TESTMOD = 0x7FF800000000
APP = 0x140000000
TEB, PEB, PARAMS, HEAP, UNKNOWN = 0x10000, 0x11000, 0x11400, 0x30000, 0x50000
SEGMENT_HEAP = 0x40000
NOT_A_HEAP = HEAP + 0x800      # has an NT *segment* signature but no _HEAP.Signature
MISSING_HEAP = 0x70000         # listed in PEB.ProcessHeaps, not captured
STACK_POINTER = 0x20F00
TID, PID = 0x1234, 0x1000
COMMAND_LINE = "app.exe --flag CTF{minidump}"


def build_x64_dump() -> bytes:
    b = DumpBuilder()

    b.stream(ST_SYSTEM_INFO, struct.pack("<HHHBBIIIIIHH", 9, 6, 0, 4, 1, 10, 0, 19045, 2, b.string(""), 0x100, 0)
             + bytes(24))

    misc = bytearray(832)
    put(misc, 0, "<6I", 832, 0x1 | 0x2 | 0x10 | 0x100, PID, 0x69000000 - 3600, 1, 2)
    put(misc, 44, "<I", 0x3000)
    build_string = "19041.1.amd64fre.vb_release.191206-1406".encode("utf-16-le")
    misc[232:232 + len(build_string)] = build_string
    b.stream(ST_MISC_INFO, bytes(misc))

    cv = b"RSDS" + PDB_GUID.bytes_le + struct.pack("<I", 1) + b"testmod.pdb\0"
    cv_rva = b.add(cv)
    modules = [(APP, 0x1000, b.string("C:\\app\\app.exe"), 0, 0),
               (TESTMOD, 0x3000, b.string("C:\\Windows\\System32\\testmod.dll"), len(cv), cv_rva)]
    blob = struct.pack("<I", len(modules))
    for base, size, name_rva, cv_size, cvr in modules:
        version = struct.pack("<13I", 0xFEEF04BD, 0x10000, (10 << 16) | 0, (19041 << 16) | 1, 0, 0, *([0] * 7))
        blob += struct.pack("<QIIII", base, size, 0xABCD, 0x5DEE0000, name_rva) + version
        blob += struct.pack("<II", cv_size, cvr) + struct.pack("<II", 0, 0) + struct.pack("<QQ", 0, 0)
    assert len(blob) == 4 + 108 * len(modules)
    b.stream(ST_MODULE_LIST, blob)

    b.stream(ST_UNLOADED, struct.pack("<III", 12, 24, 1)
             + struct.pack("<QIIII", 0x180000000, 0x2000, 0, 0, b.string("C:\\evil\\gone.dll")))

    context = bytearray(0x4D0)
    put(context, 0x30, "<I", 0x10001F)
    put(context, 0x38, "<HHHHHH", 0x33, 0x2B, 0x2B, 0x53, 0x2B, 0x2B)
    put(context, 0x44, "<I", 0x246)
    put(context, 0x78, "<Q", 4)                          # rax
    put(context, 0x98, "<Q", STACK_POINTER)              # rsp
    put(context, 0xF8, "<Q", TESTMOD + 0x1014)           # rip = FuncA+0x14
    context_rva = b.add(bytes(context))
    b.stream(ST_THREAD_LIST, struct.pack("<I", 1) + struct.pack("<IIIIQQIIII", TID, 0, 0x20, 0, TEB,
                                                                   STACK_POINTER, 0x100, 0, len(context), context_rva))
    b.stream(ST_THREAD_INFO, struct.pack("<III", 12, 64, 1)
             + struct.pack("<IIIIQQQQQQ", TID, 0, 0, 0, 133000000000000000, 0, 0, 0, UNKNOWN, 1))
    b.stream(ST_THREAD_NAMES, struct.pack("<I", 1) + struct.pack("<IQ", TID, b.string("worker")))

    handles = [(0x40, "File", "\\Device\\HarddiskVolume3\\secret.txt", 0x120089),
               (0x44, "Mutant", "\\Sessions\\1\\BaseNamedObjects\\evil_mutex", 0x1F0001)]
    blob = struct.pack("<IIII", 16, 40, len(handles), 0)
    for value, type_name, name, access in handles:
        blob += struct.pack("<QIIIIII", value, b.string(type_name), b.string(name), 0, access, 1, 2) + bytes(8)
    b.stream(ST_HANDLE_DATA, blob)

    b.stream(ST_EXCEPTION, struct.pack("<II", TID, 0) + struct.pack("<IIQQII", 0xC0000005, 0, 0, TESTMOD + 0x1014, 2, 0)
             + struct.pack("<15Q", 1, 0xDEADBEEF, *([0] * 13)) + struct.pack("<II", len(context), context_rva))
    b.stream(ST_COMMENT_W, "hello from the builder\0".encode("utf-16-le"))

    regions = [
        (TEB, TEB, PAGE_READWRITE, 0x2000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        (0x20000, 0x20000, PAGE_READWRITE, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        (HEAP, HEAP, PAGE_READWRITE, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        (SEGMENT_HEAP, SEGMENT_HEAP, PAGE_READWRITE, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        (UNKNOWN, UNKNOWN, PAGE_READWRITE, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        (0x60000, 0, 0, 0x10000, MEM_FREE, PAGE_NOACCESS, 0),
        (APP, APP, PAGE_EXECUTE_WRITECOPY, 0x1000, MEM_COMMIT, PAGE_READONLY, MEM_IMAGE),
        (TESTMOD, TESTMOD, PAGE_EXECUTE_WRITECOPY, 0x2000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE),
    ]
    blob = struct.pack("<IIQ", 16, 48, len(regions))
    for base, alloc, alloc_protect, size, state, protect, mtype in regions:
        blob += struct.pack("<QQIIQIIII", base, alloc, alloc_protect, 0, size, state, protect, mtype, 0)
    b.stream(ST_MEMORY_INFO, blob)

    teb_peb = bytearray(0x2000)
    put(teb_peb, 0x08, "<QQ", 0x21000, 0x20000)                    # StackBase, StackLimit
    put(teb_peb, 0x40, "<QQ", PID, TID)                            # ClientId
    put(teb_peb, 0x60, "<Q", PEB)
    peb = PEB - TEB
    put(teb_peb, peb + 0x02, "<B", 1)
    put(teb_peb, peb + 0x10, "<Q", APP)
    put(teb_peb, peb + 0x20, "<Q", PARAMS)
    put(teb_peb, peb + 0x30, "<Q", HEAP)
    process_heaps = [HEAP, SEGMENT_HEAP, NOT_A_HEAP, MISSING_HEAP]
    put(teb_peb, peb + 0xE8, "<I", len(process_heaps))
    put(teb_peb, peb + 0xF0, "<Q", 0x11F00)
    put(teb_peb, 0x1F00, f"<{len(process_heaps)}Q", *process_heaps)
    params = PARAMS - TEB
    strings = {0x38: (0x11C00, "C:\\app\\"), 0x60: (0x11C40, "C:\\app\\app.exe"), 0x70: (0x11C80, COMMAND_LINE)}
    for field, (va, text) in strings.items():
        unicode_string(teb_peb, params + field, va, text, 8)
        encoded = text.encode("utf-16-le")
        teb_peb[va - TEB:va - TEB + len(encoded)] = encoded
    environment = "A=1\0B=2\0\0".encode("utf-16-le")
    put(teb_peb, params + 0x80, "<Q", 0x11D00)
    put(teb_peb, params + 0x3F0, "<Q", len(environment))
    teb_peb[0x1D00:0x1D00 + len(environment)] = environment

    stack = bytearray(0x1000)
    put(stack, STACK_POINTER - 0x20000, "<Q", TESTMOD + 0x1110)     # return address FuncB+0x10

    heap = bytearray(0x1000)
    put(heap, 0x10, "<I", 0xFFEEFFEE)                                # _HEAP.SegmentSignature
    put(heap, 0x70, "<I", 0x2)                                       # _HEAP.Flags = GROWABLE
    put(heap, 0x98, "<I", 0xEEFFEEFF)                                # _HEAP.Signature
    put(heap, NOT_A_HEAP - HEAP + 0x10, "<I", 0xFFEEFFEE)
    segment_heap = bytearray(0x1000)
    put(segment_heap, 0x10, "<I", 0xDDEEDDEE)                        # _SEGMENT_HEAP.Signature

    unknown = bytearray(0x1000)
    unknown[0x123:0x123 + 11] = b"FINDME_1337"

    image = pe_with_exports(0x2000, {"FuncA": 0x1000, "FuncB": 0x1100})
    image[0xFFE:0x1002] = b"SPAN"                                    # straddles the two ranges below

    b.memory64([(TEB, bytes(teb_peb)), (0x20000, bytes(stack)), (HEAP, bytes(heap)),
                (SEGMENT_HEAP, bytes(segment_heap)), (UNKNOWN, bytes(unknown)),
                (TESTMOD, bytes(image[:0x1000])), (TESTMOD + 0x1000, bytes(image[0x1000:]))])
    return b.build()


X86_TEB, X86_PEB, X86_PARAMS = 0x7FFDE000, 0x7FFDF000, 0x7FFDF400
X86_HEAP = 0x150000


def build_x86_dump() -> bytes:
    b = DumpBuilder()
    b.stream(ST_SYSTEM_INFO, struct.pack("<HHHBBIIIIIHH", 0, 6, 0, 1, 1, 6, 1, 7601, 2, b.string("Service Pack 1"), 0, 0)
             + bytes(24))
    b.stream(ST_MISC_INFO, struct.pack("<6I", 24, 0x1, 0x99, 0, 0, 0))
    context = bytearray(0x2CC)
    put(context, 0xB8, "<I", 0x401000)    # eip
    put(context, 0xC4, "<I", 0x12FF00)    # esp
    put(context, 0xC0, "<I", 0x202)       # eflags
    context_rva = b.add(bytes(context))
    b.stream(ST_THREAD_LIST, struct.pack("<I", 1) + struct.pack("<IIIIQQIIII", 0x77, 0, 0x20, 0, X86_TEB,
                                                                   0x12FF00, 0x100, 0, len(context), context_rva))
    page = bytearray(0x2000)
    put(page, 0x30, "<I", X86_PEB)
    put(page, X86_PEB - X86_TEB + 0x10, "<I", X86_PARAMS)
    put(page, X86_PEB - X86_TEB + 0x18, "<I", X86_HEAP)              # ProcessHeap
    put(page, X86_PEB - X86_TEB + 0x88, "<I", 1)                     # NumberOfHeaps
    put(page, X86_PEB - X86_TEB + 0x90, "<I", X86_PEB + 0x800)       # ProcessHeaps
    put(page, X86_PEB - X86_TEB + 0x800, "<I", X86_HEAP)
    heap = bytearray(0x100)
    put(heap, 0x08, "<I", 0xFFEEFFEE)
    put(heap, 0x40, "<I", 0x1002)                                    # GROWABLE, class 1 (private)
    put(heap, 0x64, "<I", 0xEEFFEEFF)
    command_line = "calc.exe /x86"
    unicode_string(page, X86_PARAMS - X86_TEB + 0x40, 0x7FFDFC00, command_line, 4)
    encoded = command_line.encode("utf-16-le")
    page[0x7FFDFC00 - X86_TEB:0x7FFDFC00 - X86_TEB + len(encoded)] = encoded
    b.memory64([(X86_HEAP, bytes(heap)), (X86_TEB, bytes(page))])
    return b.build(flags=0x2)
