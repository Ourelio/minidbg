from dataclasses import dataclass
from enum import IntEnum

MINIDUMP_SIGNATURE = b"MDMP"
MINIDUMP_VERSION = 0xA793


class StreamType(IntEnum):
    UnusedStream = 0
    ReservedStream0 = 1
    ReservedStream1 = 2
    ThreadListStream = 3
    ModuleListStream = 4
    MemoryListStream = 5
    ExceptionStream = 6
    SystemInfoStream = 7
    ThreadExListStream = 8
    Memory64ListStream = 9
    CommentStreamA = 10
    CommentStreamW = 11
    HandleDataStream = 12
    FunctionTableStream = 13
    UnloadedModuleListStream = 14
    MiscInfoStream = 15
    MemoryInfoListStream = 16
    ThreadInfoListStream = 17
    HandleOperationListStream = 18
    TokenStream = 19
    JavaScriptDataStream = 20
    SystemMemoryInfoStream = 21
    ProcessVmCountersStream = 22
    IptTraceStream = 23
    ThreadNamesStream = 24


def stream_name(stream_type: int) -> str:
    try:
        return StreamType(stream_type).name
    except ValueError:
        pass
    if 0x8000 <= stream_type <= 0xFFFF:
        return f"ceStream({stream_type:#x})"
    if stream_type > 0xFFFF:
        return f"UserStream({stream_type:#x})"
    return f"UnknownStream({stream_type:#x})"


MINIDUMP_TYPE_FLAGS = [
    (0x00000001, "MiniDumpWithDataSegs"),
    (0x00000002, "MiniDumpWithFullMemory"),
    (0x00000004, "MiniDumpWithHandleData"),
    (0x00000008, "MiniDumpFilterMemory"),
    (0x00000010, "MiniDumpScanMemory"),
    (0x00000020, "MiniDumpWithUnloadedModules"),
    (0x00000040, "MiniDumpWithIndirectlyReferencedMemory"),
    (0x00000080, "MiniDumpFilterModulePaths"),
    (0x00000100, "MiniDumpWithProcessThreadData"),
    (0x00000200, "MiniDumpWithPrivateReadWriteMemory"),
    (0x00000400, "MiniDumpWithoutOptionalData"),
    (0x00000800, "MiniDumpWithFullMemoryInfo"),
    (0x00001000, "MiniDumpWithThreadInfo"),
    (0x00002000, "MiniDumpWithCodeSegs"),
    (0x00004000, "MiniDumpWithoutAuxiliaryState"),
    (0x00008000, "MiniDumpWithFullAuxiliaryState"),
    (0x00010000, "MiniDumpWithPrivateWriteCopyMemory"),
    (0x00020000, "MiniDumpIgnoreInaccessibleMemory"),
    (0x00040000, "MiniDumpWithTokenInformation"),
    (0x00080000, "MiniDumpWithModuleHeaders"),
    (0x00100000, "MiniDumpFilterTriage"),
    (0x00200000, "MiniDumpWithAvxXStateContext"),
    (0x00400000, "MiniDumpWithIptTrace"),
    (0x00800000, "MiniDumpScanInaccessiblePartialPages"),
    (0x01000000, "MiniDumpFilterWriteCombinedMemory"),
]


def decode_dump_flags(flags: int) -> list[tuple[int, str]]:
    names = [(bit, name) for bit, name in MINIDUMP_TYPE_FLAGS if flags & bit]
    known = sum(bit for bit, _ in names)
    if flags & ~known:
        names.append((flags & ~known, "<unknown bits>"))
    return names


ARCH_X86 = 0
ARCH_ARM = 5
ARCH_IA64 = 6
ARCH_AMD64 = 9
ARCH_ARM64 = 12

PROCESSOR_ARCHITECTURE = {
    ARCH_X86: "x86",
    ARCH_ARM: "ARM",
    ARCH_IA64: "IA64",
    ARCH_AMD64: "x64",
    ARCH_ARM64: "ARM64",
}

POINTER_SIZE = {ARCH_X86: 4, ARCH_ARM: 4, ARCH_IA64: 8, ARCH_AMD64: 8, ARCH_ARM64: 8}

PRODUCT_TYPES = {1: "WinNt", 2: "LanManNt", 3: "ServerNt"}

MISC1_PROCESS_ID = 0x1
MISC1_PROCESS_TIMES = 0x2
MISC3_PROCESS_INTEGRITY = 0x10
MISC3_PROTECTED_PROCESS = 0x80
MISC4_BUILDSTRING = 0x100

INTEGRITY_LEVELS = {
    0x0000: "Untrusted",
    0x1000: "Low",
    0x2000: "Medium",
    0x2100: "Medium Plus",
    0x3000: "High",
    0x4000: "System",
    0x5000: "Protected Process",
}

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

MEMORY_STATES = {MEM_COMMIT: "MEM_COMMIT", MEM_RESERVE: "MEM_RESERVE", MEM_FREE: "MEM_FREE"}
MEMORY_TYPES = {MEM_PRIVATE: "MEM_PRIVATE", MEM_MAPPED: "MEM_MAPPED", MEM_IMAGE: "MEM_IMAGE"}

PAGE_PROTECTIONS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}
PAGE_MODIFIERS = {0x100: "PAGE_GUARD", 0x200: "PAGE_NOCACHE", 0x400: "PAGE_WRITECOMBINE"}


def protect_name(protect: int) -> str:
    if protect == 0:
        return ""
    parts = [PAGE_PROTECTIONS.get(protect & 0xFF, f"{protect & 0xFF:#x}")] if protect & 0xFF else []
    parts += [name for bit, name in PAGE_MODIFIERS.items() if protect & bit]
    return " | ".join(parts)


EXCEPTION_CODES = {
    0x80000001: "Guard page violation",
    0x80000002: "Datatype misalignment",
    0x80000003: "Break instruction exception",
    0x80000004: "Single step exception",
    0xC0000005: "Access violation",
    0xC0000008: "Invalid handle",
    0xC000001D: "Illegal instruction",
    0xC0000094: "Integer divide-by-zero",
    0xC0000096: "Privileged instruction",
    0xC00000FD: "Stack overflow",
    0xC0000374: "Heap corruption",
    0xC0000409: "Security check failure or stack buffer overrun",
    0xE06D7363: "C++ EH exception",
}

# Stable across every Windows build checked (Vista through 11) because shellcode,
# runtimes and debuggers all depend on them; verified against Volatility's ISF files.
@dataclass(frozen=True)
class NtOffsets:
    teb_stack_base: int
    teb_stack_limit: int
    teb_client_id: int
    teb_peb: int
    peb_being_debugged: int
    peb_image_base: int
    peb_ldr: int
    peb_process_parameters: int
    peb_process_heap: int
    peb_number_of_heaps: int
    peb_process_heaps: int
    upp_current_directory: int
    upp_dll_path: int
    upp_image_path_name: int
    upp_command_line: int
    upp_environment: int
    upp_window_title: int
    upp_environment_size: int
    unicode_string_buffer: int


NT_OFFSETS = {
    8: NtOffsets(
        teb_stack_base=0x08, teb_stack_limit=0x10, teb_client_id=0x40, teb_peb=0x60,
        peb_being_debugged=0x02, peb_image_base=0x10, peb_ldr=0x18, peb_process_parameters=0x20,
        peb_process_heap=0x30, peb_number_of_heaps=0xE8, peb_process_heaps=0xF0,
        upp_current_directory=0x38, upp_dll_path=0x50, upp_image_path_name=0x60,
        upp_command_line=0x70, upp_environment=0x80, upp_window_title=0xB0,
        upp_environment_size=0x3F0, unicode_string_buffer=0x08,
    ),
    4: NtOffsets(
        teb_stack_base=0x04, teb_stack_limit=0x08, teb_client_id=0x20, teb_peb=0x30,
        peb_being_debugged=0x02, peb_image_base=0x08, peb_ldr=0x0C, peb_process_parameters=0x10,
        peb_process_heap=0x18, peb_number_of_heaps=0x88, peb_process_heaps=0x90,
        upp_current_directory=0x24, upp_dll_path=0x30, upp_image_path_name=0x38,
        upp_command_line=0x40, upp_environment=0x48, upp_window_title=0x70,
        upp_environment_size=0x290, unicode_string_buffer=0x04,
    ),
}

_AMD64_GPRS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]

# (minimum bytes needed, [(register, offset, struct format)])
CONTEXT_LAYOUTS = {
    ARCH_AMD64: (0x100, [(name, 0x78 + 8 * i, "<Q") for i, name in enumerate(_AMD64_GPRS)] + [
        ("eflags", 0x44, "<I"), ("cs", 0x38, "<H"), ("ds", 0x3A, "<H"), ("es", 0x3C, "<H"),
        ("fs", 0x3E, "<H"), ("gs", 0x40, "<H"), ("ss", 0x42, "<H"),
    ]),
    ARCH_X86: (0xCC, [
        ("gs", 0x8C, "<I"), ("fs", 0x90, "<I"), ("es", 0x94, "<I"), ("ds", 0x98, "<I"),
        ("edi", 0x9C, "<I"), ("esi", 0xA0, "<I"), ("ebx", 0xA4, "<I"), ("edx", 0xA8, "<I"),
        ("ecx", 0xAC, "<I"), ("eax", 0xB0, "<I"), ("ebp", 0xB4, "<I"), ("eip", 0xB8, "<I"),
        ("cs", 0xBC, "<I"), ("eflags", 0xC0, "<I"), ("esp", 0xC4, "<I"), ("ss", 0xC8, "<I"),
    ]),
}

INSTRUCTION_POINTER = {ARCH_AMD64: "rip", ARCH_X86: "eip"}
STACK_POINTER = {ARCH_AMD64: "rsp", ARCH_X86: "esp"}
