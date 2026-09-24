from __future__ import annotations

import bisect
import datetime
import mmap
import os
import struct
import uuid
from dataclasses import dataclass, field
from typing import Iterator, Optional

from . import constants as C
from .constants import StreamType

MODULE_ENTRY_SIZE = 108  # MINIDUMP_MODULE is packed to 4 bytes, so not 112
THREAD_ENTRY_SIZE = 48
THREAD_EX_ENTRY_SIZE = 64
SEARCH_CHUNK = 16 * 1024 * 1024


class MiniDumpError(Exception):
    pass


class MemoryNotCaptured(MiniDumpError):
    def __init__(self, address: int):
        super().__init__(f"memory at {address:#x} was not captured in this dump")
        self.address = address


def filetime_to_datetime(value: int) -> Optional[datetime.datetime]:
    if not value:
        return None
    try:
        return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def time_t_to_datetime(value: int) -> Optional[datetime.datetime]:
    if not value:
        return None
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _utf16z(data: bytes) -> str:
    return data.decode("utf-16-le", errors="replace").split("\0", 1)[0]


def _file_version(vs: tuple[int, ...], index: int) -> Optional[str]:
    if vs[0] != 0xFEEF04BD:
        return None
    ms, ls = vs[index], vs[index + 1]
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


@dataclass
class Header:
    signature: bytes
    version: int
    number_of_streams: int
    stream_directory_rva: int
    checksum: int
    time_date_stamp: int
    flags: int


@dataclass
class DirectoryEntry:
    index: int
    stream_type: int
    data_size: int
    rva: int

    @property
    def name(self) -> str:
        return C.stream_name(self.stream_type)


@dataclass
class SystemInfo:
    processor_architecture: int
    processor_level: int
    processor_revision: int
    number_of_processors: int
    product_type: int
    major_version: int
    minor_version: int
    build_number: int
    platform_id: int
    csd_version: str
    suite_mask: int


@dataclass
class MiscInfo:
    size_of_info: int
    flags1: int
    process_id: Optional[int] = None
    process_create_time: Optional[int] = None
    process_user_time: Optional[int] = None
    process_kernel_time: Optional[int] = None
    integrity_level: Optional[int] = None
    protected_process: Optional[int] = None
    build_string: Optional[str] = None
    dbg_build_string: Optional[str] = None


@dataclass
class CodeViewRecord:
    signature: str
    pdb_name: str
    age: int
    guid: Optional[uuid.UUID] = None
    timestamp: Optional[int] = None

    @property
    def symbol_key(self) -> str:
        """The GUID+age folder name a symbol server stores this PDB under."""
        if self.guid is not None:
            return f"{self.guid.hex.upper()}{self.age:X}"
        return f"{self.timestamp or 0:08X}{self.age:X}"


@dataclass
class Module:
    base: int
    size: int
    checksum: int
    time_date_stamp: int
    path: str
    file_version: Optional[str] = None
    product_version: Optional[str] = None
    codeview: Optional[CodeViewRecord] = None

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def image_name(self) -> str:
        return self.path.replace("/", "\\").rsplit("\\", 1)[-1]

    @property
    def name(self) -> str:
        stem = self.image_name.rsplit(".", 1)[0] if "." in self.image_name else self.image_name
        return "".join(c if c.isalnum() else "_" for c in stem) or f"image{self.base:x}"


@dataclass
class UnloadedModule:
    base: int
    size: int
    checksum: int
    time_date_stamp: int
    path: str

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass
class ThreadInfo:
    dump_flags: int
    dump_error: int
    exit_status: int
    create_time: int
    exit_time: int
    kernel_time: int
    user_time: int
    start_address: int
    affinity: int


@dataclass
class Thread:
    index: int
    thread_id: int
    suspend_count: int
    priority_class: int
    priority: int
    teb: int
    stack_start: int
    stack_size: int
    stack_rva: int
    context_size: int
    context_rva: int
    context: Optional[dict[str, int]] = None
    info: Optional[ThreadInfo] = None
    name: Optional[str] = None


@dataclass
class MemoryRange:
    start: int
    size: int
    rva: int

    @property
    def end(self) -> int:
        return self.start + self.size


@dataclass
class MemoryInfo:
    base_address: int
    allocation_base: int
    allocation_protect: int
    region_size: int
    state: int
    protect: int
    type: int

    @property
    def end(self) -> int:
        return self.base_address + self.region_size


@dataclass
class Handle:
    handle: int
    type_name: str
    object_name: str
    attributes: int
    granted_access: int
    handle_count: int
    pointer_count: int


@dataclass
class ExceptionInfo:
    thread_id: int
    code: int
    flags: int
    record: int
    address: int
    parameters: list[int]
    context_size: int
    context_rva: int
    context: Optional[dict[str, int]] = None


@dataclass
class Region:
    info: MemoryInfo
    categories: frozenset[str]
    usage: str


@dataclass
class _ExportTable:
    rvas: list[int] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    by_name: dict[str, int] = field(default_factory=dict)


class MiniDump:
    def __init__(self, path: str, force: bool = False):
        self.path = path
        self._file = open(path, "rb")
        self.file_size = os.fstat(self._file.fileno()).st_size
        try:
            self._mm = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ) if self.file_size else None
        except (OSError, ValueError):
            self._mm = None

        self.warnings: list[str] = []
        self.system_info: Optional[SystemInfo] = None
        self.misc_info: Optional[MiscInfo] = None
        self.modules: list[Module] = []
        self.unloaded_modules: list[UnloadedModule] = []
        self.threads: list[Thread] = []
        self.memory_ranges: list[MemoryRange] = []
        self.memory_info: list[MemoryInfo] = []
        self.handles: list[Handle] = []
        self.exception: Optional[ExceptionInfo] = None
        self.comments: list[str] = []
        self._thread_infos: dict[int, ThreadInfo] = {}
        self._thread_names: dict[int, str] = {}
        self._exports: dict[int, _ExportTable] = {}
        self._peb_cache: Optional[tuple[Optional[int]]] = None

        try:
            self.header = self._parse_header(force)
            self.directory = self._parse_directory()
            self._parse_streams()
            self._finish()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
        self._file.close()

    def __enter__(self) -> MiniDump:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- raw file access -------------------------------------------------

    def _read_file(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.file_size:
            raise MiniDumpError(
                f"read of {size:#x} bytes at file offset {offset:#x} runs past end of file ({self.file_size:#x})"
            )
        if self._mm is not None:
            return self._mm[offset:offset + size]
        self._file.seek(offset)
        return self._file.read(size)

    def read_minidump_string(self, rva: int) -> str:
        if rva == 0:
            return ""
        try:
            (length,) = struct.unpack("<I", self._read_file(rva, 4))
            return self._read_file(rva + 4, min(length, 0x10000) & ~1).decode("utf-16-le", errors="replace")
        except MiniDumpError as exc:
            self.warnings.append(f"MINIDUMP_STRING at {rva:#x}: {exc}")
            return f"<unreadable string @ {rva:#x}>"

    def _clip(self, count: int, available: int, entry_size: int, what: str) -> int:
        fits = max(available, 0) // entry_size if entry_size else 0
        if count > fits:
            self.warnings.append(f"{what}: header claims {count} entries but only {fits} fit; clipping")
            return fits
        return count

    # ---- header and directory -------------------------------------------

    def _parse_header(self, force: bool) -> Header:
        if self.file_size < 32:
            raise MiniDumpError("file is too small to hold a MINIDUMP_HEADER (32 bytes)")
        header = Header(*struct.unpack("<4sIIIIIQ", self._read_file(0, 32)))
        if header.signature != C.MINIDUMP_SIGNATURE:
            message = f"bad signature {header.signature!r}, expected {C.MINIDUMP_SIGNATURE!r}"
            if not force:
                raise MiniDumpError(message + " (use --force to parse anyway)")
            self.warnings.append(message)
        if header.version & 0xFFFF != C.MINIDUMP_VERSION:
            self.warnings.append(f"unexpected version {header.version & 0xFFFF:#x} (expected {C.MINIDUMP_VERSION:#x})")
        return header

    def _parse_directory(self) -> list[DirectoryEntry]:
        rva = self.header.stream_directory_rva
        count = self._clip(self.header.number_of_streams, self.file_size - rva, 12, "stream directory")
        blob = self._read_file(rva, count * 12)
        return [DirectoryEntry(i, *struct.unpack_from("<III", blob, i * 12)) for i in range(count)]

    def _parse_streams(self) -> None:
        parsers = {
            StreamType.SystemInfoStream: self._parse_system_info,
            StreamType.MiscInfoStream: self._parse_misc_info,
            StreamType.ModuleListStream: self._parse_module_list,
            StreamType.UnloadedModuleListStream: self._parse_unloaded_module_list,
            StreamType.ThreadListStream: lambda blob: self._parse_thread_list(blob, THREAD_ENTRY_SIZE),
            StreamType.ThreadExListStream: lambda blob: self._parse_thread_list(blob, THREAD_EX_ENTRY_SIZE),
            StreamType.ThreadInfoListStream: self._parse_thread_info_list,
            StreamType.ThreadNamesStream: self._parse_thread_names,
            StreamType.MemoryListStream: self._parse_memory_list,
            StreamType.Memory64ListStream: self._parse_memory64_list,
            StreamType.MemoryInfoListStream: self._parse_memory_info_list,
            StreamType.HandleDataStream: self._parse_handle_data,
            StreamType.ExceptionStream: self._parse_exception,
            StreamType.CommentStreamA: lambda blob: self.comments.append(blob.decode("latin-1").rstrip("\0")),
            StreamType.CommentStreamW: lambda blob: self.comments.append(_utf16z(blob)),
        }
        seen: set[int] = set()
        for entry in self.directory:
            parse = parsers.get(entry.stream_type)
            if parse is None:
                continue
            if entry.stream_type in seen:
                self.warnings.append(f"duplicate {entry.name} (directory entry {entry.index}) ignored")
                continue
            seen.add(entry.stream_type)
            try:
                parse(self._read_file(entry.rva, entry.data_size))
            except (MiniDumpError, struct.error, ValueError) as exc:
                self.warnings.append(f"{entry.name} at {entry.rva:#x}: {exc}")

    # ---- metadata streams -------------------------------------------------

    def _parse_system_info(self, blob: bytes) -> None:
        (arch, level, revision, nprocs, product, major, minor, build, platform, csd_rva, suite, _) = \
            struct.unpack_from("<HHHBBIIIIIHH", blob)
        self.system_info = SystemInfo(arch, level, revision, nprocs, product, major, minor, build,
                                      platform, self.read_minidump_string(csd_rva), suite)

    def _parse_misc_info(self, blob: bytes) -> None:
        size, flags1, pid, create, user, kernel = struct.unpack_from("<6I", blob)
        info = MiscInfo(size, flags1)
        if flags1 & C.MISC1_PROCESS_ID:
            info.process_id = pid
        if flags1 & C.MISC1_PROCESS_TIMES:
            info.process_create_time, info.process_user_time, info.process_kernel_time = create, user, kernel
        # MINIDUMP_MISC_INFO grew over time; each version appends fields, and SizeOfInfo says which one we have
        if len(blob) >= 232 and flags1 & C.MISC3_PROCESS_INTEGRITY:
            info.integrity_level = struct.unpack_from("<I", blob, 44)[0]
        if len(blob) >= 232 and flags1 & C.MISC3_PROTECTED_PROCESS:
            info.protected_process = struct.unpack_from("<I", blob, 52)[0]
        if len(blob) >= 832 and flags1 & C.MISC4_BUILDSTRING:
            info.build_string = _utf16z(blob[232:752])
            info.dbg_build_string = _utf16z(blob[752:832])
        self.misc_info = info

    def _parse_codeview(self, size: int, rva: int) -> Optional[CodeViewRecord]:
        if size < 16 or rva == 0:
            return None
        try:
            data = self._read_file(rva, min(size, 0x1000))
        except MiniDumpError:
            return None
        if data[:4] == b"RSDS" and len(data) >= 24:
            (age,) = struct.unpack_from("<I", data, 20)
            name = data[24:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
            return CodeViewRecord("RSDS", name, age, guid=uuid.UUID(bytes_le=data[4:20]))
        if data[:4] == b"NB10":
            _, timestamp, age = struct.unpack_from("<III", data, 4)
            name = data[16:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
            return CodeViewRecord("NB10", name, age, timestamp=timestamp)
        return None

    def _parse_module_list(self, blob: bytes) -> None:
        (count,) = struct.unpack_from("<I", blob)
        count = self._clip(count, len(blob) - 4, MODULE_ENTRY_SIZE, "ModuleListStream")
        for i in range(count):
            off = 4 + i * MODULE_ENTRY_SIZE
            base, size, checksum, timestamp, name_rva = struct.unpack_from("<QIIII", blob, off)
            version_info = struct.unpack_from("<13I", blob, off + 24)
            cv_size, cv_rva = struct.unpack_from("<II", blob, off + 76)
            self.modules.append(Module(
                base, size, checksum, timestamp, self.read_minidump_string(name_rva),
                _file_version(version_info, 2), _file_version(version_info, 4),
                self._parse_codeview(cv_size, cv_rva),
            ))
        self.modules.sort(key=lambda m: m.base)

    def _parse_unloaded_module_list(self, blob: bytes) -> None:
        header_size, entry_size, count = struct.unpack_from("<III", blob)
        if entry_size < 24:
            raise MiniDumpError(f"entry size {entry_size} is smaller than MINIDUMP_UNLOADED_MODULE (24)")
        count = self._clip(count, len(blob) - header_size, entry_size, "UnloadedModuleListStream")
        for i in range(count):
            base, size, checksum, timestamp, name_rva = struct.unpack_from("<QIIII", blob, header_size + i * entry_size)
            self.unloaded_modules.append(
                UnloadedModule(base, size, checksum, timestamp, self.read_minidump_string(name_rva)))

    # ---- threads ------------------------------------------------------------

    def _parse_thread_list(self, blob: bytes, entry_size: int) -> None:
        if self.threads:
            self.warnings.append("both ThreadListStream and ThreadExListStream present; keeping the first")
            return
        (count,) = struct.unpack_from("<I", blob)
        count = self._clip(count, len(blob) - 4, entry_size, "thread list")
        for i in range(count):
            fields = struct.unpack_from("<IIIIQQIIII", blob, 4 + i * entry_size)
            self.threads.append(Thread(i, *fields))

    def _parse_thread_info_list(self, blob: bytes) -> None:
        header_size, entry_size, count = struct.unpack_from("<III", blob)
        if entry_size < 64:
            raise MiniDumpError(f"entry size {entry_size} is smaller than MINIDUMP_THREAD_INFO (64)")
        count = self._clip(count, len(blob) - header_size, entry_size, "ThreadInfoListStream")
        for i in range(count):
            tid, *rest = struct.unpack_from("<IIIIQQQQQQ", blob, header_size + i * entry_size)
            self._thread_infos[tid] = ThreadInfo(*rest)

    def _parse_thread_names(self, blob: bytes) -> None:
        (count,) = struct.unpack_from("<I", blob)
        count = self._clip(count, len(blob) - 4, 12, "ThreadNamesStream")
        for i in range(count):
            tid, name_rva = struct.unpack_from("<IQ", blob, 4 + i * 12)
            self._thread_names[tid] = self.read_minidump_string(name_rva)

    def _parse_context(self, size: int, rva: int) -> Optional[dict[str, int]]:
        layout = C.CONTEXT_LAYOUTS.get(self.architecture)
        if layout is None or not rva or size < layout[0]:
            return None
        try:
            blob = self._read_file(rva, layout[0])
        except MiniDumpError as exc:
            self.warnings.append(f"thread context at {rva:#x}: {exc}")
            return None
        return {name: struct.unpack_from(fmt, blob, offset)[0] for name, offset, fmt in layout[1]}

    # ---- memory -----------------------------------------------------------------

    def _parse_memory_list(self, blob: bytes) -> None:
        (count,) = struct.unpack_from("<I", blob)
        count = self._clip(count, len(blob) - 4, 16, "MemoryListStream")
        for i in range(count):
            self.memory_ranges.append(MemoryRange(*struct.unpack_from("<QII", blob, 4 + i * 16)))

    def _parse_memory64_list(self, blob: bytes) -> None:
        count, base_rva = struct.unpack_from("<QQ", blob)
        count = self._clip(count, len(blob) - 16, 16, "Memory64ListStream")
        # Memory64 descriptors carry no RVA: the range data is stored back to back from BaseRva
        rva = base_rva
        for i in range(count):
            start, size = struct.unpack_from("<QQ", blob, 16 + i * 16)
            self.memory_ranges.append(MemoryRange(start, size, rva))
            rva += size
        if rva > self.file_size:
            self.warnings.append(
                f"Memory64ListStream describes data up to file offset {rva:#x} but the file is only "
                f"{self.file_size:#x} bytes (truncated dump?)")

    def _parse_memory_info_list(self, blob: bytes) -> None:
        header_size, entry_size, count = struct.unpack_from("<IIQ", blob)
        if entry_size < 48:
            raise MiniDumpError(f"entry size {entry_size} is smaller than MINIDUMP_MEMORY_INFO (48)")
        count = self._clip(count, len(blob) - header_size, entry_size, "MemoryInfoListStream")
        for i in range(count):
            base, alloc_base, alloc_protect, _, size, state, protect, mtype, _ = \
                struct.unpack_from("<QQIIQIIII", blob, header_size + i * entry_size)
            self.memory_info.append(MemoryInfo(base, alloc_base, alloc_protect, size, state, protect, mtype))
        self.memory_info.sort(key=lambda r: r.base_address)

    # ---- handles and exception --------------------------------------------------

    def _parse_handle_data(self, blob: bytes) -> None:
        header_size, descriptor_size, count, _ = struct.unpack_from("<IIII", blob)
        if descriptor_size < 32:
            raise MiniDumpError(f"descriptor size {descriptor_size} is smaller than MINIDUMP_HANDLE_DESCRIPTOR (32)")
        count = self._clip(count, len(blob) - header_size, descriptor_size, "HandleDataStream")
        for i in range(count):
            handle, type_rva, name_rva, attrs, access, handle_count, pointer_count = \
                struct.unpack_from("<QIIIIII", blob, header_size + i * descriptor_size)
            self.handles.append(Handle(handle, self.read_minidump_string(type_rva),
                                       self.read_minidump_string(name_rva), attrs, access,
                                       handle_count, pointer_count))

    def _parse_exception(self, blob: bytes) -> None:
        tid, _ = struct.unpack_from("<II", blob)
        code, flags, record, address, nparams, _ = struct.unpack_from("<IIQQII", blob, 8)
        params = struct.unpack_from("<15Q", blob, 40)
        ctx_size, ctx_rva = struct.unpack_from("<II", blob, 160)
        self.exception = ExceptionInfo(tid, code, flags, record, address, list(params[:min(nparams, 15)]),
                                       ctx_size, ctx_rva)

    # ---- post-processing ------------------------------------------------------------

    def _finish(self) -> None:
        if self.system_info is None:
            self.warnings.append("no SystemInfoStream; assuming x64")
        for thread in self.threads:
            thread.info = self._thread_infos.get(thread.thread_id)
            thread.name = self._thread_names.get(thread.thread_id)
            thread.context = self._parse_context(thread.context_size, thread.context_rva)
        if self.exception is not None:
            self.exception.context = self._parse_context(self.exception.context_size, self.exception.context_rva)

        self._index: list[MemoryRange] = []
        for r in sorted(self.memory_ranges, key=lambda r: r.start):
            if r.size == 0:
                continue
            if self._index and r.start < self._index[-1].end:
                overlap = self._index[-1].end - r.start
                if overlap >= r.size:
                    continue
                r = MemoryRange(r.start + overlap, r.size - overlap, r.rva + overlap)
            self._index.append(r)
        self._index_starts = [r.start for r in self._index]
        self._module_bases = [m.base for m in self.modules]
        self._region_bases = [r.base_address for r in self.memory_info]

    # ---- properties ---------------------------------------------------------------------

    @property
    def architecture(self) -> int:
        return self.system_info.processor_architecture if self.system_info else C.ARCH_AMD64

    @property
    def pointer_size(self) -> int:
        return C.POINTER_SIZE.get(self.architecture, 8)

    @property
    def offsets(self) -> C.NtOffsets:
        return C.NT_OFFSETS[self.pointer_size]

    @property
    def process_id(self) -> Optional[int]:
        return self.misc_info.process_id if self.misc_info else None

    def thread_by_id(self, thread_id: int) -> Optional[Thread]:
        return next((t for t in self.threads if t.thread_id == thread_id), None)

    # ---- virtual memory -------------------------------------------------------------------

    def find_range(self, address: int) -> Optional[MemoryRange]:
        i = bisect.bisect_right(self._index_starts, address) - 1
        if i >= 0 and address < self._index[i].end:
            return self._index[i]
        return None

    def _segments(self, address: int, size: int) -> Iterator[tuple[int, int, Optional[MemoryRange]]]:
        """Split [address, address+size) into (address, length, range-or-None-for-a-gap) pieces."""
        while size > 0:
            r = self.find_range(address)
            if r is None:
                i = bisect.bisect_right(self._index_starts, address)
                n = min(size, self._index[i].start - address) if i < len(self._index) else size
            else:
                n = min(size, r.end - address)
            yield address, n, r
            address += n
            size -= n

    def read(self, address: int, size: int, pad: bool = False) -> bytes:
        """Read virtual memory. Raises MemoryNotCaptured for gaps unless pad=True (gaps become zeros)."""
        out = bytearray()
        for seg_address, n, r in self._segments(address, size):
            if r is None:
                if not pad:
                    raise MemoryNotCaptured(seg_address)
                out += bytes(n)
            else:
                out += self._read_file(r.rva + (seg_address - r.start), n)
        return bytes(out)

    def read_partial(self, address: int, size: int) -> list[Optional[int]]:
        """Bytes at address, with None for every byte the dump did not capture."""
        out: list[Optional[int]] = []
        for seg_address, n, r in self._segments(address, size):
            if r is None:
                out.extend([None] * n)
            else:
                out.extend(self._read_file(r.rva + (seg_address - r.start), n))
        return out

    def captured_length(self, address: int, limit: int) -> int:
        """How many bytes starting at address can be read before hitting uncaptured memory."""
        total = 0
        while total < limit:
            r = self.find_range(address + total)
            if r is None:
                break
            total += min(limit - total, r.end - (address + total))
        return total

    def captured_bytes(self, start: int, end: int) -> int:
        total = 0
        i = max(bisect.bisect_right(self._index_starts, start) - 1, 0)
        while i < len(self._index) and self._index[i].start < end:
            r = self._index[i]
            total += max(0, min(end, r.end) - max(start, r.start))
            i += 1
        return total

    def read_u16(self, address: int) -> int:
        return struct.unpack("<H", self.read(address, 2))[0]

    def read_u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def read_u64(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, 8))[0]

    def read_pointer(self, address: int) -> int:
        return self.read_u64(address) if self.pointer_size == 8 else self.read_u32(address)

    def read_cstring(self, address: int, limit: int = 0x1000, wide: bool = False) -> str:
        data = self.read(address, self.captured_length(address, limit))
        if wide:
            for i in range(0, len(data) - 1, 2):
                if data[i] == 0 and data[i + 1] == 0:
                    data = data[:i]
                    break
            return data[: len(data) & ~1].decode("utf-16-le", errors="replace")
        return data.split(b"\0", 1)[0].decode("latin-1")

    def read_unicode_string(self, address: int) -> str:
        """Read a UNICODE_STRING structure (Length, MaximumLength, Buffer)."""
        length = self.read_u16(address)
        buffer = self.read_pointer(address + self.offsets.unicode_string_buffer)
        if not length or not buffer:
            return ""
        return self.read(buffer, length & ~1).decode("utf-16-le", errors="replace")

    def memory_runs(self) -> list[tuple[int, int]]:
        """Captured memory merged into contiguous (start, end) runs."""
        runs: list[list[int]] = []
        for r in self._index:
            if runs and runs[-1][1] == r.start:
                runs[-1][1] = r.end
            else:
                runs.append([r.start, r.end])
        return [(s, e) for s, e in runs]

    def search(self, pattern: bytes, start: int = 0, end: int = 1 << 64) -> Iterator[int]:
        if not pattern:
            return
        overlap = len(pattern) - 1
        for run_start, run_end in self.memory_runs():
            lo, hi = max(run_start, start), min(run_end, end)
            pos = lo
            while pos < hi:
                n = min(SEARCH_CHUNK, hi - pos)
                data = self.read(pos, min(n + overlap, hi - pos))
                hit = data.find(pattern)
                while hit != -1 and hit < n:
                    yield pos + hit
                    hit = data.find(pattern, hit + 1)
                pos += n

    # ---- modules and symbols --------------------------------------------------------------

    def module_at(self, address: int) -> Optional[Module]:
        i = bisect.bisect_right(self._module_bases, address) - 1
        if i >= 0 and address < self.modules[i].end:
            return self.modules[i]
        return None

    def module_by_name(self, name: str) -> Optional[Module]:
        lowered = name.lower()
        for m in self.modules:
            if m.name.lower() == lowered or m.image_name.lower() == lowered:
                return m
        return None

    def exports(self, module: Module) -> _ExportTable:
        table = self._exports.get(module.base)
        if table is None:
            table = self._parse_exports(module.base)
            self._exports[module.base] = table
        return table

    def _parse_exports(self, base: int) -> _ExportTable:
        table = _ExportTable()
        try:
            if self.read(base, 2) != b"MZ":
                return table
            nt = base + self.read_u32(base + 0x3C)
            if self.read(nt, 4) != b"PE\0\0":
                return table
            optional_header = nt + 24
            magic = self.read_u16(optional_header)
            data_dirs = optional_header + (0x70 if magic == 0x20B else 0x60)
            export_rva, export_size = struct.unpack("<II", self.read(data_dirs, 8))
            if not export_rva:
                return table
            (_, _, _, _, _, ordinal_base, n_funcs, n_names, funcs_rva, names_rva, ords_rva) = \
                struct.unpack("<IIHHIIIIIII", self.read(base + export_rva, 40))
            n_funcs, n_names = min(n_funcs, 0x10000), min(n_names, 0x10000)
            funcs = struct.unpack(f"<{n_funcs}I", self.read(base + funcs_rva, 4 * n_funcs))
            name_rvas = struct.unpack(f"<{n_names}I", self.read(base + names_rva, 4 * n_names))
            ordinals = struct.unpack(f"<{n_names}H", self.read(base + ords_rva, 2 * n_names))
        except (MiniDumpError, struct.error):
            return table

        names_by_index: dict[int, list[str]] = {}
        for name_rva, index in zip(name_rvas, ordinals):
            if index < n_funcs:
                try:
                    names_by_index.setdefault(index, []).append(self.read_cstring(base + name_rva, 512))
                except MiniDumpError:
                    continue
        entries: list[tuple[int, str]] = []
        for index, rva in enumerate(funcs):
            if rva == 0 or export_rva <= rva < export_rva + export_size:  # forwarded export
                continue
            for name in names_by_index.get(index, [f"Ordinal{ordinal_base + index}"]):
                entries.append((rva, name))
                table.by_name.setdefault(name.lower(), rva)
        # Aliases share an RVA (NtX/ZwX); keep the alphabetically first so output is stable
        entries.sort()
        for rva, name in entries:
            if table.rvas and table.rvas[-1] == rva:
                continue
            table.rvas.append(rva)
            table.names.append(name)
        return table

    def resolve_symbol(self, module_name: str, export_name: str) -> Optional[int]:
        module = self.module_by_name(module_name)
        if module is None:
            return None
        rva = self.exports(module).by_name.get(export_name.lower())
        return None if rva is None else module.base + rva

    def symbolize(self, address: int) -> Optional[str]:
        """module!export+offset (nearest export, no PDB), module+offset, or None outside modules."""
        module = self.module_at(address)
        if module is None:
            return None
        rva = address - module.base
        table = self.exports(module)
        i = bisect.bisect_right(table.rvas, rva) - 1
        if i >= 0:
            offset = rva - table.rvas[i]
            return f"{module.name}!{table.names[i]}" + (f"+{offset:#x}" if offset else "")
        return f"{module.name}+{rva:#x}"

    # ---- process structures (PEB/TEB) ------------------------------------------------------

    @property
    def peb_address(self) -> Optional[int]:
        if self._peb_cache is None:
            peb = None
            for thread in self.threads:
                if not thread.teb:
                    continue
                try:
                    peb = self.read_pointer(thread.teb + self.offsets.teb_peb)
                    break
                except MiniDumpError:
                    continue
            self._peb_cache = (peb,)
        return self._peb_cache[0]

    def process_heaps(self) -> list[int]:
        peb = self.peb_address
        if peb is None:
            return []
        try:
            count = min(self.read_u32(peb + self.offsets.peb_number_of_heaps), 0x1000)
            array = self.read_pointer(peb + self.offsets.peb_process_heaps)
            return [self.read_pointer(array + i * self.pointer_size) for i in range(count)]
        except MiniDumpError:
            return []

    def image_base(self) -> Optional[int]:
        peb = self.peb_address
        if peb is None:
            return None
        try:
            return self.read_pointer(peb + self.offsets.peb_image_base)
        except MiniDumpError:
            return None

    def main_module(self) -> Optional[Module]:
        base = self.image_base()
        if base is not None:
            module = self.module_at(base)
            if module is not None:
                return module
        return self.modules[0] if self.modules else None

    # ---- regions -----------------------------------------------------------------------------

    def region_at(self, address: int) -> Optional[MemoryInfo]:
        i = bisect.bisect_right(self._region_bases, address) - 1
        if i >= 0 and address < self.memory_info[i].end:
            return self.memory_info[i]
        return None

    def classify_regions(self) -> list[Region]:
        """Label each MemoryInfoList region the way WinDbg's !address Usage column does."""
        point_labels: dict[int, list[str]] = {}
        stack_threads: dict[int, list[int]] = {}
        for thread in self.threads:
            teb_region = self.region_at(thread.teb) if thread.teb else None
            if teb_region is not None:
                point_labels.setdefault(teb_region.base_address, []).append(f"TEB ~{thread.index}")
            stack_region = self.region_at(thread.stack_start) if thread.stack_size else None
            if stack_region is not None:
                stack_threads.setdefault(stack_region.allocation_base, []).append(thread.index)
        peb = self.peb_address
        peb_region = self.region_at(peb) if peb is not None else None
        if peb_region is not None:
            point_labels.setdefault(peb_region.base_address, []).insert(0, "PEB")
        heap_bases = set(self.process_heaps())

        regions = []
        for info in self.memory_info:
            if info.state == C.MEM_FREE:
                categories, usage = {"Free"}, "Free"
            elif info.type == C.MEM_IMAGE:
                module = self.module_at(info.base_address)
                categories, usage = {"Image"}, f"Image  {module.image_name}" if module else "Image"
            elif info.base_address in point_labels:
                labels = point_labels[info.base_address]
                categories = {label.split()[0] for label in labels}
                usage = ", ".join(labels)
            elif info.allocation_base in stack_threads:
                categories = {"Stack"}
                usage = "Stack  " + ",".join(f"~{i}" for i in stack_threads[info.allocation_base])
            elif info.allocation_base in heap_bases:
                categories, usage = {"Heap"}, f"Heap  {info.allocation_base:#x}"
            elif info.type == C.MEM_MAPPED:
                categories, usage = {"MappedFile"}, "MappedFile"
            else:
                categories, usage = {"Unknown"}, "<unknown>"
            regions.append(Region(info, frozenset(categories), usage))
        return regions
