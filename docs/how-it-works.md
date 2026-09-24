# How minidbg works

This guide explains what happens inside minidbg, from the first byte it reads to the text each command prints. The worked examples use real numbers from `stealer.DMP` (a full-memory dump of `stealer.exe` on Windows 10 build 17763).

Read it in order the first time. Part 1 is the file format, Part 2 is how minidbg turns file offsets into virtual memory, Part 3 is the plugin system and what happens when you run a command, and Part 4 goes through every plugin.

minidbg is a command-line tool in the style of Volatility: every run is one plugin on one dump.

```
minidbg <dump> <plugin> [plugin options]

minidbg stealer.DMP lm
minidbg stealer.DMP address -f PAGE_READWRITE,MEM_PRIVATE,Unknown
minidbg stealer.DMP s -a "flag{"
minidbg -h                          list all plugins
minidbg stealer.DMP lm -h           options of one plugin
```

## Quick reference

| Plugin | WinDbg | What it answers | Where the data comes from |
|---|---|---|---|
| `dumpdebug` | `.dumpdebug` | What is in this file? | Header, stream directory |
| `vertarget` | `vertarget` | Which Windows, when, how long had the process run? | SystemInfo, MiscInfo, header timestamp |
| `process` | `\|` | Which process is this? | MiscInfo (PID), PEB image base, ModuleList |
| `lm` | `lm`, `lmvm` | Which DLLs were loaded, which versions, which PDBs? | ModuleList, UnloadedModuleList, CodeView records |
| `ln` | `ln` | What function is this address in? | ModuleList + PE export tables read from memory |
| `threads` | `~` | Which threads exist, where are they? | ThreadList, ThreadInfoList, ThreadNames |
| `r` | `r`, `~* r`, `.ecxr` | What were a thread's registers? | Thread CONTEXT record |
| `exr` | `.exr -1` | Why did it crash? | Exception stream |
| `teb`, `peb` | `!teb`, `!peb` | Thread and process structures | Memory, read at fixed offsets |
| `db dw dd dq dps da du` | the same | Show me memory | Memory64List / MemoryList |
| `s` | `s` | Where is this string or byte pattern? | Memory64List / MemoryList |
| `writemem` | `.writemem` | Save memory to a file | Memory64List / MemoryList |
| `address` | `!address` | What is every region of the address space? | MemoryInfoList + everything above |
| `handles` | `!handle` | What files, keys, mutexes were open? | HandleData |
| `heap` | `!heap` | Which heaps does the process have, and which heap manager runs each? | `PEB.ProcessHeaps` + each heap's header |

## Where the code lives

| File | Job |
|---|---|
| `minidbg/minidump.py` | The parser. Opens the file, reads every stream, builds the memory index, reads virtual memory, parses exports, finds the PEB. No printing. |
| `minidbg/heap.py` | Heaps: finds them in `PEB.ProcessHeaps` and tells NT heaps from segment heaps by signature. No printing. |
| `minidbg/constants.py` | Stream numbers, dump flags, protection names, and the fixed offsets for PEB, TEB and CONTEXT. |
| `minidbg/plugin.py` | The `Plugin` base class and `load_plugins()`, which finds every plugin. |
| `minidbg/context.py` | `Context`: the chosen thread and its registers, the expression parser, address formatting. |
| `minidbg/plugins/*.py` | One file per plugin (or per family, like `display.py` for `db`/`dd`/`dq`/…). |
| `minidbg/cli.py` | Loads the plugins, builds the command line, opens the dump, runs one plugin. |
| `~/.local/bin/minidbg` | Two-line launcher, so `minidbg` works from any folder. |
| `tests/dumpbuilder.py` | Writes small minidumps from scratch, so tests know the right answers. |
| `tests/test_minidbg.py` | 23 unit tests. |
| `tests/crosscheck_skelsec.py` | Compares minidbg against skelsec's independent `minidump` library on real dumps. |

The flow for every run is the same:

```
minidbg stealer.DMP lm
        |
        v
cli.main()  ->  load_plugins()           plugin.py: every Plugin subclass in minidbg/plugins/
        |
        v
argparse picks the plugin 'lm' and its options
        |
        v
MiniDump(path)                           minidump.py: header -> directory -> streams -> _finish()
        |
        v
Context(dump, thread options)            context.py: which thread, which registers
        |
        v
Lm(ctx, args).run()                      plugins/lm.py: reads dump.modules, prints the table
```

---

# Part 1 — The file format, and how it is parsed

## 1.1 The big picture

A minidump is a small header, a table of contents (the **stream directory**), and a pile of **streams**. Each stream is one kind of information: the thread list, the module list, the memory. The directory says where each stream starts and how long it is.

Every location inside the file is given as an **RVA**. In minidumps, an RVA is simply a byte offset from the start of the file. It has nothing to do with the RVA inside a PE file.

This is the actual layout of `stealer.DMP`, sorted by file offset:

```
file offset
0x0000000  +-----------------------------------+
           | MINIDUMP_HEADER      (32 bytes)   |  'MDMP', 15 directory entries, directory at 0x20
0x0000020  +-----------------------------------+
           | stream directory  (15 x 12 bytes) |  10 real streams + 5 UnusedStream padding entries
0x00000d4  +-----------------------------------+
           | SystemInfo            (0x38)      |
0x000010c  | MiscInfo              (0x554)     |
0x0000660  | ThreadList            (0x154)     |
0x00007b4  | ThreadInfoList        (0x1cc)     |
0x0000980  | ModuleList            (0x514)     |
           |   ... strings, CONTEXT records,   |
           |   CodeView records ...            |
0x00048cb  | HandleData            (0x1000)    |
0x00058cb  | MemoryInfoList        (0x2ad0)    |
0x000839b  | Memory64List          (0x960)     |  149 (address, size) pairs
0x0008cfb  +-----------------------------------+
           | captured memory, back to back     |  72.9 MB of process memory
           |   range 0   0x7ffe0000   0x1000   |
           |   range 1   0x7ffe2000   0x1000   |
           |   ...                             |
0x48e4cfb  +-----------------------------------+  end of file
```

Nothing forces this order. A parser must always follow the directory instead of assuming positions, and minidbg does.

## 1.2 Opening the file

`MiniDump.__init__` opens the file and memory-maps it with `mmap`. After that, reading bytes at a file offset is a slice (`self._mm[offset:offset + size]`), with no seek or read system calls. That matters when the file is on `/mnt/c`, where every system call goes through WSL's file bridge and is slow.

Every file read goes through `_read_file(offset, size)`. It refuses any read that would run past the end of the file and raises `MiniDumpError` with the exact offset. Truncated or damaged dumps then produce a clear message instead of garbage.

If anything fails during parsing, the constructor closes the file before re-raising the error.

## 1.3 The header

The first 32 bytes are `MINIDUMP_HEADER`. minidbg unpacks it with the `struct` format `"<4sIIIIIQ"`. The `<` means little-endian with no padding.

| Offset | Size | Field | In stealer.DMP |
|---|---|---|---|
| 0x00 | 4 | Signature | `MDMP` |
| 0x04 | 4 | Version | low word `A793` (the format version), high word `A063` (dbghelp's own version) |
| 0x08 | 4 | NumberOfStreams | 15 |
| 0x0C | 4 | StreamDirectoryRva | `0x20` (right after the header) |
| 0x10 | 4 | CheckSum | 0 (almost always unused) |
| 0x14 | 4 | TimeDateStamp | `69ee5780` = 2026-04-26 18:20:48 UTC, when the dump was written |
| 0x18 | 8 | Flags | `0x421826`, the `MINIDUMP_TYPE` the dumping tool asked for |

**Signature check.** If the first four bytes are not `MDMP`, minidbg stops with an error. With `--force` it records a warning and keeps going. That is useful for CTF files with a deliberately broken signature.

**Flags.** `Flags` is a bit field. `decode_dump_flags()` in `constants.py` splits it into names:

```
0x421826 = 0x400000  MiniDumpWithIptTrace
         + 0x020000  MiniDumpIgnoreInaccessibleMemory
         + 0x001000  MiniDumpWithThreadInfo          -> ThreadInfoList stream
         + 0x000800  MiniDumpWithFullMemoryInfo      -> MemoryInfoList stream
         + 0x000020  MiniDumpWithUnloadedModules
         + 0x000004  MiniDumpWithHandleData          -> HandleData stream
         + 0x000002  MiniDumpWithFullMemory          -> Memory64List with all readable memory
```

The flags explain which streams you will find. A dump without `MiniDumpWithFullMemoryInfo` has no MemoryInfoList, so the `address` plugin cannot work on it.

## 1.4 The stream directory

The directory is `NumberOfStreams` entries of 12 bytes each (`"<III"`):

| Offset | Size | Field |
|---|---|---|
| 0x0 | 4 | StreamType |
| 0x4 | 4 | DataSize |
| 0x8 | 4 | Rva |

The last two fields together are called a `MINIDUMP_LOCATION_DESCRIPTOR`. The same pair appears inside many streams whenever one piece of data points at another.

`stealer.DMP` has 15 entries. Ten are real streams and five have type 0 (`UnusedStream`), size 0 and RVA 0. dbghelp reserves extra slots, and parsers skip them.

**Clipping.** Before reading the directory, `_clip()` checks how many 12-byte entries actually fit between the directory offset and the end of the file. If the header claims more, minidbg reads only what fits and records a warning. The same check runs on every list inside every stream, so a corrupted count can never make the parser read past the end of the file.

## 1.5 How streams are dispatched

`_parse_streams()` holds a table from stream type to parser method. For each directory entry it:

1. looks up the parser (types it does not know, like SystemMemoryInfo or Token, are listed by `dumpdebug` but not decoded);
2. skips a second copy of a stream type it has already parsed, with a warning;
3. reads the whole stream (`DataSize` bytes at `Rva`) in one call and hands the bytes to the parser;
4. turns any error inside that parser into a warning, so one bad stream does not stop the others.

Parsers work on the stream's bytes with `struct.unpack_from(format, blob, offset)`. Strings and records that live elsewhere in the file are read separately through their RVA.

### Three kinds of lists

Minidump lists come in three styles. Recognising them makes the whole format easier to read.

**1. Count, then fixed-size entries.** ThreadList, ModuleList, MemoryList and ThreadNames start with a 32-bit count. The entry size is fixed by the documentation.

**2. A self-describing header.** ThreadInfoList, UnloadedModuleList, MemoryInfoList and HandleData start with `SizeOfHeader, SizeOfEntry, NumberOfEntries`. minidbg steps through entries with `header_size + i * entry_size` instead of assuming sizes. A future Windows version can add fields to the end of each entry and old parsers still work.

**3. Memory64List.** This one is special; see section 1.8.

You can check every stream size with simple arithmetic:

| Stream | DataSize | Header + count × entry |
|---|---|---|
| ThreadList | 0x154 | 4 + 7 × 48 = 340 |
| ThreadInfoList | 0x1cc | 12 + 7 × 64 = 460 |
| ModuleList | 0x514 | 4 + 12 × 108 = 1300 |
| HandleData | 0x1000 | 16 + 102 × 40 = 4096 |
| MemoryInfoList | 0x2ad0 | 16 + 228 × 48 = 10960 |
| Memory64List | 0x960 | 16 + 149 × 16 = 2400 |

### Strings

Names are stored as `MINIDUMP_STRING`: a 32-bit length **in bytes** (not counting a terminator), then UTF-16LE text. `read_minidump_string(rva)` reads the length, then the text. In `stealer.DMP` the ntdll module name is at RVA `0x1166`, with length 58: 29 UTF-16 characters, `C:\Windows\System32\ntdll.dll`.

### Packing

The Windows header that defines these structures uses 4-byte packing. So an 8-byte field can sit at an offset that is not a multiple of 8, and a structure's size need not be a multiple of 8. `MINIDUMP_MODULE` is 108 bytes. A C compiler with normal alignment would make it 112, and every module after the first would then be read from the wrong place. Python's `struct` with `<` never pads, which matches the file exactly.

## 1.6 Metadata streams

### SystemInfo (type 7)

Parsed with `"<HHHBBIIIIIHH"` (32 bytes; a 24-byte CPU block follows and is not used):

| Field | Used for |
|---|---|
| ProcessorArchitecture | 9 = x64, 0 = x86, 12 = ARM64. Decides pointer size (8 or 4), which offset table and which CONTEXT layout to use. |
| NumberOfProcessors, ProductType | `vertarget` |
| MajorVersion, MinorVersion, BuildNumber | `vertarget`. Build 22000 or higher on version 10 is Windows 11. |
| CSDVersionRva | Service pack string (a `MINIDUMP_STRING`) |

If a dump has no SystemInfo, minidbg assumes x64 and warns.

### MiscInfo (type 15)

This structure grew over five Windows versions. Each version appends fields, and the first field, `SizeOfInfo`, says which version you have: 24 (v1), 44 (v2), 232 (v3), 832 (v4), 1364 (v5). `stealer.DMP` has 1364.

The `Flags1` field says which parts are valid. minidbg reads:

| Offset | Field | Needs flag |
|---|---|---|
| 8 | ProcessId | `0x1` |
| 12, 16, 20 | ProcessCreateTime (time_t), user time, kernel time (seconds) | `0x2` |
| 44 | ProcessIntegrityLevel (v3+) | `0x10` |
| 52 | ProtectedProcess (v3+) | `0x80` |
| 232 | BuildString, 260 UTF-16 characters (v4+) | `0x100` |
| 752 | DbgBldStr, 40 UTF-16 characters (v4+) | `0x100` |

### ModuleList (type 4)

A 32-bit count, then 108-byte `MINIDUMP_MODULE` entries:

| Offset | Size | Field |
|---|---|---|
| 0x00 | 8 | BaseOfImage |
| 0x08 | 4 | SizeOfImage |
| 0x0C | 4 | CheckSum |
| 0x10 | 4 | TimeDateStamp (from the PE header) |
| 0x14 | 4 | ModuleNameRva (a `MINIDUMP_STRING`) |
| 0x18 | 52 | VersionInfo (`VS_FIXEDFILEINFO`) |
| 0x4C | 8 | CvRecord (DataSize, Rva) |
| 0x54 | 8 | MiscRecord |
| 0x5C | 16 | Reserved |

In `stealer.DMP`, ntdll is entry 1, at file offset `0x980 + 4 + 1 × 108 = 0x9f0`.

- **Version.** `VS_FIXEDFILEINFO` starts with the signature `0xFEEF04BD`. If it matches, the file version is built from `FileVersionMS` and `FileVersionLS`: high word, low word, high word, low word, e.g. `10.0.17763.1`.
- **Module name.** minidbg takes the file name without its extension and replaces anything that is not a letter or digit with `_`. `C:\Windows\System32\KERNEL32.DLL` becomes `KERNEL32`, the same short name WinDbg uses in `KERNEL32!CreateFileW`.
- **CodeView record.** `CvRecord` points to a small record that identifies the module's PDB file. For modern binaries it is `RSDS`, then a 16-byte GUID, a 32-bit age and the PDB name. ntdll's is 0x22 bytes at RVA `0x3618`: `RSDS`, the GUID, age 1, `ntdll.pdb`. The GUID in hex plus the age in hex is the **symbol server key**, `2055091C8F2C5808D8DFE02C75D129591`. Microsoft's symbol server stores that exact PDB under `ntdll.pdb/2055091C8F2C5808D8DFE02C75D129591/ntdll.pdb`, which is how debuggers and Volatility's `pdbutil` fetch the right symbols for a binary. Older binaries use `NB10` records, which identify the PDB by timestamp and age instead.

Modules are sorted by base address after parsing, so lookups can use binary search.

### UnloadedModuleList (type 14)

A self-describing list of 24-byte entries: base, size, checksum, timestamp, name RVA. These are DLLs the process loaded and later unloaded. That is interesting evidence: a DLL that was injected and then removed can still show up here.

## 1.7 Threads

### ThreadList (type 3)

A count, then 48-byte `MINIDUMP_THREAD` entries, parsed with `"<IIIIQQIIII"`:

| Offset | Field |
|---|---|
| 0x00 | ThreadId |
| 0x04 | SuspendCount |
| 0x08 | PriorityClass |
| 0x0C | Priority |
| 0x10 | Teb (address of the thread's TEB) |
| 0x18 | Stack: StartOfMemoryRange (8), DataSize (4), Rva (4) |
| 0x28 | ThreadContext: DataSize (4), Rva (4) |

`Stack` describes the part of the stack that was captured: from roughly the stack pointer up to the stack base. `ThreadContext` points to the thread's saved registers.

ThreadExList (type 8) is the same with 16 more bytes per entry. It is rare, and minidbg reads it the same way with a 64-byte step.

### The CONTEXT record

`CONTEXT` is the structure Windows uses to hold a thread's registers. Its layout depends on the CPU. minidbg reads the registers at these offsets (from `CONTEXT_LAYOUTS` in `constants.py`):

| x64 register | Offset | x86 register | Offset |
|---|---|---|---|
| SegCs … SegSs | 0x38 – 0x42 | SegGs, SegFs, SegEs, SegDs | 0x8C – 0x98 |
| EFlags | 0x44 | Edi, Esi, Ebx, Edx, Ecx, Eax | 0x9C – 0xB0 |
| Rax, Rcx, Rdx, Rbx | 0x78 – 0x90 | Ebp | 0xB4 |
| Rsp, Rbp, Rsi, Rdi | 0x98 – 0xB0 | Eip | 0xB8 |
| R8 … R15 | 0xB8 – 0xF0 | SegCs, EFlags | 0xBC, 0xC0 |
| Rip | 0xF8 | Esp, SegSs | 0xC4, 0xC8 |

The full x64 CONTEXT is 0x4D0 bytes; minidbg only needs the first 0x100. These offsets were checked against the `_CONTEXT` type in all eight of Volatility's Windows symbol files on this machine. Contexts are parsed after all streams are read, because the architecture from SystemInfo has to be known first.

### ThreadInfoList (type 17) and ThreadNames (type 24)

ThreadInfoList adds a 64-byte `MINIDUMP_THREAD_INFO` per thread: dump flags, exit status, creation, exit, kernel and user times (as FILETIME, 100-nanosecond steps since 1601), the **start address** and the CPU affinity. ThreadNames holds `(ThreadId, RVA64 of a MINIDUMP_STRING)` pairs, 12 bytes each, for threads that were given a name with `SetThreadDescription`.

Both are matched to threads by thread ID in `_finish()`. The start address is useful for forensics. A thread that started outside every loaded module began running in memory that no DLL or EXE accounts for, a classic sign of injected code.

## 1.8 Memory: MemoryList and Memory64List

The captured memory is described by one of two streams.

**MemoryList (type 5)** is used by smaller dump types. It is a count followed by 16-byte descriptors: start address (8), size (4), RVA (4). Each range says where its bytes are in the file.

**Memory64List (type 9)** is used by full-memory dumps:

```
offset 0   NumberOfMemoryRanges   (8 bytes)
offset 8   BaseRva                (8 bytes)
offset 16  { StartOfMemoryRange, DataSize }   16 bytes each, no RVA
```

The descriptors have **no RVA**. All the memory is stored in one block starting at `BaseRva`, range after range, in the order of the list. So the file offset of a range is `BaseRva` plus the sizes of all ranges before it. `_parse_memory64_list()` keeps a running total:

```python
rva = base_rva
for each (start, size):
    ranges.append(MemoryRange(start, size, rva))
    rva += size
```

In `stealer.DMP` the list sits at `0x839b`, is `0x960` bytes long, and `BaseRva` is `0x8cfb`, which is `0x839b + 0x960`: the memory starts right after the list.

| # | Virtual address | Size | File offset |
|---|---|---|---|
| 0 | `0x7ffe0000` | 0x1000 | `0x8cfb` |
| 1 | `0x7ffe2000` | 0x1000 | `0x8cfb + 0x1000 = 0x9cfb` |
| 2 | `0xd6fb515000` | 0xf000 | `0x9cfb + 0x1000 = 0xacfb` |

(`0x7ffe0000` is `KUSER_SHARED_DATA`, a page Windows maps at the same address in every process.)

If the running total ends past the end of the file, the dump was cut short, and minidbg warns.

## 1.9 MemoryInfoList (type 16)

This stream records what `VirtualQueryEx` said about every region of the address space: committed, reserved and free regions, not only the captured ones. Header `(16, 48, count)`; `stealer.DMP` has 228 entries. Each 48-byte `MINIDUMP_MEMORY_INFO` holds:

| Field | Meaning |
|---|---|
| BaseAddress, RegionSize | The region |
| AllocationBase, AllocationProtect | The `VirtualAlloc` call this region came from, and its original protection |
| State | `MEM_COMMIT` 0x1000, `MEM_RESERVE` 0x2000, `MEM_FREE` 0x10000 |
| Protect | `PAGE_READWRITE` 0x04, `PAGE_EXECUTE_READ` 0x20, `PAGE_EXECUTE_READWRITE` 0x40, … plus modifiers like `PAGE_GUARD` 0x100 |
| Type | `MEM_PRIVATE` 0x20000, `MEM_MAPPED` 0x40000, `MEM_IMAGE` 0x1000000 |

A region being listed here does not mean its bytes are in the dump. Reserved and free regions have no bytes, guard pages are skipped, and some committed memory cannot be read. The `address` plugin shows the difference in its Captured column.

## 1.10 HandleData, Exception and comments

**HandleData (type 12).** Header `SizeOfHeader, SizeOfDescriptor, NumberOfDescriptors, Reserved`, then descriptors of 32 bytes (version 1) or 40 bytes (version 2): handle value, type name RVA, object name RVA, attributes, granted access, handle count, pointer count. Names are only there if the dumping tool could query them. The File handles in `stealer.DMP` have no names, and skelsec's parser agrees.

**Exception (type 6).** Only crash dumps have it. `"<II"` gives the thread ID. Then comes `MINIDUMP_EXCEPTION` at offset 8: code, flags, a pointer to a nested record, the exception address, the parameter count and up to 15 parameters. At offset 160 is the location of the CONTEXT at the moment of the exception.

**CommentStreamA / CommentStreamW (types 10, 11).** Free text, ANSI or UTF-16, that a tool may attach.

## 1.11 Finishing up: `_finish()`

After every stream is read:

1. Each thread gets its ThreadInfo and name (matched by thread ID) and its parsed CONTEXT.
2. The exception's CONTEXT is parsed.
3. The **memory index** is built: all memory ranges sorted by address, empty ranges dropped and overlaps trimmed. A separate list holds only the start addresses, for binary search.
4. Lists of module base addresses and region base addresses are built for the same reason.

---

# Part 2 — The memory layer

Everything that shows memory, from `db` to `peb` to symbol names, goes through a few methods in `minidump.py`.

## 2.1 Finding the range that holds an address

`find_range(address)` uses `bisect_right` on the sorted start addresses. It finds the last range starting at or below the address, then checks the address is below that range's end. That takes about 8 comparisons for 149 ranges instead of 149.

A full translation, for thread 0's instruction pointer in `stealer.DMP`:

```
virtual address        0x7ffc4b34e614
bisect  ->  range #143 0x7ffc4b2b1000 - 0x7ffc4b3c8000, data at file offset 0x46f8cfb

offset into range      0x7ffc4b34e614 - 0x7ffc4b2b1000 = 0x9d614
file offset            0x46f8cfb + 0x9d614            = 0x479630f
bytes there            c3 cd 2e c3 ...
```

Those bytes are `ret`, `int 2e`, `ret`: the end of ntdll's system call stub, exactly where a thread waiting in the kernel should be.

## 2.2 Reading: `read`, `read(pad=True)`, `read_partial`

A read can cross from one range into the next, or run into memory that was not captured. `_segments(address, size)` splits a request into pieces, each either inside one range or inside a gap:

```
request:  |------------------------------|
ranges:   [ range A ][ range B ]   gap   [ range C ]
pieces:   |  A part  |  B part |  gap  |  C part  |
```

- `read(address, size)` joins the pieces and raises `MemoryNotCaptured` at the first gap.
- `read(address, size, pad=True)` fills gaps with zero bytes. `writemem` uses this.
- `read_partial(address, size)` returns a list where every uncaptured byte is `None`. The display commands print those as `??`, like WinDbg.

Two helpers answer "how much is there?":

- `captured_length(address, limit)` is how many bytes can be read from `address` before the first gap.
- `captured_bytes(start, end)` is how many bytes of `[start, end)` are captured in total. `address` uses it for the Captured column.

## 2.3 Typed reads

- `read_u16`, `read_u32`, `read_u64`, `read_pointer` (4 or 8 bytes depending on the architecture).
- `read_cstring(address, limit, wide)` reads up to the first gap, then cuts at the first NUL (or first aligned double NUL for UTF-16).
- `read_unicode_string(address)` reads a Windows `UNICODE_STRING` structure: `Length` (bytes, u16), `MaximumLength` (u16), then a pointer to the text at +8 on x64 or +4 on x86. It follows the pointer and decodes `Length` bytes.

## 2.4 Searching

`search(pattern, start, end)` is behind the `s` command.

1. `memory_runs()` merges ranges that touch each other into runs. `stealer.DMP` has 149 ranges but only 56 runs. A string that crosses from one range into the next is still found.
2. Each run is clipped to the requested `[start, end)`.
3. The run is read in 16 MB chunks. Each chunk reads `len(pattern) - 1` extra bytes, so a match that starts near the end of a chunk is still complete. Only matches that start inside the chunk proper are reported, so the extra bytes never produce a duplicate.

```
chunk 1: [==========16 MB==========]+overlap
chunk 2:                            [==========16 MB==========]+overlap
                       a match here   ^ is found in chunk 1, and skipped in chunk 2
```

## 2.5 Turning addresses into names (exports)

minidbg has no PDB symbols, so it builds names from each module's **export table**, the list of functions a DLL makes available to other programs. In a full-memory dump the module's headers are in memory, so the table can be read from the dump itself. `_parse_exports(base)` follows the PE format, with ntdll's real values:

```
base + 0x00   'MZ'                          DOS header
base + 0x3C   e_lfanew = 0xe0               where the NT headers start
base + 0xE0   'PE\0\0'                      signature (4 bytes)
              + 20-byte file header
base + 0xF8   optional header, magic 0x20B  0x20B = 64-bit (PE32+), 0x10B = 32-bit
              data directories at +0x70     (+0x60 for 32-bit)
              entry 0 = exports: RVA 0x14c130, size 0x12511

IMAGE_EXPORT_DIRECTORY (40 bytes)
  NumberOfFunctions, NumberOfNames
  AddressOfFunctions     -> array of function RVAs
  AddressOfNames         -> array of name RVAs
  AddressOfNameOrdinals  -> for each name, its index into AddressOfFunctions
```

Rules applied while reading:

- A function RVA that points inside the export directory itself is a **forwarder** (for example `kernel32!AcquireSRWLockExclusive` is really `NTDLL.RtlAcquireSRWLockExclusive`). It is skipped because there is no code at that address.
- Functions exported only by number get the name `Ordinal<n>`.
- When two names share one address (ntdll exports both `NtWaitForSingleObject` and `ZwWaitForSingleObject` for the same code), the alphabetically first is kept, so the output is stable. That picks the `Nt` name.

ntdll ends up with 1819 distinct addresses. Tables are built on first use and cached per module.

`symbolize(address)` then:

1. finds the module with binary search over module bases;
2. converts the address to an offset inside the module;
3. finds the nearest export at or below that offset, again by binary search;
4. returns `module!export+offset`, or `module+offset` if no export is below it, or nothing if the address is not in any module.

**Limitation.** Functions that are not exported get the name of the nearest exported function before them, often with a large offset. WinDbg with PDB symbols would name them exactly. Treat big offsets as "somewhere after this export".

`resolve_symbol(module, name)` goes the other way, for expressions like `ntdll!NtWaitForSingleObject`.

## 2.6 The TEB and PEB

Every thread has a **TEB** (Thread Environment Block) and the process has one **PEB** (Process Environment Block). Both are ordinary user-mode memory, so they are in a full-memory dump. The ThreadList gives each TEB's address. The PEB address is a field inside any TEB.

`peb_address` tries each thread's TEB until one is readable and caches the result. These are the fixed offsets minidbg uses (`NT_OFFSETS` in `constants.py`):

| Field | x64 | x86 |
|---|---|---|
| TEB → StackBase, StackLimit | 0x08, 0x10 | 0x04, 0x08 |
| TEB → ClientId (process id, thread id) | 0x40 | 0x20 |
| TEB → ProcessEnvironmentBlock | 0x60 | 0x30 |
| PEB → BeingDebugged | 0x02 | 0x02 |
| PEB → ImageBaseAddress | 0x10 | 0x08 |
| PEB → Ldr | 0x18 | 0x0C |
| PEB → ProcessParameters | 0x20 | 0x10 |
| PEB → ProcessHeap | 0x30 | 0x18 |
| PEB → NumberOfHeaps, ProcessHeaps | 0xE8, 0xF0 | 0x88, 0x90 |
| Parameters → CurrentDirectory | 0x38 | 0x24 |
| Parameters → DllPath | 0x50 | 0x30 |
| Parameters → ImagePathName | 0x60 | 0x38 |
| Parameters → CommandLine | 0x70 | 0x40 |
| Parameters → Environment | 0x80 | 0x48 |
| Parameters → WindowTitle | 0xB0 | 0x70 |
| Parameters → EnvironmentSize | 0x3F0 | 0x290 |

Most Windows structures change between versions, so hardcoding offsets is normally a mistake. These are an exception. Every x64 symbol file checked (seven kernel builds and one ntdll, from Volatility's symbol folder) has exactly these values, because shellcode, language runtimes and debuggers all depend on them. The heap walker planned for phase 2 will need offsets that do change, and those will come from symbol files.

## 2.7 Labelling regions for `address`

`classify_regions()` gives every MemoryInfoList region a usage label, checking rules in this order. The first rule that matches wins:

| # | Rule | Label |
|---|---|---|
| 1 | State is `MEM_FREE` | `Free` |
| 2 | Type is `MEM_IMAGE` | `Image  <file name of the module there>` |
| 3 | The region contains the PEB or any thread's TEB | `PEB`, `TEB ~0`, … |
| 4 | Its AllocationBase equals that of the region holding a thread's captured stack | `Stack  ~n` |
| 5 | Its AllocationBase is one of the addresses in `PEB.ProcessHeaps` | `Heap  <address>` |
| 6 | Type is `MEM_MAPPED` | `MappedFile` |
| 7 | anything else | `<unknown>` |

Rule 4 compares allocation bases so that all the pieces of one stack get the label: the reserved part, the guard page and the committed part. Rule 5 only recognises a heap's **first** segment, because finding the rest requires walking heap structures. That is phase 2.

`<unknown>` is where to look for oddities, such as the 5 MB private read-write buffer in the keii write-up.

---

# Part 3 — The plugin system

## 3.1 What happens when you run a command

```
minidbg stealer.DMP address -f PAGE_READWRITE
   |
   1  early parse      look only for -p / --plugin-dir
   2  load_plugins()   import every module in minidbg/plugins/ and every .py file in each -p folder;
                       keep the Plugin subclasses that have a name
   3  build parser     one subcommand per plugin (plus its aliases), each with that plugin's own
                       options and the shared thread options
   4  parse argv       args.plugin_class = Address, args.filter = ["PAGE_READWRITE"]
   5  MiniDump(path)   the whole file is parsed (Part 1)
   6  Context(...)     picks the thread and registers (section 3.3)
   7  Address(ctx, args).run()   prints to stdout
```

Why parse twice? The plugins decide which subcommands exist, and `-p` adds plugins. So `-p` has to be read before the real parser can be built. Because the first parse only looks for `-p`, it must come **before** the dump path: `minidbg -p ~/myplugins stealer.DMP badstarts`.

**Output and exit codes.** Results go to standard output and nothing else does. Parser warnings and errors go to standard error, prefixed with `minidbg:`. The exit code tells a script what happened:

| Exit code | Meaning |
|---|---|
| 0 | The plugin ran |
| 1 | The dump or the plugin reported a problem: file not found, bad signature, an address that can't be resolved, memory not captured, a stream the dump doesn't have |
| 2 | The command line itself was wrong (unknown plugin, missing argument), or a plugin file failed to load |

So minidbg output works with the usual tools: `minidbg x.DMP lm > modules.txt`, `minidbg x.DMP s -u password | head`, `minidbg x.DMP address -f Unknown | grep MEM_COMMIT`. When the reader stops early (as `head` does), minidbg exits quietly instead of printing a Python error.

## 3.2 Plugins

Each plugin is a class in `minidbg/plugins/`:

| File | Plugins |
|---|---|
| `dumpdebug.py` | `dumpdebug` |
| `vertarget.py` | `vertarget` |
| `process.py` | `process` |
| `lm.py` | `lm` |
| `ln.py` | `ln` |
| `threads.py` | `threads` |
| `registers.py` | `r` |
| `exr.py` | `exr` |
| `teb.py` | `teb` |
| `peb.py` | `peb` |
| `display.py` | `db`, `dw`, `dd`, `dq`, `dps`, `da`, `du` |
| `search.py` | `s` |
| `writemem.py` | `writemem` |
| `address.py` | `address` |
| `handles.py` | `handles` |
| `heap.py` | `heap` |

This is the whole of `lm.py`'s structure:

```python
class Lm(Plugin):
    name = "lm"                                   # the word you type after the dump
    aliases = ()                                  # other words that also work
    help = "loaded and unloaded modules (DLLs and the EXE)"

    @classmethod
    def add_arguments(cls, parser):               # an argparse parser just for this plugin
        parser.add_argument("pattern", nargs="?")
        parser.add_argument("-v", "--verbose", action="store_true")

    def run(self):                                # self.dump, self.ctx and self.args are ready
        for m in self.dump.modules:
            self.print(...)
```

**How plugins are found.** `load_plugins()` in `plugin.py`:

1. imports every module in the `minidbg/plugins/` package, using `pkgutil.iter_modules`;
2. imports every `.py` file in each `-p` folder, using `importlib.util.spec_from_file_location`;
3. in each module, keeps the classes that subclass `Plugin`, have a non-empty `name`, and were defined in that module. The last rule stops an imported class being counted twice, and helper classes with no name (like `_Display`, the shared parent of `db`/`dd`/`dq`) are skipped;
4. stops with an error naming both files if two plugins claim the same name or alias.

**WinDbg names.** `!address`, `~` and `|` mean something to the shell: `!` is history expansion in bash, `~` is your home folder, `|` is a pipe. So each plugin has a plain name, and the WinDbg spelling is kept as an alias that works when quoted: `minidbg x.DMP '!address'`.

## 3.3 The context: which thread?

Registers belong to a thread. Anything that uses them (`r`, `@rsp` inside an address, `teb`) needs a chosen thread. Every plugin accepts the same options:

| Option | Thread and registers used |
|---|---|
| *(none)* | The thread that caused the exception if it is a crash dump, otherwise thread 0 |
| `-t N` | Thread N, numbered as in `threads` |
| `--tid 1fc8` | The thread with that thread ID (hex) |
| `--ecxr` | The registers saved with the exception, instead of the thread's current ones (crash dumps only) |

`Context` (in `context.py`) holds that choice, and the helpers every plugin uses:

- `fmt()` prints an address the WinDbg way, with a backtick in the middle on 64-bit: `00007ffc`4b34e614`;
- `describe()` prints an address plus its `module!export+offset`;
- `evaluate()` turns an expression into a number (section 3.4);
- `parse_range()` reads a start address and a length (section 3.5);
- `thread_line()` is the one-line thread summary used by `threads` and `r --all`.

## 3.4 Expressions

Wherever a plugin takes an address, you can type an expression. `_Expression` is a small parser:

```
sum   := term (('+' | '-') term)*
term  := 'poi(' sum ')'      read a pointer at that address
       | '(' sum ')'
       | '-' term
       | atom
```

An **atom** is resolved in this order:

| Atom | Meaning | Example |
|---|---|---|
| `@reg` | A register of the chosen thread | `@rsp`, `@rip` |
| `@peb`, `@teb`, `@ip`, `@csp` | Pseudo-registers: PEB, TEB, instruction pointer, stack pointer. WinDbg writes them `@$peb`, and that works too | `@peb+20` |
| `module!export` | An exported function's address | `ntdll!NtWaitForSingleObject` |
| `module` | A module's base address | `kernel32`, `stealer` |
| `0n…` | Decimal | `0n100` = 0x64 |
| anything else | Hexadecimal, with or without `0x` | `7ffe0000`, `0x10` |

Backticks are removed first, so `00007ffc`4b34e614` can be pasted from the output. Numbers are **hex by default**, like WinDbg: `+20` means +0x20. Module names are tried before numbers, so a module called `add` would win over the number 0xadd.

**Quoting in the shell.** Put single quotes around an expression that contains `(`, `)`, `$`, `*` or spaces, or bash will interpret those characters itself:

```
minidbg stealer.DMP dps @rsp L8                       no quotes needed
minidbg stealer.DMP du 'poi(poi(@peb+20)+78)'         PEB -> ProcessParameters -> CommandLine.Buffer
minidbg stealer.DMP dq '@$teb+60' L1                  the WinDbg spelling needs quotes because of $
minidbg stealer.DMP ln ntdll!NtWaitForSingleObject+0x14
```

## 3.5 Ranges

Display, search and save plugins take a start address and an optional extent, parsed by `parse_range`:

| Form | Meaning |
|---|---|
| `ADDR` | The plugin's default length |
| `ADDR L<n>` | n units (bytes for `db`, dwords for `dd`, pointers for `dps`, …) |
| `ADDR L?<n>` | The same; the `?` is accepted because WinDbg uses it to allow very large sizes |
| `ADDR END` | From ADDR up to, not including, END (not for `da`/`du`) |

`n` is an expression too, so it is hex: `L20` is 0x20 units. For `s --range`, a module name on its own also works and means the whole module.

## 3.6 Writing your own plugin

A plugin is one Python file. It does not have to live inside minidbg. This one lists threads that started outside every loaded module, a common sign of injected code:

```python
# ~/minidbg-plugins/badstarts.py
from minidbg.plugin import Plugin


class BadStarts(Plugin):
    name = "badstarts"
    help = "threads whose start address is outside every module"

    def run(self):
        found = 0
        for thread in self.dump.threads:
            start = thread.info.start_address if thread.info else 0
            if start and self.dump.module_at(start) is None:
                self.print(self.ctx.thread_line(thread))
                found += 1
        self.print(f"{found} thread(s) started outside any module")
```

```
$ minidbg -p ~/minidbg-plugins stealer.DMP badstarts
0 thread(s) started outside any module
```

It shows up in `minidbg -p ~/minidbg-plugins -h` like a built-in plugin. To make it permanent, move the file into `minidbg/plugins/`.

A few conventions keep plugins consistent:

- For a problem the user can fix, raise `CommandError("what went wrong and what to do")` from `minidbg.context`. It prints as `minidbg: error: …` with exit code 1. `MiniDumpError` and `MemoryNotCaptured` from reads are handled the same way, so you don't need to catch them unless you want to keep going.
- Take addresses as strings and pass them to `self.ctx.evaluate()` or `self.ctx.parse_range()`, so expressions work the same as in every other plugin.
- Print with `self.print()`.

What `self.dump` offers:

| Kind | Names |
|---|---|
| Parsed streams | `header`, `directory`, `system_info`, `misc_info`, `modules`, `unloaded_modules`, `threads`, `memory_ranges`, `memory_info`, `handles`, `exception`, `comments`, `warnings` |
| Reading memory | `read()`, `read_partial()`, `read_pointer()`, `read_u16/32/64()`, `read_cstring()`, `read_unicode_string()`, `search()`, `find_range()`, `captured_length()`, `captured_bytes()` |
| Modules and names | `module_at()`, `module_by_name()`, `symbolize()`, `resolve_symbol()`, `exports()` |
| Process structures | `peb_address`, `process_heaps()`, `image_base()`, `main_module()`, `offsets` |
| Regions | `region_at()`, `classify_regions()` |
| Target | `architecture`, `pointer_size`, `process_id` |

---

# Part 4 — Every plugin

Each section gives the command, the WinDbg command it matches, what it shows, and how it gets its answer. All plugins also take `-t`, `--tid` and `--ecxr` (section 3.3) and `-h`.

## `dumpdebug`

```
minidbg stealer.DMP dumpdebug                  WinDbg: .dumpdebug
```

**Shows** the header fields, each dump flag by name, every directory entry (type, size, RVA), a memory summary and any parser warnings.

**How.** It prints `dump.header`, runs `decode_dump_flags()`, loops over `dump.directory`, and adds up the sizes of `dump.memory_ranges`. Nothing is read from process memory. If a dump looks wrong, start here: a missing stream or a warning usually explains it.

## `vertarget`

```
minidbg stealer.DMP vertarget                  WinDbg: vertarget
```

**Shows** the Windows version, the edition build string, when the dump was taken, when the process started, its uptime, CPU times, integrity level and whether it was a protected process.

**How.**
- The version line comes from SystemInfo.
- "Edition build lab" is MiscInfo's `BuildString` (v4+).
- The dump time is the header's `TimeDateStamp`.
- Process creation time is MiscInfo's `ProcessCreateTime`, and uptime is the difference between the two.
- Integrity level comes from MiscInfo offset 44, turned into a name (`0x2000` Medium, `0x3000` High, `0x4000` System).

## `process`

```
minidbg stealer.DMP process                    WinDbg: |
```

**Shows** the process ID (hex and decimal) and the path of the main executable.

**How.** The PID is from MiscInfo. The main module is the module that contains `PEB.ImageBaseAddress`. If the PEB cannot be read, it falls back to the first module in the list.

## `lm`

```
minidbg stealer.DMP lm                         WinDbg: lm
minidbg stealer.DMP lm 'kernel*'               WinDbg: lm m kernel*
minidbg stealer.DMP lm -v ntdll                WinDbg: lmvm ntdll
```

**Shows** loaded modules (start, end, name, file version, path) and then unloaded modules.

**How.** It loops over `dump.modules` (sorted by base).
- The pattern filters short names with shell-style wildcards. Quote it, or bash may expand `*` against files in your current folder.
- `-v` adds, for each module: full path, PE timestamp, checksum, image size, file and product version, and the PDB name with its symbol server key.

**Note on timestamps.** Since Windows 10, most Windows DLLs are built "reproducibly", and the PE `TimeDateStamp` field holds a hash instead of a date. A date in 1985 or 2089 is expected.

## `ln`

```
minidbg stealer.DMP ln 7ffc4b34e614            WinDbg: ln
minidbg stealer.DMP ln @rip
```

**Shows** the nearest exported function for an address, or which region it is in when it is not inside a module.

**How.** `symbolize()` from section 2.5. For addresses outside modules it calls `region_at()` (binary search over MemoryInfoList) and prints the region's start and type.

## `threads`

```
minidbg stealer.DMP threads                    WinDbg: ~
```

**Shows** one line per thread:

```
.  0  Id: 15a4.1fc8 Suspend: 0 Teb: 000000d6`fb516000  Ip: ntdll!NtWaitForSingleObject+0x14  Start: stealer+0x79420
^  ^      ^    ^                     ^                       ^                                   ^
|  |      |    thread id             TEB address             symbolized RIP from the CONTEXT     start address (ThreadInfoList)
|  |      process id (MiscInfo)
|  index: use it with -t
'.' = the chosen thread, '#' = the thread that caused the exception
```

If the start address is not inside any module, the line says `(not in any module)`. The thread name is shown in quotes when ThreadNames has one.

## `r`

```
minidbg stealer.DMP r                          WinDbg: r
minidbg stealer.DMP r -t 2                     WinDbg: ~2 r
minidbg stealer.DMP r rip rsp                  WinDbg: r rip, rsp
minidbg stealer.DMP r --all                    WinDbg: ~* r
minidbg crash.dmp r --ecxr                     WinDbg: .ecxr
```

**Shows** the registers of the chosen thread, the decoded flags, the symbol at the instruction pointer and the 16 raw bytes there.

**How.**
- The values come from `ctx.registers`: the exception's CONTEXT with `--ecxr`, otherwise the chosen thread's CONTEXT. With `--all` it loops over every thread's own CONTEXT.
- The flags line decodes the `EFlags` bits the way WinDbg does: `nv/ov` overflow, `up/dn` direction, `ei/di` interrupts, `pl/ng` sign, `nz/zr` zero, `na/ac` auxiliary carry, `po/pe` parity, `nc/cy` carry, and IOPL from bits 12–13.
- There is no disassembler, so the bytes are shown raw. In `stealer.DMP`, `c3 cd 2e c3 0f 1f 84 00 … 4c 8b d1 b8` is `ret; int 2e; ret; nop; mov r10, rcx; mov eax, …`: the end of one ntdll system call stub and the start of the next.

## `exr`

```
minidbg crash.dmp exr                          WinDbg: .exr -1
```

This only works on crash dumps, which have an Exception stream. Task Manager dumps do not have one.

**Shows** the exception address (symbolized), the code with its name, the flags and the parameters. For an access violation (`c0000005`) it also explains the parameters: the first is 0 for a read, 1 for a write, 8 for executing non-executable memory; the second is the address. To see the registers at the moment of the crash, use `r --ecxr`: those are the saved registers of the crash itself, not where the thread is now.

## `teb`

```
minidbg stealer.DMP teb                        WinDbg: !teb
minidbg stealer.DMP teb -t 3                   WinDbg: ~3 !teb
```

**Shows** the chosen thread's TEB: stack base and limit, client ID, PEB address, captured stack range, creation time, start address and name.

**How.** Stack base, limit, client ID and PEB pointer are read from the TEB in memory at the offsets in section 2.6. The captured stack range is the ThreadList `Stack` descriptor. Creation time and start address are from ThreadInfoList. A start address outside every module is flagged. Any field whose memory was not captured shows `<not captured>`.

## `peb`

```
minidbg stealer.DMP peb                        WinDbg: !peb
```

**Shows** the PEB and the process parameters: whether a debugger was attached, image base, loader data, every heap, current directory, window title, image path, **command line**, DLL path and the whole **environment**.

**How.**
1. `peb_address` (section 2.6).
2. Fields read directly from the PEB. The heap list is `NumberOfHeaps` pointers read from the array at `ProcessHeaps`.
3. `ProcessParameters` points to `RTL_USER_PROCESS_PARAMETERS`. Each string field there is a `UNICODE_STRING`, read with `read_unicode_string()`.
4. The environment is a block of UTF-16 `NAME=value` strings, each ending in a NUL, with an extra NUL at the end. minidbg reads `EnvironmentSize` bytes (or up to 64 KB if that field looks wrong), stops at the first uncaptured byte and splits the text.

The command line and environment are often where a CTF hides something, and where malware leaves its arguments.

## `db`, `dw`, `dd`, `dq`

```
minidbg stealer.DMP db stealer L40             WinDbg: db stealer L40
minidbg stealer.DMP dd 7ffe0000
minidbg stealer.DMP dq @teb L10
minidbg stealer.DMP db 7ffe0000 7ffe0040       start and end
```

**Shows** memory as bytes with ASCII, 16-bit words, 32-bit dwords or 64-bit qwords.

| Plugin | Unit | Default | Per line |
|---|---|---|---|
| `db` | 1 byte | 0x80 bytes | 16 bytes + ASCII |
| `dw` | 2 bytes | 0x40 words | 8 |
| `dd` | 4 bytes | 0x20 dwords | 4 |
| `dq` | 8 bytes | 0x10 qwords | 2 |

**How.** `parse_range` gives start and length. `read_partial` returns the bytes with `None` for uncaptured ones, printed as `??`. A value that is partly uncaptured prints as question marks. More than 16 MB is refused; use `writemem` for that.

## `dps`

```
minidbg stealer.DMP dps @rsp L20               WinDbg: dps @rsp L20
minidbg stealer.DMP dps @rsp -t 3
```

Also answers to `dqs` and `dds`.

**Shows** pointer-sized values, one per line, each followed by `module!export+offset` if it points into a module.

**How.** It reads pointer-sized values with `read_partial` and runs `symbolize()` on each. This is the stack inspection tool, since there is no stack unwinder yet. On thread 0 of `stealer.DMP`, `dps @rsp` shows `KERNELBASE!WaitForSingleObjectEx+0x93` at the top: the return address into the function that called `NtWaitForSingleObject`.

## `da`, `du`

```
minidbg stealer.DMP du 'poi(poi(@peb+20)+78)'  WinDbg: du poi(poi(@$peb+20)+78)
minidbg stealer.DMP da stealer+4e L40
```

**Shows** an ASCII (`da`) or UTF-16 (`du`) string at an address.

**How.** It checks the first byte is captured (otherwise it reports an error), then calls `read_cstring`. It reads at most 0x100 bytes for `da` and 0x200 bytes for `du`, or the `L` value. Unlike WinDbg, `L` here counts **bytes** for both, not characters.

## `s`

```
minidbg stealer.DMP s -a 'flag{'                        ASCII text, all captured memory
minidbg stealer.DMP s -u password                       UTF-16 text
minidbg stealer.DMP s -b 4d 5a 90 00                    bytes
minidbg stealer.DMP s -d deadbeef --range stealer       a 32-bit value, only inside stealer.exe
minidbg stealer.DMP s -a SERV --range '7ffe0000 L1000' -n 5
```

WinDbg: `s -a 0 L?7fffffffffff "flag{"`. Also answers to `search`.

**Shows** every place a pattern occurs, with the 16 bytes found there and a symbol if the match is inside a module.

**How.**
- `-a`, `-u`, `-b`, `-w`, `-d` or `-q` picks how the pattern is turned into bytes (`-b` if none is given):
  - `-a`: UTF-8 text;
  - `-u`: UTF-16LE text;
  - `-b`: hex bytes (`de ad be ef` or `deadbeef`);
  - `-w`, `-d`, `-q`: each value packed little-endian as 16, 32 or 64 bits.
- `--range` limits the search (section 3.5); without it, all captured memory is searched.
- `dump.search()` (section 2.4) does the scan. Output stops after 1000 matches unless `-n` says otherwise.

## `writemem`

```
minidbg stealer.DMP writemem payload.bin 2aed6000000 L?4db000     WinDbg: .writemem
minidbg stealer.DMP writemem stealer_hdr.bin stealer L1000
```

**Does** save memory to a file, as in the keii write-up.

**How.** It reads with `read(pad=True)`, so uncaptured bytes become zeros and the file always has the requested size, and it reports how many bytes were filled in. It refuses more than 4 GB.

## `address`

The biggest plugin. It has four forms.

```
minidbg stealer.DMP address                                        WinDbg: !address
minidbg stealer.DMP address -f PAGE_READWRITE,MEM_PRIVATE,Unknown  WinDbg: !address -f:...
minidbg stealer.DMP address --summary                              WinDbg: !address -summary
minidbg stealer.DMP address @rsp                                   WinDbg: !address @rsp
```

**`address`** lists every region from MemoryInfoList:

```
  BaseAddress       EndAddress+1      RegionSize        Type         State        Protect                      Captured Usage
+ 00000241`9bda0000 00000241`9bdc6000 00000000`00026000 MEM_PRIVATE  MEM_COMMIT   PAGE_READWRITE               all      Heap  0x2419bda0000
  000000d6`fb7f9000 000000d6`fb7fc000 00000000`00003000 MEM_PRIVATE  MEM_COMMIT   PAGE_READWRITE | PAGE_GUARD  none     Stack  ~0
```

- `+` marks the first region of an allocation (BaseAddress equals AllocationBase), as in WinDbg.
- **Captured** is `all`, `none` or a percentage for committed regions (from `captured_bytes`), and `-` for reserved or free ones. Stack guard pages show `none`: the dumping tool did not include them.
- **Usage** is the label from section 2.7.

**`address -f <filters>`** keeps only matching regions. The WinDbg spelling `-f:PAGE_READWRITE` also works. A filter can be:

| Kind | Values |
|---|---|
| Protection | `PAGE_NOACCESS`, `PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_WRITECOPY`, `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`, `PAGE_GUARD`, `PAGE_NOCACHE`, `PAGE_WRITECOMBINE` |
| Type | `MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE` |
| State | `MEM_COMMIT`, `MEM_RESERVE`, `MEM_FREE` |
| Usage | `Image`, `Stack`, `Heap`, `TEB`, `PEB`, `Free`, `MappedFile`, `Unknown` |

Filters of the same kind are combined with **or**; different kinds with **and**. So `-f PAGE_READWRITE,MEM_PRIVATE,Unknown` means "read-write, and private, and not identified", which is the search for a hidden buffer. A protection filter compares the base protection, so `PAGE_READWRITE` also matches `PAGE_READWRITE | PAGE_GUARD`. To find code that could have been injected, try `-f PAGE_EXECUTE_READWRITE` or `-f MEM_PRIVATE,PAGE_EXECUTE_READ,PAGE_EXECUTE_READWRITE`.

**`address --summary`** (also `-s` and `-summary`) prints four tables (by usage, type, state and protection) with region count, total size, percentage of used memory and percentage of the whole address space. Free space is included in "% of total" and excluded from "% of busy". On 64-bit Windows the free space is about 128 TB, so "% of total" is tiny for everything else.

**`address <addr>`** describes the one region containing that address: usage, bounds, size, state, protection, type, allocation base and protection, how much is captured, and the symbol if it is inside a module.

## `handles`

```
minidbg stealer.DMP handles                    WinDbg: !handle
minidbg stealer.DMP handles Mutant             only one object type
minidbg stealer.DMP handles -s                 count per type
```

**Shows** open handles: value, type, granted access, handle and pointer counts, and object name.

**How.** It loops over `dump.handles`. The type filter is case-insensitive. Useful types:

| Type | What it tells you |
|---|---|
| `File` | Open files, directories and devices |
| `Key` | Open registry keys (persistence, configuration) |
| `Mutant` | Mutexes. Malware often creates a uniquely named mutex so it runs only once, which makes a good indicator. |
| `Process`, `Thread` | Handles to other processes, needed for injection |
| `Section` | Shared memory |

Access values are raw bit masks. For example `0x00100020` on a File handle is `SYNCHRONIZE | FILE_TRAVERSE`, typical of the handle a process keeps to its current directory.

## `heap`

```
minidbg stealer.DMP heap                       WinDbg: !heap
```

**Shows** every heap the process has: its address, which heap manager runs it, its flags, and which one is the default heap. This is step 1 of phase 2. It lists heaps but does not yet look inside them.

```
  #  Heap Address       Type           Flags     Class              Flag names
  0* 00000241`9bda0000  NT Heap        00000002  0 process heap     GROWABLE
  1  00000241`9bbc0000  NT Heap        00008000  8 CSR port heap
2 heap(s) in PEB.ProcessHeaps; * = PEB.ProcessHeap (what GetProcessHeap() returns)
```

**How the heaps are found.** A heap handle, the value `HeapCreate` and `GetProcessHeap` return, is simply the address of the heap's header. The PEB keeps a list of them:

| PEB field | x64 | x86 | Meaning |
|---|---|---|---|
| `ProcessHeap` | +0x30 | +0x18 | The default heap (`GetProcessHeap()`); marked `*` |
| `NumberOfHeaps` | +0xE8 | +0x88 | How many entries the list has |
| `ProcessHeaps` | +0xF0 | +0x90 | Pointer to an array of heap addresses |

`list_heaps()` in `heap.py` reads the array (with `dump.process_heaps()` from section 2.6), then checks each header with `identify_heap()`.

**Two heap managers.** Windows 10 and 11 have two:

- The **NT heap**, the classic one. Its header is `_HEAP`, which begins with its own first segment (`_HEAP_SEGMENT`).
- The **segment heap**, newer. Its header is `_SEGMENT_HEAP`. Windows uses it for Store apps and some system processes.

Both headers put a signature dword two pointers in, at the same offset. This is how ntdll itself decides which code handles a heap handle:

| Value at +0x10 (x64) / +0x08 (x86) | Meaning |
|---|---|
| `DDEEDDEE` | `_SEGMENT_HEAP.Signature`: a segment heap |
| `FFEEFFEE` | `_HEAP_SEGMENT.SegmentSignature`: an NT heap *segment* |

`FFEEFFEE` alone is not enough, because every NT heap segment has it, including a heap's extra segments. Only the heap header also has `_HEAP.Signature = EEFFEEFF` at +0x98 (x86: +0x64). minidbg checks both. Anything else is shown as `unrecognised` with the dword it found. If the header was not saved in the dump, the row says `<not captured>`.

**Flags and class.** For NT heaps, `_HEAP.Flags` (+0x70; x86 +0x40) holds the `HEAP_*` flags the heap was created with. Bits 12–15 are the heap *class*, which says who created it:

| Class | Flags | Who creates it |
|---|---|---|
| 0 process heap | `00000002` | The loader, at process start: the default heap |
| 1 private heap | `00001002` | `HeapCreate` (the C runtime and many DLLs do this) |
| 7 CSR shared heap | `00007008` | csrss.exe itself (seen only there in `memhere.mem`) |
| 8 CSR port heap | `00008000` | Shared with csrss.exe when the process connects to it. 111 of the 115 processes in `memhere.mem` have one |

`GROWABLE` (0x2) means the heap can add segments when it is full. Heaps made with a maximum size don't have it. Segment heaps store their flags differently, so their row shows `-` for now.

**Where the offsets come from.** They are not guessed. The x64 values match all 8 of Volatility's 64-bit symbol files on this machine (7 kernels and one ntdll; one kernel is old enough to have no segment heap at all), and the x86 `_HEAP` values match the one 32-bit file. That file predates the segment heap, so the x86 `_SEGMENT_HEAP.Signature` offset (+0x08) is derived from the structure (it comes after two pointers), not checked.

**Checked on real data.** A throwaway Volatility plugin read the same dwords for every heap of every process in `memhere.mem` (Windows 10 19041):

- 188 NT heaps, all with both signatures;
- 227 segment heaps, in svchost, lsass, csrss, services, smss, RuntimeBroker, msedge and others (in 90 processes the *default* heap is a segment heap);
- 12 heaps whose header was paged out.

All NT heap flags decoded to classes from the table above. Your three minidumps contain only NT heaps. A dump of lsass or svchost would show segment heaps.

---

# Part 5 — How it was checked, and what is missing

## Tests

`python3 -m unittest discover -s tests` runs 23 tests against minidumps that `tests/dumpbuilder.py` writes from scratch. Because the builder puts every byte in place, each test knows the exact right answer. They cover:

- header and flags; a second module in the list (proves the 108-byte step);
- Memory64 offsets adding up; reads across two adjacent ranges; reads into a gap (error, padding, `None`);
- search across a range boundary and inside a limited range;
- thread registers, start address and name; export-based symbols and reverse lookup;
- PEB, heaps and command line; region labels; handles, exception, MiscInfo, comments;
- `heap`: an NT heap, a segment heap, an NT segment that is not a heap header, and a heap that was not captured; the flag and class names; the x86 offsets;
- a 32-bit dump (pointer size 4, x86 registers, x86 PEB offsets);
- a bad signature (needs `--force`) and an impossible module count (clipped with a warning);
- every plugin, run through the real command line, prints what it should;
- the plugin system: WinDbg-name aliases, a plugin loaded from a `-p` folder, and errors going to stderr with exit codes 1 and 2.

## Cross-check against an independent parser

`python3 tests/crosscheck_skelsec.py <dump> …` compares minidbg with skelsec's `minidump` library (the parser behind pypykatz): modules, threads, registers, memory ranges and their file offsets, memory regions, handles, system info, PID, and 2000 random 64-byte memory reads. All three of your dumps pass 9 of 9.

One difference is expected. skelsec cannot represent combined protections like `PAGE_READWRITE | PAGE_GUARD` (0x104) and reports `None`; minidbg keeps the real value. The script allows for that.

## Not there yet

- **No PDB symbols.** Names come from export tables only (section 2.5).
- **No disassembler (`u`) and no call stack (`k`).** Use `r` for the raw bytes and `dps @rsp` for the stack.
- **Registers for x64 and x86 only.** ARM64 dumps parse, but `r` has nothing to show.
- **Heap contents.** `heap` lists the heaps (step 1 of phase 2) but does not walk them, and `address` recognises only each heap's first segment. Next steps: `_HEAP.SegmentList` → `_HEAP_ENTRY`, decode the encoded entry headers, then the LFH and large allocations, then segment heaps.
- **Streams listed but not decoded:** Token, SystemMemoryInfo, ProcessVmCounters, IptTrace, FunctionTable, HandleOperationList.
- **Kernel dumps** (`PAGEDU64`, e.g. `C:\Windows\MEMORY.DMP` and the files in `C:\Windows\Minidump`) are a different format. Use Volatility or WinDbg for those.
