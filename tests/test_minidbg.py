import contextlib
import io
import os
import struct
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import dumpbuilder as B  # noqa: E402
from minidbg import MemoryNotCaptured, MiniDump, MiniDumpError  # noqa: E402
from minidbg.cli import main  # noqa: E402
from minidbg.heap import NT_HEAP, SEGMENT_HEAP, heap_class, heap_flag_names, list_heaps  # noqa: E402
from minidbg.plugin import load_plugins  # noqa: E402


def write_temp(data: bytes, suffix: str = ".dmp") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class X64DumpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = write_temp(B.build_x64_dump())
        cls.dump = MiniDump(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.dump.close()
        os.remove(cls.path)

    def test_parses_without_warnings(self):
        self.assertEqual(self.dump.warnings, [])

    def test_header(self):
        h = self.dump.header
        self.assertEqual(h.signature, b"MDMP")
        self.assertEqual(h.version & 0xFFFF, 0xA793)
        self.assertEqual(h.flags, 0x421826)
        self.assertEqual(len(self.dump.directory), 16)

    def test_second_module_proves_108_byte_stride(self):
        paths = [m.path for m in self.dump.modules]
        self.assertEqual(paths, ["C:\\app\\app.exe", "C:\\Windows\\System32\\testmod.dll"])
        testmod = self.dump.modules[1]
        self.assertEqual(testmod.name, "testmod")
        self.assertEqual(testmod.file_version, "10.0.19041.1")
        self.assertEqual(testmod.codeview.pdb_name, "testmod.pdb")
        self.assertEqual(testmod.codeview.symbol_key, "123456789ABCDEF011223344556677881")

    def test_memory64_offsets_are_cumulative(self):
        ranges = self.dump.memory_ranges
        for prev, cur in zip(ranges, ranges[1:]):
            self.assertEqual(cur.rva, prev.rva + prev.size)

    def test_read_across_adjacent_ranges(self):
        self.assertEqual(self.dump.read(B.TESTMOD + 0xFFE, 4), b"SPAN")

    def test_read_gap_raises_or_pads(self):
        with self.assertRaises(MemoryNotCaptured):
            self.dump.read(0x12000, 1)
        with self.assertRaises(MemoryNotCaptured):
            self.dump.read(0x11FFE, 4)
        self.assertEqual(self.dump.read(0x11FFE, 4, pad=True)[2:], b"\0\0")
        self.assertEqual(self.dump.read_partial(0x11FFE, 4)[2:], [None, None])

    def test_search(self):
        self.assertEqual(list(self.dump.search(b"SPAN")), [B.TESTMOD + 0xFFE])
        self.assertEqual(list(self.dump.search(b"FINDME_1337")), [B.UNKNOWN + 0x123])
        self.assertEqual(list(self.dump.search(b"FINDME_1337", 0, B.UNKNOWN + 0x100)), [])

    def test_thread_context_info_and_name(self):
        thread = self.dump.threads[0]
        self.assertEqual(thread.thread_id, B.TID)
        self.assertEqual(thread.context["rip"], B.TESTMOD + 0x1014)
        self.assertEqual(thread.context["rsp"], B.STACK_POINTER)
        self.assertEqual(thread.context["cs"], 0x33)
        self.assertEqual(thread.info.start_address, B.UNKNOWN)
        self.assertEqual(thread.name, "worker")

    def test_symbolize_with_exports(self):
        self.assertEqual(self.dump.symbolize(B.TESTMOD + 0x1014), "testmod!FuncA+0x14")
        self.assertEqual(self.dump.symbolize(B.TESTMOD + 0x1100), "testmod!FuncB")
        self.assertEqual(self.dump.symbolize(B.TESTMOD + 0x10), "testmod+0x10")
        self.assertIsNone(self.dump.symbolize(B.UNKNOWN))
        self.assertEqual(self.dump.resolve_symbol("TESTMOD", "funcb"), B.TESTMOD + 0x1100)

    def test_peb_structures(self):
        self.assertEqual(self.dump.peb_address, B.PEB)
        self.assertEqual(self.dump.process_heaps(), [B.HEAP, B.SEGMENT_HEAP, B.NOT_A_HEAP, B.MISSING_HEAP])
        self.assertEqual(self.dump.main_module().path, "C:\\app\\app.exe")
        command_line = self.dump.read_unicode_string(B.PARAMS + self.dump.offsets.upp_command_line)
        self.assertEqual(command_line, B.COMMAND_LINE)

    def test_region_usage(self):
        usages = {r.info.base_address: (r.usage, r.categories) for r in self.dump.classify_regions()}
        self.assertEqual(usages[B.TEB][1], {"PEB", "TEB"})
        self.assertEqual(usages[0x20000][1], {"Stack"})
        self.assertEqual(usages[B.HEAP][1], {"Heap"})
        self.assertEqual(usages[B.UNKNOWN][0], "<unknown>")
        self.assertEqual(usages[0x60000][1], {"Free"})
        self.assertEqual(usages[B.TESTMOD][0], "Image  testmod.dll")

    def test_list_heaps(self):
        heaps = list_heaps(self.dump)
        self.assertEqual([h.address for h in heaps], [B.HEAP, B.SEGMENT_HEAP, B.NOT_A_HEAP, B.MISSING_HEAP])
        self.assertEqual([h.kind for h in heaps], [NT_HEAP, SEGMENT_HEAP, None, None])
        self.assertEqual([h.default for h in heaps], [True, False, False, False])
        self.assertEqual([h.captured for h in heaps], [True, True, True, False])
        self.assertEqual(heaps[0].flags, 0x2)
        self.assertEqual(heaps[2].signature, 0xFFEEFFEE)    # a segment signature alone isn't a heap

    def test_heap_flag_decoding(self):
        self.assertEqual(heap_class(0x8000), "8 CSR port heap")
        self.assertEqual((heap_class(0x7008), heap_flag_names(0x7008)), ("7 CSR shared heap", "ZERO_MEMORY"))
        self.assertEqual(heap_flag_names(0x1002), "GROWABLE")
        self.assertEqual(heap_flag_names(0x100003), "NO_SERIALIZE | GROWABLE | 0x100000")

    def test_misc_system_handles_exception(self):
        self.assertEqual(self.dump.process_id, B.PID)
        self.assertEqual(self.dump.misc_info.integrity_level, 0x3000)
        self.assertTrue(self.dump.misc_info.build_string.startswith("19041.1.amd64fre"))
        self.assertEqual(self.dump.system_info.build_number, 19045)
        self.assertEqual([h.type_name for h in self.dump.handles], ["File", "Mutant"])
        self.assertEqual(self.dump.exception.code, 0xC0000005)
        self.assertEqual(self.dump.exception.parameters, [1, 0xDEADBEEF])
        self.assertEqual(self.dump.exception.context["rip"], B.TESTMOD + 0x1014)
        self.assertEqual(self.dump.unloaded_modules[0].path, "C:\\evil\\gone.dll")
        self.assertEqual(self.dump.comments, ["hello from the builder"])

    def test_plugins_from_the_command_line(self):
        cases = [
            (["peb"], ["CTF{minidump}", "A=1", "B=2", "BeingDebugged:      Yes"]),
            (["!peb"], ["CTF{minidump}"]),
            (["s", "-a", "FINDME"], ["00000000`00050123"]),
            (["s", "-a", "FINDME", "--range", "testmod"], ["no matches"]),
            (["s", "-b", "53", "50", "41", "4e"], ["00007ff8`00000ffe"]),
            (["threads"], ["Ip: testmod!FuncA+0x14", "Start: 00000000`00050000 (not in any module)", '"worker"']),
            (["r"], ["rip=00007ff800001014", "testmod!FuncA+0x14:"]),
            (["r", "rip", "-t", "0"], ["rip=7ff800001014"]),
            (["r", "--ecxr", "rsp"], ["rsp=20f00"]),
            (["r", "--all"], ["rip=00007ff800001014"]),
            (["dps", "@rsp", "L1"], ["testmod!FuncB+0x10"]),
            (["exr"], ["Access violation", "Attempt to write to address 00000000`deadbeef"]),
            (["address", "-f", "Heap"], ["00000000`00030000"]),
            (["address", "-f:Unknown"], ["00000000`00050000"]),
            (["!address", "-summary"], ["Usage Summary"]),
            (["address", "50123"], ["Usage:                  <unknown>"]),
            (["lm"], ["testmod", "Unloaded modules:", "gone.dll"]),
            (["lm", "-v", "test*"], ["symbol server key 123456789ABCDEF011223344556677881"]),
            (["handles", "Mutant"], ["evil_mutex"]),
            (["handles", "-s"], ["File", "2 handles"]),
            (["ln", "testmod!FuncB+10"], ["testmod!FuncB+0x10"]),
            (["db", "11ffe", "L4"], ["?? ??"]),
            (["du", "poi(poi(@$peb+20)+78)"], ["CTF{minidump}"]),
            (["dq", "@$teb+60", "L1"], ["00000000`00011000"]),
            (["vertarget"], ["Windows 10 Version 10.0.19045", "Integrity level:    High"]),
            (["dumpdebug"], ["MiniDumpWithFullMemory", "Memory64ListStream (9)"]),
            (["process"], ["name: C:\\app\\app.exe"]),
            (["heap"], ["  0* 00000000`00030000  NT Heap        00000002  0 process heap     GROWABLE",
                        "  1  00000000`00040000  Segment Heap   -",
                        "  2  00000000`00030800  unrecognised",  "(signature dword is ffeeffee)",
                        "  3  00000000`00070000  <not captured>", "4 heap(s) in PEB.ProcessHeaps"]),
            (["!heap"], ["Segment Heap"]),
            (["teb"], ["ClientId:         1000.1234", "<-- not inside any module"]),
        ]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                code, out, err = run_cli(self.path, *argv)
                self.assertEqual(code, 0, err)
                for text in expected:
                    self.assertIn(text, out)

    def test_address_filter_excludes_other_usages(self):
        _, out, _ = run_cli(self.path, "address", "-f", "Unknown")
        self.assertIn("00000000`00050000", out)
        self.assertNotIn("Heap", out)

    def test_errors_go_to_stderr_with_exit_codes(self):
        code, out, err = run_cli(self.path, "db", "zzz")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("couldn't resolve 'zzz'", err)
        code, _, err = run_cli(self.path, "r", "-t", "5")
        self.assertEqual(code, 1)
        self.assertIn("no thread 5", err)
        code, _, err = run_cli(self.path, "nosuchplugin")
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", err)
        code, _, err = run_cli("/nonexistent.dmp", "lm")
        self.assertEqual(code, 1)

    def test_writemem(self):
        out_path = write_temp(b"", suffix=".bin")
        try:
            code, _, err = run_cli(self.path, "writemem", out_path, f"{B.UNKNOWN + 0x120:x}", "L10")
            self.assertEqual(code, 0, err)
            with open(out_path, "rb") as f:
                self.assertEqual(f.read(), self.dump.read(B.UNKNOWN + 0x120, 0x10))
        finally:
            os.remove(out_path)


class PluginSystemTests(unittest.TestCase):
    def test_builtin_plugins_and_aliases_are_unique(self):
        plugins = load_plugins()
        self.assertIn("lm", plugins)
        self.assertIn("address", plugins)
        self.assertIn("!address", plugins["address"].aliases)

    def test_plugin_from_a_folder(self):
        dump_path = write_temp(B.build_x64_dump())
        try:
            with tempfile.TemporaryDirectory() as folder:
                with open(os.path.join(folder, "countmods.py"), "w") as f:
                    f.write(textwrap.dedent("""
                        from minidbg.plugin import Plugin

                        class CountModules(Plugin):
                            name = "countmods"
                            help = "how many modules are loaded"

                            @classmethod
                            def add_arguments(cls, parser):
                                parser.add_argument("--prefix", default="modules:")

                            def run(self):
                                self.print(f"{self.args.prefix} {len(self.dump.modules)}")
                    """))
                code, out, err = run_cli("-p", folder, dump_path, "countmods", "--prefix", "loaded")
                self.assertEqual(code, 0, err)
                self.assertEqual(out.strip(), "loaded 2")
        finally:
            os.remove(dump_path)


class X86DumpTests(unittest.TestCase):
    def test_x86_pointer_size_context_and_peb(self):
        path = write_temp(B.build_x86_dump())
        try:
            with MiniDump(path) as dump:
                self.assertEqual(dump.pointer_size, 4)
                self.assertEqual(dump.threads[0].context["eip"], 0x401000)
                self.assertEqual(dump.threads[0].context["esp"], 0x12FF00)
                self.assertEqual(dump.peb_address, B.X86_PEB)
                self.assertEqual(dump.system_info.csd_version, "Service Pack 1")
            _, out, _ = run_cli(path, "peb")
            self.assertIn("'calc.exe /x86'", out)
            self.assertIn("PEB at 7ffdf000", out)
            _, out, _ = run_cli(path, "r")
            self.assertIn("eip=00401000", out)
            _, out, _ = run_cli(path, "heap")
            self.assertIn("  0* 00150000      NT Heap        00001002  1 private heap     GROWABLE", out)
        finally:
            os.remove(path)


class CorruptionTests(unittest.TestCase):
    def test_bad_signature_needs_force(self):
        data = bytearray(B.build_x64_dump())
        data[0:4] = b"XXXX"
        path = write_temp(bytes(data))
        try:
            with self.assertRaises(MiniDumpError):
                MiniDump(path)
            with MiniDump(path, force=True) as dump:
                self.assertEqual(len(dump.modules), 2)
                self.assertTrue(any("bad signature" in w for w in dump.warnings))
            self.assertEqual(run_cli(path, "lm")[0], 1)
            self.assertEqual(run_cli("--force", path, "lm")[0], 0)
        finally:
            os.remove(path)

    def test_oversized_module_count_is_clipped(self):
        data = bytearray(B.build_x64_dump())
        path = write_temp(bytes(data))
        with MiniDump(path) as dump:
            module_rva = next(e.rva for e in dump.directory if e.stream_type == 4)
        struct.pack_into("<I", data, module_rva, 100000)
        with open(path, "wb") as f:
            f.write(data)
        try:
            with MiniDump(path) as dump:
                self.assertEqual(len(dump.modules), 2)
                self.assertTrue(any("clipping" in w for w in dump.warnings))
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
