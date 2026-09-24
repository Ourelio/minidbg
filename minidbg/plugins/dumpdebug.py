from .. import constants as C
from ..context import fmt_time, human_size
from ..minidump import time_t_to_datetime
from ..plugin import Plugin


class DumpDebug(Plugin):
    name = "dumpdebug"
    aliases = (".dumpdebug",)
    help = "header, dump flags and stream directory of the file"

    def run(self) -> None:
        dump, h = self.dump, self.dump.header
        self.print("MINIDUMP_HEADER:")
        self.print(f"Signature           {h.signature!r}")
        self.print(f"Version             {h.version & 0xFFFF:X} ({h.version >> 16:X})")
        self.print(f"NumberOfStreams     {h.number_of_streams}")
        self.print(f"StreamDirectoryRva  {h.stream_directory_rva:08x}")
        self.print(f"CheckSum            {h.checksum:08x}")
        self.print(f"TimeDateStamp       {h.time_date_stamp:08x} {fmt_time(time_t_to_datetime(h.time_date_stamp))}")
        self.print(f"Flags               {h.flags:x}")
        for bit, name in C.decode_dump_flags(h.flags):
            self.print(f"                    {bit:08x} {name}")
        self.print()
        self.print("Streams:")
        for entry in dump.directory:
            self.print(f"Stream {entry.index:>2}: type {entry.name} ({entry.stream_type}), "
                       f"size {entry.data_size:08x}, RVA {entry.rva:08x}")
        captured = sum(r.size for r in dump.memory_ranges)
        self.print()
        self.print(f"Memory: {len(dump.memory_ranges)} ranges, {captured:#x} bytes captured "
                   f"({human_size(captured).strip()}); file size {dump.file_size:#x}")
        if dump.warnings:
            self.print()
            self.print("Parser warnings:")
            for warning in dump.warnings:
                self.print(f"  {warning}")
