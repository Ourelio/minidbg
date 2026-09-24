from ..context import CommandError
from ..minidump import MiniDumpError
from ..plugin import Plugin


class Peb(Plugin):
    name = "peb"
    aliases = ("!peb",)
    help = "PEB: image, heaps, current directory, command line, environment"

    def run(self) -> None:
        ctx, dump = self.ctx, self.dump
        off = dump.offsets
        peb = dump.peb_address
        if peb is None:
            raise CommandError("PEB not available (no TEB memory captured in this dump)")
        self.print(f"PEB at {ctx.fmt(peb)}")

        def field(label, reader):
            try:
                value = reader()
            except MiniDumpError:
                value = "<not captured>"
            self.print(f"    {label:<20}{value}")

        field("BeingDebugged:", lambda: "Yes" if dump.read(peb + off.peb_being_debugged, 1)[0] else "No")
        field("ImageBaseAddress:", lambda: ctx.describe(dump.read_pointer(peb + off.peb_image_base)))
        field("Ldr:", lambda: ctx.fmt(dump.read_pointer(peb + off.peb_ldr)))
        field("ProcessHeap:", lambda: ctx.fmt(dump.read_pointer(peb + off.peb_process_heap)))
        heaps = dump.process_heaps()
        self.print(f"    {'ProcessHeaps:':<20}{len(heaps)} heap(s)")
        for heap in heaps:
            self.print(f"    {'':<20}{ctx.fmt(heap)}")
        try:
            params = dump.read_pointer(peb + off.peb_process_parameters)
        except MiniDumpError:
            self.print(f"    {'ProcessParameters:':<20}<not captured>")
            return
        self.print(f"    {'ProcessParameters:':<20}{ctx.fmt(params)}")
        field("CurrentDirectory:", lambda: f"'{dump.read_unicode_string(params + off.upp_current_directory)}'")
        field("WindowTitle:", lambda: f"'{dump.read_unicode_string(params + off.upp_window_title)}'")
        field("ImageFile:", lambda: f"'{dump.read_unicode_string(params + off.upp_image_path_name)}'")
        field("CommandLine:", lambda: f"'{dump.read_unicode_string(params + off.upp_command_line)}'")
        field("DllPath:", lambda: f"'{dump.read_unicode_string(params + off.upp_dll_path)}'")
        try:
            env = dump.read_pointer(params + off.upp_environment)
            size = dump.read_pointer(params + off.upp_environment_size)
            if not 0 < size <= 0x100000:
                size = 0x10000
            data = dump.read(env, dump.captured_length(env, size))
        except MiniDumpError:
            self.print(f"    {'Environment:':<20}<not captured>")
            return
        self.print(f"    {'Environment:':<20}{ctx.fmt(env)}")
        text = data[: len(data) & ~1].decode("utf-16-le", errors="replace").split("\0\0", 1)[0]
        for entry in text.split("\0"):
            if entry:
                self.print(f"        {entry}")
