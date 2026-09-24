from ..context import CommandError, fmt_time
from ..minidump import MiniDumpError, filetime_to_datetime
from ..plugin import Plugin


class Teb(Plugin):
    name = "teb"
    aliases = ("!teb",)
    help = "TEB of a thread: stack bounds, ids, start address, creation time"

    def run(self) -> None:
        ctx, dump, thread = self.ctx, self.dump, self.ctx.thread
        if thread is None:
            raise CommandError("this dump has no threads")
        off = dump.offsets
        self.print(f"TEB at {ctx.fmt(thread.teb)}  (thread {thread.index}, id {thread.thread_id:x})")

        def field(label, reader):
            try:
                value = reader()
            except MiniDumpError:
                value = "<not captured>"
            self.print(f"    {label:<18}{value}")

        field("StackBase:", lambda: ctx.fmt(dump.read_pointer(thread.teb + off.teb_stack_base)))
        field("StackLimit:", lambda: ctx.fmt(dump.read_pointer(thread.teb + off.teb_stack_limit)))
        field("ClientId:", lambda: f"{dump.read_pointer(thread.teb + off.teb_client_id):x}."
                                   f"{dump.read_pointer(thread.teb + off.teb_client_id + dump.pointer_size):x}")
        field("PEB Address:", lambda: ctx.fmt(dump.read_pointer(thread.teb + off.teb_peb)))
        self.print(f"    {'Captured stack:':<18}{ctx.fmt(thread.stack_start)} - "
                   f"{ctx.fmt(thread.stack_start + thread.stack_size)} ({thread.stack_size:#x} bytes)")
        if thread.info is not None:
            start = thread.info.start_address
            self.print(f"    {'Created:':<18}{fmt_time(filetime_to_datetime(thread.info.create_time))}")
            self.print(f"    {'Start address:':<18}{ctx.describe(start)}"
                       + ("" if dump.module_at(start) else "  <-- not inside any module"))
        if thread.name:
            self.print(f"    {'Name:':<18}{thread.name}")
