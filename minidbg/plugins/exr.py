from .. import constants as C
from ..context import CommandError
from ..plugin import Plugin


class Exr(Plugin):
    name = "exr"
    aliases = (".exr",)
    help = "the exception record of a crash dump: code, address, parameters"

    def run(self) -> None:
        ctx, exc = self.ctx, self.dump.exception
        if exc is None:
            raise CommandError("no exception stream in this dump (it isn't a crash dump)")
        self.print(f"ExceptionAddress: {ctx.describe(exc.address)}")
        self.print(f"   ExceptionCode: {exc.code:08x} ({C.EXCEPTION_CODES.get(exc.code, 'unknown')})")
        self.print(f"  ExceptionFlags: {exc.flags:08x}")
        self.print(f"NumberParameters: {len(exc.parameters)}")
        for i, param in enumerate(exc.parameters):
            self.print(f"   Parameter[{i}]: {param:016x}")
        if exc.code == 0xC0000005 and len(exc.parameters) >= 2:
            verb = {0: "read from", 1: "write to", 8: "execute (DEP) at"}.get(exc.parameters[0], "access")
            self.print(f"Attempt to {verb} address {ctx.fmt(exc.parameters[1])}")
        thread = self.dump.thread_by_id(exc.thread_id)
        self.print(f"Thread: {exc.thread_id:x}" + (f" (thread {thread.index})" if thread else ""))
        self.print("Registers at the time of the exception: minidbg <dump> r --ecxr")
