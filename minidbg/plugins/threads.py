from ..context import CommandError
from ..plugin import Plugin


class Threads(Plugin):
    name = "threads"
    aliases = ("~",)
    help = "all threads with their instruction pointer, start address and name"

    def run(self) -> None:
        if not self.dump.threads:
            raise CommandError("this dump has no thread list")
        for thread in self.dump.threads:
            self.print(self.ctx.thread_line(thread))
