from .. import constants as C
from ..context import CommandError
from ..plugin import Plugin


def _eflags_text(efl: int) -> str:
    bits = [(11, "ov", "nv"), (10, "dn", "up"), (9, "ei", "di"), (7, "ng", "pl"),
            (6, "zr", "nz"), (4, "ac", "na"), (2, "pe", "po"), (0, "cy", "nc")]
    return f"iopl={(efl >> 12) & 3}         " + " ".join(on if efl >> bit & 1 else off for bit, on, off in bits)


class R(Plugin):
    name = "r"
    help = "registers of a thread (default: the crashing thread, else thread 0)"

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("registers", nargs="*", metavar="REG", help="only these registers, e.g. rip rsp")
        parser.add_argument("--all", action="store_true", help="every thread, one after another (WinDbg: ~* r)")

    def run(self) -> None:
        if self.args.all:
            for thread in self.dump.threads:
                self.ctx.thread_index = thread.index
                self.print(self.ctx.thread_line(thread))
                self._show(thread.context or {})
                self.print()
            return
        self._show(self.ctx.registers)

    def _show(self, regs: dict[str, int]) -> None:
        ctx = self.ctx
        if not regs:
            raise CommandError("no register context for this thread (unsupported architecture or not captured)")
        if self.args.registers:
            for arg in self.args.registers:
                name = arg.lower().lstrip("@")
                if name not in regs:
                    raise CommandError(f"unknown register '{arg}'")
                self.print(f"{name}={regs[name]:x}")
            return
        if self.dump.architecture == C.ARCH_AMD64:
            rows = [["rax", "rbx", "rcx"], ["rdx", "rsi", "rdi"], ["rip", "rsp", "rbp"],
                    ["r8", "r9", "r10"], ["r11", "r12", "r13"], ["r14", "r15"]]
            for row in rows:
                self.print(" ".join(f"{name:>3}={regs[name]:016x}" for name in row))
            self.print(_eflags_text(regs["eflags"]))
            self.print(f"cs={regs['cs']:04x}  ss={regs['ss']:04x}  ds={regs['ds']:04x}  es={regs['es']:04x}  "
                       f"fs={regs['fs']:04x}  gs={regs['gs']:04x}             efl={regs['eflags']:08x}")
            ip = regs["rip"]
        else:
            self.print(" ".join(f"{n}={regs[n]:08x}" for n in ["eax", "ebx", "ecx", "edx", "esi", "edi"]))
            self.print(" ".join(f"{n}={regs[n]:08x}" for n in ["eip", "esp", "ebp"]) + " " + _eflags_text(regs["eflags"]))
            self.print(" ".join(f"{n}={regs[n] & 0xFFFF:04x} " for n in ["cs", "ss", "ds", "es", "fs", "gs"])
                       + f"            efl={regs['eflags']:08x}")
            ip = regs["eip"]
        self.print(f"{self.dump.symbolize(ip) or ctx.fmt(ip)}:")
        code = self.dump.read_partial(ip, 16)
        self.print(f"{ctx.fmt(ip)}  " + " ".join("??" if b is None else f"{b:02x}" for b in code)
                   + "   (raw bytes; no disassembler)")
