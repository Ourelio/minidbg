from ..plugin import Plugin


class Process(Plugin):
    name = "process"
    aliases = ("|",)
    help = "process id and path of the main executable"

    def run(self) -> None:
        pid = self.dump.process_id
        main = self.dump.main_module()
        self.print(f"id: {pid if pid is not None else 0:x}  ({pid if pid is not None else 0})")
        self.print(f"name: {main.path if main else '?'}")
