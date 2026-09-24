from .. import constants as C
from ..plugin import Plugin


class Ln(Plugin):
    name = "ln"
    help = "nearest module!export for an address"

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("address", nargs="+", help="address expression, e.g. @rip or ntdll+1000")

    def run(self) -> None:
        ctx = self.ctx
        address = ctx.evaluate(" ".join(self.args.address))
        symbol = self.dump.symbolize(address)
        if symbol:
            self.print(f"({ctx.fmt(address)})   {symbol}")
            return
        region = self.dump.region_at(address)
        where = f"region {ctx.fmt(region.base_address)} {C.MEMORY_TYPES.get(region.type, '')}" if region else "no region"
        self.print(f"({ctx.fmt(address)})   not inside any module ({where})")
