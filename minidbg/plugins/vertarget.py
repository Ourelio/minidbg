from .. import constants as C
from ..context import fmt_time, windows_name
from ..minidump import time_t_to_datetime
from ..plugin import Plugin


class VerTarget(Plugin):
    name = "vertarget"
    help = "Windows version, dump time, process start time and integrity level"

    def run(self) -> None:
        si, misc = self.dump.system_info, self.dump.misc_info
        if si is not None:
            arch = C.PROCESSOR_ARCHITECTURE.get(si.processor_architecture, f"arch {si.processor_architecture}")
            mp = "MP" if si.number_of_processors > 1 else "UP"
            self.print(f"{windows_name(si.major_version, si.minor_version, si.build_number)} Version "
                       f"{si.major_version}.{si.minor_version}.{si.build_number} {mp} "
                       f"({si.number_of_processors} procs) {arch}")
            self.print(f"Product: {C.PRODUCT_TYPES.get(si.product_type, si.product_type)}"
                       + (f", {si.csd_version}" if si.csd_version else ""))
        if misc is not None and misc.build_string:
            self.print(f"Edition build lab: {misc.build_string}")
        dump_time = time_t_to_datetime(self.dump.header.time_date_stamp)
        self.print(f"Debug session time: {fmt_time(dump_time)}")
        if misc is not None and misc.process_create_time:
            created = time_t_to_datetime(misc.process_create_time)
            self.print(f"Process created:    {fmt_time(created)}")
            if created and dump_time:
                self.print(f"Process uptime:     {dump_time - created}")
            self.print(f"Process user time:  {misc.process_user_time} s, kernel time: {misc.process_kernel_time} s")
        if misc is not None and misc.integrity_level is not None:
            level = C.INTEGRITY_LEVELS.get(misc.integrity_level, f"{misc.integrity_level:#x}")
            self.print(f"Integrity level:    {level} ({misc.integrity_level:#x})")
        if misc is not None and misc.protected_process is not None:
            self.print(f"Protected process:  {misc.protected_process:#x}")
