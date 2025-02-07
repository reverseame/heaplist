import enum
import logging
import string
from typing import Generator, List

from volatility3.framework import exceptions, interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import versions

vollog = logging.getLogger(__name__)

# Flags for heap entries (HEAP_ENTRY)
class HEAP_ENTRY_FLAGS(enum.IntFlag):
    HEAP_ENTRY_BUSY             = 0x01
    HEAP_ENTRY_EXTRA_PRESENT    = 0x02
    HEAP_ENTRY_FILL_PATTERN     = 0x04
    HEAP_ENTRY_VIRTUAL_ALLOC    = 0x08
    HEAP_ENTRY_LAST_ENTRY       = 0x10
    HEAP_ENTRY_SETTABLE_FLAG1   = 0x20
    HEAP_ENTRY_SETTABLE_FLAG2   = 0x40
    HEAP_ENTRY_SETTABLE_FLAG3   = 0x80

# Custom HEAP_ENTRY display names
HEAP_ENTRY_FLAGS_DISPLAY_NAMES = {
    HEAP_ENTRY_FLAGS.HEAP_ENTRY_BUSY:           "busy",
    HEAP_ENTRY_FLAGS.HEAP_ENTRY_EXTRA_PRESENT:  "extra",
    HEAP_ENTRY_FLAGS.HEAP_ENTRY_FILL_PATTERN:   "fill",
    HEAP_ENTRY_FLAGS.HEAP_ENTRY_VIRTUAL_ALLOC:  "internal",
    HEAP_ENTRY_FLAGS.HEAP_ENTRY_LAST_ENTRY:     "last",
    HEAP_ENTRY_FLAGS.HEAP_ENTRY_SETTABLE_FLAG1: "user_flag1",
    HEAP_ENTRY_FLAGS.HEAP_ENTRY_SETTABLE_FLAG2: "user_flag2",
    HEAP_ENTRY_FLAGS.HEAP_ENTRY_SETTABLE_FLAG3: "user_flag3",
}

class HeapList(interfaces.plugins.PluginInterface):
    """Lists the NT heap entries of processes from a Windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="dump",
                description="Virtual memory address of the heap entry to dump",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump-all",
                description="Extract all heap entries",
                default=False,
                optional=True,
            ),
        ]

    def read_heap_entry_data(self, heap_entry: int, heap_entry_size: int, granularity: int) -> bytes:
        trans_layer = self.context.layers[heap_entry.vol.layer_name]

        # The actual data is appended next to the _HEAP_ENTRY (granularity = _HEAP_ENTRY.size)
        return trans_layer.read(heap_entry.vol.offset + granularity, heap_entry_size - granularity)

    def flag_to_string(self, flag: int) -> str:
        flag_encoded = HEAP_ENTRY_FLAGS(flag)

        if HEAP_ENTRY_FLAGS.HEAP_ENTRY_BUSY in flag_encoded:
            string = HEAP_ENTRY_FLAGS_DISPLAY_NAMES.get(HEAP_ENTRY_FLAGS.HEAP_ENTRY_BUSY)
        else:
            string = "free"

        for f in list(HEAP_ENTRY_FLAGS)[1:]:
            if f in flag_encoded:
                string += f" {HEAP_ENTRY_FLAGS_DISPLAY_NAMES.get(f, f.name)}"

        return string

    def is_addr_uncommitted(self, addr: int, uncommitted_regions: [(int, int)]) -> int:
        for uncommitted_region in uncommitted_regions:
            if (addr >= uncommitted_region[0]) and (addr <= uncommitted_region[0] + uncommitted_region[1]):
                return uncommitted_region[1]

        return 0

    def _generator(self, procs: Generator[interfaces.objects.ObjectInterface, None, None]):
        kernel = self.context.modules[self.config["kernel"]]

        _HEAP = kernel.get_type("_HEAP")
        _HEAP_ENTRY = kernel.get_type("_HEAP_ENTRY")
        granularity = _HEAP_ENTRY.size

        for proc in procs:
            pid = proc.UniqueProcessId
            proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")

            try:
                peb = proc.get_peb()
                heap_pointers = utility.array_of_pointers(
                                    peb.ProcessHeaps.dereference(),
                                    count=peb.NumberOfHeaps,
                                    subtype=_HEAP,
                                    context=self.context,
                                )
            except exceptions.InvalidAddressException:
                vollog.warning(f"{proc_name} ({pid})\t: Unable to read the _PEB")
                continue

            for heap in heap_pointers:
                if heap.has_member("SegmentList"):
                    # Windows 7 and beyond
                    segments = heap.SegmentList.to_list(f"{kernel.symbol_table_name}{constants.BANG}_HEAP_SEGMENT", "SegmentListEntry")
                else:
                    vollog.warning(f"{proc_name} ({pid})\t: Unsupported _HEAP @ {heap.vol.offset:#x}")
                    continue

                for segment in segments:
                    try:
                        heap_entry_addr = segment.FirstEntry

                        uncommitted_regions = []
                        if segment.NumberOfUnCommittedPages:
                            for uncommitted_region in segment.UCRSegmentList.to_list(f"{kernel.symbol_table_name}{constants.BANG}_HEAP_UCR_DESCRIPTOR", "SegmentEntry"):
                                uncommitted_regions.append((uncommitted_region.Address, uncommitted_region.Size))

                        while heap_entry_addr < segment.LastValidEntry:
                            if uncommitted_regions:
                                no_uncommitted_bytes = self.is_addr_uncommitted(heap_entry_addr, uncommitted_regions)
                                if no_uncommitted_bytes:
                                    heap_entry_addr += no_uncommitted_bytes
                                    continue

                            heap_entry = self.context.object(_HEAP_ENTRY, segment.vol.layer_name, heap_entry_addr)

                            heap_entry_size = heap_entry.Size
                            heap_entry_flags = heap_entry.Flags

                            if heap.EncodeFlagMask == 0x100000:
                                heap_entry_size ^= heap.Encoding.Size
                                heap_entry_flags ^=  heap.Encoding.Flags

                            heap_entry_size *= granularity

                            try:
                                data = self.read_heap_entry_data(heap_entry, heap_entry_size, granularity)

                                file_output = "Disabled"

                                if self.config["dump-all"] or (self.config["dump"] == heap_entry_addr):
                                    file_output = f"{pid}.heap.{heap_entry_addr:x}.dmp"
                                    with open(file_output, "wb") as f:
                                        f.write(data)

                                decoded_data = "".join([c if (c in string.printable) and (c not in string.whitespace) else "." for c in data[:40].decode("ascii", errors="replace").replace("\ufffd", ".")])
                            except exceptions.InvalidAddressException:
                                # We retrieved the _HEAP_ENTRY but not the data, we can still traverse the following _HEAP_ENTRYs
                                vollog.debug(f"{proc_name} ({pid})\t: Unable to read _HEAP_ENTRY data @ {heap_entry_addr:#x}")
                                file_output = "Unavailable"
                                decoded_data = "????"

                            yield (
                                0,
                                (
                                    pid,
                                    proc_name,
                                    format_hints.Hex(heap.BaseAddress),
                                    format_hints.Hex(segment.BaseAddress),
                                    format_hints.Hex(heap_entry_addr),
                                    format_hints.Hex(heap_entry_size),
                                    f"[{heap_entry_flags:02x}]",
                                    self.flag_to_string(heap_entry_flags),
                                    decoded_data,
                                    file_output
                                )
                            )

                            heap_entry_addr += heap_entry_size
                    except exceptions.InvalidAddressException:
                        vollog.warning(f"{proc_name} ({pid})\t: _HEAP_ENTRY missing\t: _HEAP {heap.BaseAddress:#x}\t: Unable to read the _HEAP_SEGMENT {segment.BaseAddress:#x} beyond _HEAP_ENTRY {heap_entry_addr:#x}")

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Name", str),
                ("Heap", format_hints.Hex),
                ("Segment", format_hints.Hex),
                ("Entry", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Flags", str),
                ("State", str),
                ("Data", str),
                ("File Output", str)

            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=filter_func,
                )
            ),
        )
