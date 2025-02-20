import enum
import logging
import string
import struct
from typing import Generator, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers, constants, contexts, symbols, objects
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import versions, pdbutil

from volatility3.plugins.windows import pslist, vadinfo, info

vollog = logging.getLogger(__name__)

""" Flags for HEAP_ENTRY when backend allocated """
class HEAP_ENTRY_FLAGS(enum.IntFlag):
    BUSY             = 0x01
    EXTRA_PRESENT    = 0x02
    FILL_PATTERN     = 0x04
    VIRTUAL_ALLOC    = 0x08
    LAST_ENTRY       = 0x10
    SETTABLE_FLAG1   = 0x20
    SETTABLE_FLAG2   = 0x40
    SETTABLE_FLAG3   = 0x80

HEAP_ENTRY_FLAGS_DISPLAY_NAMES = {
    HEAP_ENTRY_FLAGS.BUSY:           "busy",
    HEAP_ENTRY_FLAGS.EXTRA_PRESENT:  "extra",
    HEAP_ENTRY_FLAGS.FILL_PATTERN:   "fill",
    HEAP_ENTRY_FLAGS.VIRTUAL_ALLOC:  "internal",
    HEAP_ENTRY_FLAGS.LAST_ENTRY:     "last",
    HEAP_ENTRY_FLAGS.SETTABLE_FLAG1: "user_flag1",
    HEAP_ENTRY_FLAGS.SETTABLE_FLAG2: "user_flag2",
    HEAP_ENTRY_FLAGS.SETTABLE_FLAG3: "user_flag3",
}

""" Flags related to the Low-Fragmentation Heap (LFH) """
LFH_HEAP_ACTIVE     = 0x02
LFH_HEAP_ENTRY_FREE = 0x80
""" The number of LFH buckets on each version of Windows ranges from 1--128 """
NO_LFH_BUCKETS = 129

class HeapList(interfaces.plugins.PluginInterface):
    """Lists the NT heap entries of processes from a Windows memory image, supporting both back end and front end (LFH) layers."""

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
            requirements.VersionRequirement(
                name="pdbutil", component=pdbutil.PDBUtility, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="vadinfo", plugin=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="info", plugin=info.Info, version=(1, 0, 0)
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

    def _flag_to_string(self, flag: int) -> str:
        flag_encoded = HEAP_ENTRY_FLAGS(flag)

        if HEAP_ENTRY_FLAGS.BUSY in flag_encoded:
            string = HEAP_ENTRY_FLAGS_DISPLAY_NAMES.get(HEAP_ENTRY_FLAGS.BUSY)
        else:
            string = "free"

        for f in list(HEAP_ENTRY_FLAGS)[1:]:
            if f in flag_encoded:
                string += f" {HEAP_ENTRY_FLAGS_DISPLAY_NAMES.get(f, f.name)}"

        return string

    def _is_addr_uncommitted(self, addr: int, uncommitted_regions: [(int, int)]) -> int:
        """ Accessing a reserved memory throws a page fault exception, avoid accessing memory that is not committed """
        for uncommitted_region in uncommitted_regions:
            if (addr >= uncommitted_region[0]) and (addr <= uncommitted_region[0] + uncommitted_region[1]):
                return uncommitted_region[1]

        return 0

    def _get_lfh_key(self, ntdll: contexts.Module, layer_name: str) -> int:
        kernel = self.context.modules[self.config["kernel"]]

        lfh_key_address = ntdll.offset + ntdll.get_symbol("RtlpLFHKey").address

        is_kernel_64 = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)

        if is_kernel_64:
            lfh_key_content = self.context.layers[layer_name].read(lfh_key_address, 8)
            return struct.unpack("<Q", lfh_key_content)[0]
        else:
            lfh_key_content = self.context.layers[layer_name].read(lfh_key_address, 4)
            return struct.unpack("<I", lfh_key_content)[0]

    def _find_ntdll_by_vad(self, proc: interfaces.context.ContextInterface) -> Tuple[int, int]:
        """ Returns (Offset, Size) of the VAD corresponding to the ntdll.dll of a given process """
        kernel = self.context.modules[self.config["kernel"]]

        for vad in proc.get_vad_root().traverse():
            filename = vad.get_file_name()

            if isinstance(filename, str) and filename.lower().endswith("\\ntdll.dll"):
                vad_protection = vad.get_protection(
                    vadinfo.VadInfo.protect_values(
                        self.context,
                        kernel.layer_name,
                        kernel.symbol_table_name,
                    ),
                    vadinfo.winnt_protections,
                )

                """ Basic check of the usual DLL protection when loaded normally """
                if vad_protection == "PAGE_EXECUTE_WRITECOPY":
                    return (vad.get_start(), vad.get_size())
                else:
                    vollog.warning(f"Suspicious ntdll.dll at {vad.get_start():#x} (VAD protection {vad_protection})")

        return (None, None)

    def _load_ntdll_symbols(self) -> contexts.Module:
        kernel = self.context.modules[self.config["kernel"]]

        for proc in pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=pslist.PsList.create_pid_filter(None),
                ):
            """
            Let's assume that the same legitimate ntdll.dll is running in each process. For our purposes,
            just finding one should be enough
            """
            (ntdll_base, ntdll_size) = self._find_ntdll_by_vad(proc)

            if (ntdll_base is not None) and (ntdll_size is not None):
                proc_layer_name = proc.add_process_layer()

                try:
                    vollog.debug(f"Trying to obtaining symbols for ntdll.dll from {utility.array_to_string(proc.ImageFileName)} ({proc.UniqueProcessId})...")

                    ntdll_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(
                                    self.context,
                                    interfaces.configuration.path_join(self.config_path, "ntdll"),
                                    proc_layer_name,
                                    "ntdll.pdb",
                                    ntdll_base,
                                    ntdll_size,
                                )

                    return self.context.module(
                        ntdll_symbols, layer_name=proc_layer_name, offset=ntdll_base
                    )
                except exceptions.VolatilityException:
                    continue

        return None

    def _generate_output(self, proc_name: str, pid: objects.Pointer, layer_name: str, heap_entry: objects.StructType, heap_entry_size: int, granularity: int) -> Tuple[str, str]:
        try:
            """ Read the actual user data appended to the end of the _HEAP_ENTRY """
            data = self.context.layers[layer_name].read(heap_entry.vol.offset + granularity, heap_entry_size - granularity)

            file_output = "Disabled"

            if self.config["dump-all"] or (self.config["dump"] == heap_entry.vol.offset):
                file_output = f"{pid}.heap.{heap_entry.vol.offset:x}.dmp"
                with open(file_output, "wb") as f:
                    f.write(data)

            decoded_data = "".join([c if (c in string.printable) and (c not in string.whitespace) else "." for c in data[:40].decode("ascii", errors="replace").replace("\ufffd", ".")])
        except exceptions.InvalidAddressException:
            """ We retrieved the _HEAP_ENTRY but not the data, we can still traverse the following _HEAP_ENTRYs """
            vollog.debug(f"{proc_name} ({pid})\t: Unable to read _HEAP_ENTRY data @ {heap_entry.vol.offset:#x}")
            file_output = "Unavailable"
            decoded_data = "????"

        return (decoded_data, file_output)

    def _generator(self, procs: Generator[interfaces.objects.ObjectInterface, None, None]):
        kernel = self.context.modules[self.config["kernel"]]
        kuser = info.Info.get_kuser_structure(self.context, kernel.layer_name, kernel.symbol_table_name)

        """ Minimum supported is Windows 8.1 (NT 6.3) """
        if int(kuser.NtMajorVersion) < 6 or (int(kuser.NtMajorVersion) == 6 and int(kuser.NtMinorVersion) < 3):
            vollog.error(f"Windows {kuser.NtMajorVersion:d}.{kuser.NtMinorVersion:d}\t: Windows image not supported, minimum supported is Windows 8.1 (NT 6.3)")
            return None

        """ Heap back end structures """
        _HEAP = kernel.get_type("_HEAP")
        _HEAP_ENTRY = kernel.get_type("_HEAP_ENTRY")
        granularity = _HEAP_ENTRY.size

        """
        Front end layer structures, Windows only supports LFH.
        We need to load ntdll.pdb symbols to access the LFH structures
        """
        ntdll = self._load_ntdll_symbols()

        if ntdll is None:
            vollog.warning(f"Failed to load symbols for ntdll.dll, LFH layer parsing is disabled")
        else:
            _LFH_HEAP = ntdll.get_type("_LFH_HEAP")
            _HEAP_LOCAL_SEGMENT_INFO = ntdll.get_type("_HEAP_LOCAL_SEGMENT_INFO")
            _HEAP_USERDATA_HEADER = ntdll.get_type("_HEAP_USERDATA_HEADER")

        for proc in procs:
            pid = proc.UniqueProcessId
            proc_name = utility.array_to_string(proc.ImageFileName)

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

            """ The key will be used later to decode the _HEAP_USERDATA_HEADER information """
            if ntdll is not None:
                LFH_KEY = self._get_lfh_key(ntdll, peb.vol.layer_name)

            for heap in heap_pointers:
                try:
                    vollog.debug(f'_HEAP\t\t\t: {heap.BaseAddress:#x}')
                    lfh_entries = {}

                    """ We loaded the ntdll.dll symbols to work with the LFH """
                    if ntdll is not None:
                        """ LFH front end layer is active for this _HEAP """
                        if heap.FrontEndHeapType == LFH_HEAP_ACTIVE:
                            lfh_heap = self.context.object(_LFH_HEAP, peb.vol.layer_name, heap.FrontEndHeap)
                            vollog.debug(f'_LFH_HEAP\t\t: {lfh_heap.vol.offset:#x}')
                            segment_info_pointers = utility.array_of_pointers(lfh_heap.SegmentInfoArrays, count=NO_LFH_BUCKETS, subtype=_HEAP_LOCAL_SEGMENT_INFO, context=self.context)

                            for segment_info in segment_info_pointers:
                                """
                                Avoid segments with no LFH triggered, LFH is triggered when more than 16 allocations occur
                                for given size requested by the user
                                """
                                if segment_info != 0:
                                    block_size = 0
                                    try:
                                        vollog.debug(f'_HEAP_LOCAL_SEGMENT_INFO\t: {segment_info:#x}')
                                        active_subsegment = segment_info.ActiveSubsegment
                                        vollog.debug(f'_HEAP_SUBSEGMENT\t\t: {active_subsegment:#x}')
                                        user_blocks = active_subsegment.UserBlocks
                                        vollog.debug(f'_HEAP_USERDATA_HEADER\t: {user_blocks:#x}')

                                        """ Decode the fields of _HEAP_USERDATA_HEADER.EncodedOffsets """
                                        encoded_offsets_decoded = user_blocks.EncodedOffsets.StrideAndOffset ^ user_blocks ^ lfh_heap.vol.offset ^ LFH_KEY
                                        """ Get the relative address of the first _HEAP_ENTRY """
                                        first_allocation_offset = encoded_offsets_decoded & 0xFFFF
                                        """ In an LFH segment, all _HEAP_ENTRYs have the same size """
                                        block_stride = ((encoded_offsets_decoded ^ user_blocks.EncodedOffsets.BlockStride) >> 16) & 0xFFFF
                                        """ Another way to get get the _HEAP_ENTRY.Size """
                                        block_size = active_subsegment.BlockSize * granularity
                                        """ Make sure we decode the data correctly """
                                        assert block_size == block_stride
                                        heap_entry_addr = user_blocks + first_allocation_offset

                                        """ Just save the _HEAP_ENTRYs to display them later instead of the backend heap entry """
                                        heap_entries = []

                                        for _ in range(active_subsegment.BlockCount):
                                            try:
                                                heap_entry = self.context.object(_HEAP_ENTRY, peb.vol.layer_name, heap_entry_addr)
                                                heap_entries.append(heap_entry)
                                            except exceptions.InvalidAddressException:
                                                """ We know the _HEAP_ENTRY size anyway, continue traversing """
                                                vollog.debug(f"{proc_name} ({pid})\t: Unable to read LFH _HEAP_ENTRY data @ {heap_entry_addr:#x}")
                                                """ We are inserting an int instead of a StructType """
                                                heap_entries.append(heap_entry_addr)

                                            heap_entry_addr += block_size
                                    except exceptions.InvalidAddressException:
                                        vollog.warning(f"{proc_name} ({pid})\t: Unable to parse the _HEAP_USERDATA_HEADER @ {user_blocks:#x} of the LFH heap @ {lfh_heap.vol.offset:#x}")
                                        continue

                                    lfh_entries[int(user_blocks)] = {"block_size": block_size, "heap_entries": heap_entries}

                    """ Traverse the heap reserved by the backend layer """
                    segments = heap.SegmentList.to_list(f"{kernel.symbol_table_name}{constants.BANG}_HEAP_SEGMENT", "SegmentListEntry")

                    for segment in segments:
                        try:
                            heap_entry_addr = int(segment.FirstEntry)

                            """ Get the uncommitted regions to avoid any reads """
                            uncommitted_regions = []
                            if segment.NumberOfUnCommittedPages:
                                for uncommitted_region in segment.UCRSegmentList.to_list(f"{kernel.symbol_table_name}{constants.BANG}_HEAP_UCR_DESCRIPTOR", "SegmentEntry"):
                                    uncommitted_regions.append((uncommitted_region.Address, uncommitted_region.Size))

                            while heap_entry_addr < segment.LastValidEntry:
                                if uncommitted_regions:
                                    no_uncommitted_bytes = self._is_addr_uncommitted(heap_entry_addr, uncommitted_regions)
                                    """ Skip the entire uncommitted region """
                                    if no_uncommitted_bytes:
                                        heap_entry_addr += no_uncommitted_bytes
                                        continue

                                heap_entry = self.context.object(_HEAP_ENTRY, peb.vol.layer_name, heap_entry_addr)

                                heap_entry_size = heap_entry.Size
                                heap_entry_flags = heap_entry.Flags

                                """ The _HEAP_ENTRYs have encoded size and flags, decoded with the values from the _HEAP """
                                if heap.EncodeFlagMask == 0x100000:
                                    heap_entry_size ^= heap.Encoding.Size
                                    heap_entry_flags ^=  heap.Encoding.Flags

                                heap_entry_size *= granularity
                                heap_layer = "backend"

                                (decoded_data, file_output) = self._generate_output(proc_name, pid, peb.vol.layer_name, heap_entry, heap_entry_size, granularity)

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
                                        self._flag_to_string(heap_entry_flags),
                                        heap_layer,
                                        decoded_data,
                                        file_output
                                    )
                                )

                                """
                                If the _HEAP_ENTRY is allocated internally by the LFH heap, we only need to check the _HEAP_ENTRYs
                                that were allocated using VirtualAlloc
                                """
                                if lfh_entries and HEAP_ENTRY_FLAGS.VIRTUAL_ALLOC in HEAP_ENTRY_FLAGS(heap_entry_flags):
                                    """
                                    FIXME This form of traversing the LFH structures is a workaround,
                                    redo the workflow to traverse the LFH structures accordingly when parsing the backend
                                    """
                                    user_blocks_address = heap_entry_addr + granularity

                                    """ This _HEAP_ENTRY is actually managed by the LFH heap, let's show the entries already collected """
                                    if user_blocks_address in lfh_entries:
                                        heap_layer = "lfh"

                                        lfh_heap_entry_size = lfh_entries[user_blocks_address]["block_size"]

                                        for lfh_heap_entry in lfh_entries[user_blocks_address]["heap_entries"]:
                                            """ We could not retrieve the _HEAP_ENTRY from memory, we only know the address """
                                            if isinstance(lfh_heap_entry, int):
                                                yield (
                                                    0,
                                                    (
                                                        pid,
                                                        proc_name,
                                                        format_hints.Hex(heap.BaseAddress),
                                                        format_hints.Hex(segment.BaseAddress),
                                                        format_hints.Hex(lfh_heap_entry),
                                                        format_hints.Hex(0),
                                                        "????",
                                                        "????",
                                                        heap_layer,
                                                        "????",
                                                        "Unavailable",
                                                    )
                                                )
                                            else:
                                                """ We can obtain the _HEAP_ENTRY status directly from _HEAP_ENTRY.UnusedBytes """
                                                lfh_heap_entry_flags = lfh_heap_entry.UnusedBytes

                                                if lfh_heap_entry_flags == LFH_HEAP_ENTRY_FREE:
                                                    lfh_heap_entry_flags_str = 'free'
                                                else:
                                                    lfh_heap_entry_flags_str = 'busy'

                                                (decoded_data, file_output) = self._generate_output(proc_name, pid, peb.vol.layer_name, lfh_heap_entry, lfh_heap_entry_size, granularity)

                                                yield (
                                                    0,
                                                    (
                                                        pid,
                                                        proc_name,
                                                        format_hints.Hex(heap.BaseAddress),
                                                        format_hints.Hex(segment.BaseAddress),
                                                        format_hints.Hex(lfh_heap_entry.vol.offset),
                                                        format_hints.Hex(lfh_heap_entry_size),
                                                        f"[{lfh_heap_entry_flags:02x}]",
                                                        lfh_heap_entry_flags_str,
                                                        heap_layer,
                                                        decoded_data,
                                                        file_output
                                                    )
                                                )

                                """ Finally, move the pointer to the next _HEAP_ENTRY """
                                heap_entry_addr += heap_entry_size
                        except exceptions.InvalidAddressException:
                            vollog.warning(f"{proc_name} ({pid})\t: _HEAP_ENTRY missing\t: _HEAP {heap.BaseAddress:#x}\t: Unable to read the _HEAP_SEGMENT {segment.BaseAddress:#x} beyond _HEAP_ENTRY {heap_entry_addr:#x}")
                except exceptions.InvalidAddressException:
                    vollog.warning(f"{proc_name} ({pid})\t: Unable to access the _HEAP")

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
                ("Layer", str),
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
