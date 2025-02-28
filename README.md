# Heap Extraction Plugin for Volatility 3

This plugin for [Volatility 3](https://github.com/volatilityfoundation/volatility3/) allows forensic analysts to extract heap entries from processes of a Windows memory image. The plugin is particularly useful for identifying and extracting information that may be critical to a forensic investigation, such as injected code, sensitive data, and other relevant process behavior.

**NOTE**: This plugin only supports the traditional NT Heap, the modern [Segment Heap](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests#heaptype) implementation introduced in Windows 10 is not currently supported.

## Features

- List all heap entries of a given process in a Windows memory image, including entries from the Low-Fragmentation Heap (LFH).
- Dump the decoded heap data to a file for further investigation.

## Tested Windows Versions

- Windows 11 Home 24H2 x64 (Build number 10.0.26100.1742) &check;
- Windows 10 Education 22H2 x64 (Build number 10.0.19045.2965) &check;
- Windows 8.1 Core x64 (Build number 6.3.9600) &check;
- Windows 7 Professional SP1 x64 (Build number 6.1.7601) &check;
- Windows 7 Professional SP1 x86 (Build number 6.1.7601) &check;
- Windows Vista Business SP2 x64 (Build number 6.0.6002) &check;
- Windows XP Professional SP3 x86 (Build number 5.1.2600) &cross;

## Installation

1. Install [Volatility 3](https://github.com/volatilityfoundation/volatility3?tab=readme-ov-file#installing). **NOTE**: This plugin requires at least version 2.0.0.
1. Clone this repository.
3. Copy the plugin file `heaplist.py` into the default plugin directory of Volatility 3:

```shell
$ cp heaplist/heaplist.py /path/to/volatility3/volatility3/plugins/windows
```

## Usage

```
usage: volatility windows.heaplist.HeapList [-h] [--pid [PID [PID ...]]] [--dump DUMP] [--dump-all]

Lists the NT heap entries of processes from a Windows memory image, supporting both back end and front end (LFH) layers.

optional arguments:
  -h, --help            show this help message and exit
  --pid [PID [PID ...]]
                        Process ID to include (all other processes are excluded)
  --dump DUMP           Virtual memory address of the heap entry to dump
  --dump-all            Extract all heap entries
```

## Example

List and dump heap entries of a specific process with PID 11956:

```
$ vol3.py -f /path/to/windows-memory-image.raw windows.heaplist --pid 11956 --dump-all
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished                          
PID     Name    Heap    Segment Entry   Size    Flags   State   Layer   Data    File Output

11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b30740   0x20    [01]    busy    backend PUBLIC=C:\Users\        11956.heap.22225b30740.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b30760   0x20    [01]    busy    backend SESSIONNAME=Cons        11956.heap.22225b30760.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b30780   0x20    [01]    busy    backend SystemDrive=C:..        11956.heap.22225b30780.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b307a0   0x20    [01]    busy    backend SystemRoot=C:\Wi        11956.heap.22225b307a0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b307c0   0x40    [01]    busy    backend USERDOMAIN_ROAMINGPROFILE=DESKTOP-H23BTC        11956.heap.22225b307c0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b30800   0x20    [01]    busy    backend USERNAME=User...        11956.heap.22225b30800.dmp
[...redacted...]
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3c3a0   0x1010  [01]    busy    backend ................@.......................        11956.heap.22225b3c3a0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3d3b0   0x1010  [01]    busy    backend WEBVIEW2_DEFAULT_BACKGROUND_COLOR=ffffff        11956.heap.22225b3d3b0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3e3c0   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3e3c0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3e6d0   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3e6d0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3e9e0   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3e9e0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3ecf0   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3ecf0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3f000   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3f000.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3f310   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3f310.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3f620   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3f620.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3f930   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3f930.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3fc40   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3fc40.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b3ff50   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b3ff50.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b40260   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b40260.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b40570   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b40570.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b40880   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b40880.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b40b90   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b40b90.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b40ea0   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b40ea0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b411b0   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b411b0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b414c0   0x310   [01]    busy    backend AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b414c0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b417d0   0x2010  [09]    busy internal   backend ...%"......%"...........,...............        11956.heap.22225b417d0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b41820   0x310   [80]    free    lfh     ........................................        11956.heap.22225b41820.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b41b30   0x310   [90]    busy    lfh     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b41b30.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b41e40   0x310   [90]    busy    lfh     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b41e40.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b42150   0x310   [90]    busy    lfh     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b42150.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b42460   0x310   [80]    free    lfh     ........................................        11956.heap.22225b42460.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b42770   0x310   [90]    busy    lfh     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b42770.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b42a80   0x310   [90]    busy    lfh     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b42a80.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b42d90   0x310   [90]    busy    lfh     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA        11956.heap.22225b42d90.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b430a0   0x310   [80]    free    lfh     ........................................        11956.heap.22225b430a0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b433b0   0x310   [80]    free    lfh     ........................................        11956.heap.22225b433b0.dmp
11956   cmd.exe    0x22225b30000   0x22225b30000   0x22225b437e0   0x4010  [01]    busy    backend ????    Unavailable
[...redacted...]
```

## License

Licensed under the [GNU GPLv3 license](./LICENSE).
