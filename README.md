# Heap Extraction Plugin for Volatility 3

This plugin for [Volatility 3](https://github.com/volatilityfoundation/volatility3/) allows forensic analysts to extract heap entries from processes of a Windows memory image (>= Windows 7). The plugin is particularly useful for identifying and extracting information that may be critical to a forensic investigation, such as injected code, sensitive data, and other relevant process behavior.

**NOTE**: This plugin only supports the traditional NT Heap, the modern [Segment Heap](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests#heaptype) implementation introduced in Windows 10 is not currently supported.

## Features

- List all heap entries of a given process in a Windows memory image.
- Dump the decoded heap data to a file for further investigation.

## Installation

1. Install [Volatility 3](https://github.com/volatilityfoundation/volatility3?tab=readme-ov-file#installing). **NOTE**: This plugin requires at least version 2.0.0.
1. Clone this repository.
3. Copy the plugin file `heaplist.py` into the default plugin directory of Volatility 3:

```shell
$ cp heaplist/heaplist.py /path/to/volatility3/volatility3/plugins/windows
```

## Usage

```
usage: volatility windows.heaplist [-h] [--pid [PID [PID ...]]] [--dump DUMP] [--dump-all]

Lists the NT heap entries of processes from a Windows memory image.

optional arguments:
  -h, --help            show this help message and exit
  --pid [PID [PID ...]]
                        Process ID to include (all other processes are excluded)
  --dump DUMP           Virtual memory address of the heap entry to dump
  --dump-all            Extract all heap entries
```

## Example

List and dump heap entries of a specific process with PID 7540:

```
$ vol3.py -f /path/to/windows-memory-image.raw windows.heaplist --pid 7540 --dump-all
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished                        
PID     Name    Heap    Segment Entry   Size    Flags   State   Data    File Output

7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090000   0x740   [01]    busy    ........................................        7540.heap.1edba090000.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090740   0x30    [01]    busy    p........................}......        7540.heap.1edba090740.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090770   0x60    [01]    busy    @.......@...............................        7540.heap.1edba090770.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba0907d0   0x50    [01]    busy    C.:.\.W.i.n.d.o.w.s.\.S.y.s.t.e.m.3.2.\.        7540.heap.1edba0907d0.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090820   0x30    [01]    busy    0...............................        7540.heap.1edba090820.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090850   0x110   [01]    busy    ................@...............\..5*..L        7540.heap.1edba090850.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090960   0x1e0   [01]    busy    ........`...............................        7540.heap.1edba090960.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090b40   0x1e0   [01]    busy    ................0.......H.......`.......        7540.heap.1edba090b40.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090d20   0x50    [01]    busy    0.......0...............H.......H.......        7540.heap.1edba090d20.dmp
7540    OneDrive.exe    0x1edba090000   0x1edba090000   0x1edba090d70   0x20    [01]    busy    ................        7540.heap.1edba090d70.dmp
[...redacted...]
```

## License

Licensed under the [GNU GPLv3 license](./LICENSE).
