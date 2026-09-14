# HollowExecutable

An educational implementation of **process hollowing** (also called *PE injection* or *RunPE*) written in C++ for Windows x64.

> **Note:** This code is intended for security research, malware analysis education, and understanding detection engineering.

---

## Table of Contents

1. [What is Process Hollowing?](#what-is-process-hollowing)
2. [PE File Structure](#pe-file-structure)
3. [How This Implementation Works](#how-this-implementation-works)
4. [Detection by AV/EDR Products](#detection-by-averdr-products)
5. [Project Structure](#project-structure)
6. [Building](#building)

---

## What is Process Hollowing?

Process hollowing is a code injection technique:

1. Loads a target executable's image into memory
2. Unmaps (hollows out) the original memory of a legitimate process — or in the case of this implementation, the current process itself
3. Maps a different executable payload into that same address space
4. Redirects execution to the payload's entry point

The result is that a payload runs inside the address space of a host process, potentially inheriting its identity, handle table, and trust level. The technique was first documented publicly around 2011 and remains a staple of malware analysis syllabi.

This implementation performs **same-process hollowing** — the payload replaces the loader itself in memory rather than injecting into a separate target process.

---

## PE File Structure

Understanding process hollowing requires comprehension of the **Portable Executable (PE)** format, the binary format used by Windows executables (`.exe`) and libraries (`.dll`).

### DOS Header (`IMAGE_DOS_HEADER`)

Every PE file begins with the legacy MS-DOS header. Its two relevant fields are:

| Field | Purpose |
|---|---|
| `e_magic` | Magic number — must be `0x5A4D` (`MZ`) to identify a valid PE |
| `e_lfanew` | Byte offset from the start of the file to the NT Headers |

The loader validates `e_magic` and uses `e_lfanew` to jump past the stub to the real headers.

### NT Headers (`IMAGE_NT_HEADERS64`)

Located at `base + e_lfanew`. Contains three sub-structures:

```
IMAGE_NT_HEADERS64
├── Signature          (4 bytes — must be "PE\0\0" / 0x00004550)
├── FileHeader         (IMAGE_FILE_HEADER)
│   ├── Machine
│   ├── NumberOfSections
│   └── ...
└── OptionalHeader     (IMAGE_OPTIONAL_HEADER64)
    ├── ImageBase      — preferred load address in virtual memory
    ├── SizeOfImage    — total size of the mapped image in memory
    ├── AddressOfEntryPoint — RVA of the first instruction to execute
    ├── SizeOfHeaders
    └── DataDirectory[16]  — array of pointers to important tables
```

### Section Headers (`IMAGE_SECTION_HEADER`)

Immediately following the NT Headers is an array of `NumberOfSections` section headers. Each describes one region of the file:

| Field | Meaning |
|---|---|
| `VirtualAddress` | RVA where this section is mapped in memory |
| `PointerToRawData` | File offset of the raw section bytes |
| `SizeOfRawData` | How many bytes to copy from the file |
| `Characteristics` | Flags: readable, writable, executable, etc. |

Common sections: `.text` (code), `.rdata` (read-only data, imports), `.data` (globals), `.reloc` (relocation table).

### Data Directories

`OptionalHeader.DataDirectory` is an array of 16 `IMAGE_DATA_DIRECTORY` structures, each holding a `VirtualAddress` (RVA) and `Size`. The two most relevant to hollowing are:

- **`IMAGE_DIRECTORY_ENTRY_IMPORT` (index 1)** — points to the Import Directory, which describes which DLLs and functions the image depends on.
- **`IMAGE_DIRECTORY_ENTRY_BASERELOC` (index 5)** — points to the Base Relocation Table, used when the image cannot load at its preferred `ImageBase`.

### Import Address Table (IAT)

The import directory contains an array of `IMAGE_IMPORT_DESCRIPTOR` structures, one per imported DLL. Each descriptor points to two parallel arrays of `IMAGE_THUNK_DATA64`:

- **OriginalFirstThunk (INT)** — the Import Name Table; read-only list of what to import (by name or ordinal)
- **FirstThunk (IAT)** — initially a copy of the INT; at load time, the loader overwrites each slot with the actual function address from the loaded DLL

Patching the IAT is what `FixImportAddressTable()` does in this code.

### Base Relocation Table

When a PE is compiled, absolute addresses are baked in assuming `ImageBase` as the load address. If the image is mapped elsewhere, every absolute address must be adjusted by the delta `(NewBase - OldBase)`. The `.reloc` section encodes exactly which addresses need patching.

The table is a sequence of `IMAGE_BASE_RELOCATION` blocks:

```
IMAGE_BASE_RELOCATION
├── VirtualAddress   — base RVA for this block (covers a 4KB page)
├── SizeOfBlock      — total size including entries
└── Entries[]        — array of 16-bit words
    ├── Bits[15:12]  — Type (10 = IMAGE_REL_BASED_DIR64, a 64-bit field)
    └── Bits[11:0]   — Offset within the page
```

Type `IMAGE_REL_BASED_ABSOLUTE` (0) is a no-op padding entry. Type 10 (`RELOC_64BIT_FIELD`) means "add the delta to the 8-byte value at this location."

---

## How This Implementation Works

### 1. `GetNTHeaders()`

Validates the DOS signature (`MZ`) and NT signature (`PE\0\0`), then returns a pointer to `IMAGE_NT_HEADERS64`. A sanity check on `e_lfanew` (`> PEMAXOFFSET = 4096`) guards against malformed input.

### 2. `GetRelocationData()`

A helper that indexes into `DataDirectory[]` and returns the `IMAGE_DATA_DIRECTORY` for a given directory entry index (import table, relocation table, etc.). Returns `NULL` if the directory is absent.

### 3. `LaunchExecutable()`

This is the core hollowing routine:

**a) Unmap the current image**

```cpp
NtUnmapViewOfSection((HANDLE)-1, (LPVOID)NTHeaders->OptionalHeader.ImageBase);
```

`NtUnmapViewOfSection` is called with the pseudo-handle `-1` (current process) to remove the existing image mapping at `ImageBase`. This is the "hollowing" step.

**b) Allocate memory for the payload**

```cpp
VirtualAlloc(Addr, NTHeaders->OptionalHeader.SizeOfImage,
             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

The loader tries to allocate at the payload's preferred `ImageBase`. If that address is unavailable (and the payload has a relocation table), it falls back to any available address.

**c) Copy headers and sections**

The PE headers are copied first (`SizeOfHeaders` bytes), then each section is mapped from its raw file offset (`PointerToRawData`) to its virtual address (`VirtualAddress`), mirroring what the Windows loader does.

**d) Fix the Import Address Table**

`FixImportAddressTable()` walks the import directory. For each imported DLL it calls `LoadLibraryA()`, then resolves each function either by name (`GetProcAddress(hLib, ImportByName->Name)`) or by ordinal (`GetProcAddress(hLib, ordinal)`), writing the resolved address into the IAT slot.

**e) Apply relocations (if necessary)**

If the image was mapped at a different address than `ImageBase`, `ApplyRelocation()` walks the `.reloc` table and adds the delta `(NewBase - OldBase)` to every patched address field.

**f) Transfer execution**

```cpp
Entry = (ULONG_PTR)DLLBaseAddress + NTHeaders->OptionalHeader.AddressOfEntryPoint;
((int(*)())Entry)();
```

A function pointer is constructed from the entry point RVA and called directly.

---

## Detection by AV/EDR Products

Process hollowing leaves a number of detectable artifacts that modern security products look for.

### Memory Anomalies

| Indicator | Detection Method |
|---|---|
| `PAGE_EXECUTE_READWRITE` on a private allocation | Memory scanning |
| Image mapped as private memory (not a file-backed section) | Comparing the VAD (Virtual Address Descriptor) tree entry type → validate the existence of an executable file |
| PE headers present at a private allocation | Scanning mapped memory for `MZ`/`PE` signatures in non-image regions |
| `SizeOfImage` mismatch between the disk file and the in-memory image | Comparing the disk PE headers to the memory headers at the same base address |

### API Call Sequences

EDR may hook or monitor the following call chains in user space (via IAT/inline hooks) and via kernel callbacks:

- `NtUnmapViewOfSection` on the current or a remote process → incredibly rare in legitimate software
- `VirtualAlloc` with `MEM_COMMIT | MEM_RESERVE` and `PAGE_EXECUTE_READWRITE` in the same call
- `WriteProcessMemory` followed by `CreateRemoteThread` or `SetThreadContext` / `ResumeThread` (utilized in a different method)
- `LoadLibraryA` + `GetProcAddress` called in rapid succession from a non-image memory region

ETW (Event Tracing for Windows) and kernel callbacks (`PsSetLoadImageNotifyRoutine`, `PsSetCreateProcessNotifyRoutine`) give EDRs a kernel-level view of these events that is harder to tamper with from user mode.

### Image Integrity Checks

- **PEB `ImageBaseAddress` vs. actual mapping:** The Process Environment Block records the original image base. Hollowing replaces what's there without necessarily updating the PEB, creating a mismatch that memory forensics tools can detect.
- **Module list inconsistency:** The PEB's loader data lists loaded modules; a hollowed process has executable code at an address that doesn't correspond to any entry in that list.
- **Section name/characteristic mismatch:** The in-memory section layout of the injected payload will differ from the on-disk image the loader supposedly loaded.

### Behavioural / Heuristic Detection

- Entropy analysis of mapped memory regions (compressed or encrypted payloads have high entropy)
- Call stack anomalies → execution returns from an entry point that lives in an anonymous private region

---

## Project Structure

```
HollowExecutable/
├── HollowExecutable/
│   ├── main.cpp          # Core hollowing logic (GetNTHeaders, ApplyRelocation,
│   │                     # FixImportAddressTable, LaunchExecutable)
│   └── Executable.hpp    # Payload byte array (TestProject_exe[])
├── HollowExecutable.slnx # Visual Studio solution file
├── .gitignore
└── .gitattributes
```


---

## Building

**Requirements:**

- Visual Studio 2022 (or later) with the **Desktop development with C++** workload
- Windows 10/11 SDK
- x64 target architecture

**Steps:**

1. Open `HollowExecutable.slnx` in Visual Studio.
2. Provide your own `Executable.hpp` with a valid 64-bit PE payload as a byte array named `TestProject_exe`.
3. Set the build configuration to **Release / x64**.
4. Build the solution (`Ctrl+Shift+B`).

---

## Further Reading

- Microsoft PE format specification: [docs.microsoft.com/en-us/windows/win32/debug/pe-format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- *"The Art of Memory Forensics"* by Ligh, Case, Levy, Walters (Wiley, 2014)
- MITRE ATTACK technique T1055.012 — Process Hollowing: [attack.mitre.org/techniques/T1055/012](https://attack.mitre.org/techniques/T1055/012/)
