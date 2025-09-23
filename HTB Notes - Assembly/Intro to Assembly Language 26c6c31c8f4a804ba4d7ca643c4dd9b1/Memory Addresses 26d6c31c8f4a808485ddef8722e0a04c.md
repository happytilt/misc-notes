# Memory Addresses

x86 64-bit processors have 64-bit wide addresses

- `0x0` to `0xffffffffffffffff`

Fetch phase of an instruction cycle → CPU fetches from memory

- Different modes of address fetching (Fastest to Slowest):

| **Addressing Mode** | **Description** | **Example** |
| --- | --- | --- |
| `Immediate` (Fastest) | The value is given within the instruction | `add 2` |
| `Register` | The register name that holds the value is given in the instruction | `add rax` |
| `Direct` | The direct full address is given in the instruction | `call 0xffffffffaa8a25ff` |
| `Indirect` | A reference pointer is given in the instruction | `call 0x44d000` or `call [rax]` |
| `Stack` (Slowest) | Address is on top of the stack | `add rsp` |

RAM is segmented into Stack, Heap, and other regions

- each regional having different read, write, execute permissions

## **Address Endianness**

the order of its bytes in which they are stored or retrieved from memory

- Same endianess must be used for retrieving and storing

**Little-Endian**

- Little-end bytes of address is filled/retrieved from `right-to-left`

**Big-Endian**

- Big-end bytes of address is filled/retrieved from `left-to-right`

Intel/AMD x86 in most modern operating systems uses Little-Endian

- so the shellcode is always represented right-to-left