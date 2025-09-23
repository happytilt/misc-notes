# Intro to Assembly Language

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image.png)

**Cache**

| **Level** | **Description** |
| --- | --- |
| `Level 1 Cache` | Usually in kilobytes, the fastest memory available, located in each CPU core. (Only registers are faster.) |
| `Level 2 Cache` | Usually in megabytes, extremely fast (but slower than L1), shared between all CPU cores. |
| `Level 3 Cache` | Usually in megabytes (larger than L2), faster than RAM but slower than L1/L2. (Not all CPUs use L3.) |
- Accessing data from RAM addresses takes more instructions
    - retrieving an instruction from the registers takes only one clock cycle
    - retrieving it from the L1 cache takes a few cycles
    - retrieving it from RAM takes around 200 cycles
- Cache runs at the same clock speed as the CPU

RAM is split into four main segments (diagram):

| **Segment** | **Description** |
| --- | --- |
| `Stack` | Last-in First-out (LIFO) and is fixed in size. |
| `Heap` | Much larger and more versatile in storing data, as data can be stored and retrieved in any order. Slower than the Stack. |
| `Data` | Has two parts: `Data`, which is used to hold variables, and `.bss`, which is used to hold unassigned variables (i.e., buffer memory for later allocation). |
| `Text` | Main assembly instructions are loaded into this segment to be fetched and executed by the CPU. |

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image%201.png)

**Hertz**

- Frequency of cycles per second
- Measures **clock speed** - how many basic instructions are done in a second
- 3.0 GHz = 3 billion cycles per second (per core)
    - This is clock speed

**Instruction Cycle**

- One instruction takes one cycle to complete
- A cycle has four stages:
    1. Fetch - Retrieve the next instruction address
        1. from the `Instruction Address Register` (IAR); stores where next instruction is in memory
    2. Decode - Decodes the instruction address fetched from binary to see instruction
    3. Execute - Fetch operands needed for the instruction and ALU/CU does the instruction
    4. Store - Store the result value in the destination operand
- Each Instruction Cycle takes multiple clock cycles to finis

ALU - Arithmetic or Logic Unit

- Performs calculations
- Execute phase of a Instruction cycle

CU - Control Unit

- Moves and controls data.

[**Instruction Set Architectures**](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/Instruction%20Set%20Architectures%2026d6c31c8f4a8049949af4124e503406.md)

- A way CPU processes data.
- Common ISAs
    - RISC - processes more simple instructions, which takes more cycles, but each cycle is shorter and takes less power
    - CISC - based on fewer, more complex instructions, which can finish instructions in fewer cycles

It is important to understand that each processor has its own set of instructions and corresponding machine code.

each processor type has its ISA, and each ISA have several syntax formats

`lscpu`

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image%202.png)

## Registers and Memory Addresses

[Registers](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/Registers%2026d6c31c8f4a80a187a2d8e597434f4d.md)

[Memory Addresses](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/Memory%20Addresses%2026d6c31c8f4a808485ddef8722e0a04c.md)

**Data Types**

- Common data types in x86 architecture

| **Component** | Sub-register | **Length** | **Example** |
| --- | --- | --- | --- |
| `byte` | `al` | 8 bits | `0xab` |
| `word` | `ax` | 16 bits - 2 bytes | `0xabcd` |
| `double word (dword)` | `eax` | 32 bits - 4 bytes | `0xabcdef12` |
| `quad word (qword)` | `rax` | 64 bits - 8 bytes | `0xabcdef1234567890` |

Whenever we use a variable with a certain data type or use a data type with an instruction, both operands should be of the same size.

- For example, we can't use a variable defined as byte with rax, as rax has a size of 8 bytes
- use al instead because it is 1 byte which equals a byte data type

# **Assembly File Structure**

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image%203.png)

**Example Code**

```nasm
         global  _start

         section .data
message: db      "Hello HTB Academy!"

         section .text
_start:
         mov     rax, 1
         mov     rdi, 1
         mov     rsi, message
         mov     rdx, 18
         syscall

         mov     rax, 60
         mov     rdi, 0
         syscall
```

**Directives** - Commands used by an assembler to instruct how to assemble, link, or manage a program

- define memory locations
- declare variables
- define data types
- control program flow
- manage the assembly process

## Common Directives

`global _start`

- Directive
- Directs code to start executing at `_start` label

`section .data`

- Data section
- read/write
    - NOT executable
- Contains all variables
    - Variables here are loaded into memory before executing instructions
- Stored at memory segment - data
    
    **Define Variables:**
    
    `db` - Byte variable
    
    `dw` - WORD variable
    `dd` - DWORD variable
    
    - Examples
        
        
        | **Instruction** | **Description** |
        | --- | --- |
        | `db 0x0a` | Defines the byte `0x0a`, which is a new line. |
        | `message db 0x41, 0x42, 0x43, 0x0a` | Defines the label `message => abc\n`. |
        | `message db "Hello World!", 0x0a` | Defines the label `message => Hello World!\n`. |
    
    `equ` - equals; defines a constant
    
    - labels defined with `equ` are constant; can’t be changed
        - Example
            
            ```nasm
            section .data
                message db "Hello World!", 0x0a
                length  equ $-message
            ```
            
            What that looks like in Python:
            
            `length = len(message)`
            
            - `$` → current distance from the beginning of the current section
                - `message` variable is at the beginning of the data section
                - the current location (`$`) = the length of the string
            - `$ - message` subtracts the starting address of `message` from the current address
                - gives the size of the data between `message` and where you are now

`section .text`

- Text section
- read-only
- Contains all code to be executed
- Stored at memory segment - code

**Comments**

- ‘`;`'

# **Assembling**

1. **Assembling**

Assembling the Assembly code into machine code

nasm command:

`nasm -f elf64 helloWorld.s`

`-f elf` - 32-bit assembly code

`-f elf64` - 64-bit assembly code

Before:

assembly file extension - `.s` or `.asm`

- In assembly syntax

After:

assembly object/output file extension - `.o`

- Assembled into machine code
- Can’t be executed

1. **Linking**

References and labels used by nasm need to be resolved into actual addresses

We need to link the `.o` file with OS libraries needed

*This is why a Linux binary is called `ELF`, which stands for an `Executable and Linkable Format`*

ld command:

`ld -o helloWorld helloWorld.o`

`-m elf_i386` - flag needed for 32-bit binary

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image%204.png)

# Disassembling

`objdump` command

- dumps machine code from a file and interprets the assembly instruction of each hex code
- `-d {file}`: disassemble a binary
- `-M intel`: outputs Intel syntax

Output

```nasm
helloWorld:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <_start>:
  401000:	b8 01 00 00 00       	mov    eax,0x1
  401005:	bf 01 00 00 00       	mov    edi,0x1
  40100a:	48 be 00 20 40 00 00 	movabs rsi,0x402000
  401011:	00 00 00
  401014:	ba 12 00 00 00       	mov    edx,0x12
  401019:	0f 05                	syscall
  40101b:	b8 3c 00 00 00       	mov    eax,0x3c
  401020:	bf 00 00 00 00       	mov    edi,0x0
  401025:	0f 05                	syscall
```

- `--no-show-raw-insn` - Removes machine code from output
- `--no-addresses` - Removes memory addresses from output
- `-s` - Dump strings; include .data in output
- `-j .data` - Only output .data section

# **GNU Debugger (GDB)**

One of the great features of `GDB` is its support for third-party plugins

`GEF (GDB Enhanced Features)` is a free and open-source GDB plugin that is built precisely for reverse engineering and binary exploitation

To add GEF to GDB, we can use the following command

```bash
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
```

```bash
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

## >gdb - Gathering Info

`info {subcommand}` - General info about the program

- `help info` - shows the same thing as `info` with no subcommand
- `info functions`
- `info variable`

`disassemble {function name}` or `disas {function name}`

- Outputs the instructions within a specific function

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image%205.png)

- `<+num>` - offset in bytes from start of function

- Some memory addresses are in the form of `0x00000000004xxxxx`
    - rather than their raw address in memory `0xffffffffaa8a25ff`
- Due to `$rip-relative addressing` in Position-Independent Executables (PIE)
    - Memory addresses are used relative to their distance from the instruction pointer `$rip` within the program's own Virtual RAM
    - Rather than using raw memory addresses

PIE = executable that can be loaded at random addresses → stronger ASLR → harder to exploit

PIE binaries can be loaded at any memory address

Modern systems use ASLR which randomizes where code and libraries are placed in memory each time program runs

You want a binary to PIE-compiled to make use of ASLR on systems

## >gdb - Debugging

Debugging steps:

1. `Break` - Set breakpoints at points of interests
2. `Examine` - Running programing and examining state of it at each breakpoint
3. `Step` - Moving through program; examine its behavior at each instruction and user input
4. `Modify` - Modify values at registers and addresses at certain breakpoint; examine impact and changes in execution

**Set a breakpoint**

`break {address or fucntion}` or `b {address or fucntion}`

Example:

`b *_start+10`

`b *0x40100a`

*The * dereferences instruction stored in 0x40100a*

*dereference = obtain from (a pointer) the address of a data item held in another location*

**Run program**

`run` or `r`

**Continue on from BP**

`continue` or `c`

**Modifying BPs**

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image%206.png)

Breakpoints are given a numbers you can use as arguments to the commands below:

`delete`, `disable`, `enable`

**Examine Command**

`x/FMT ADDRESS`

FMT (short for format) Arguments in Order:

| **Argument** | **Description** | **Example** |
| --- | --- | --- |
| `Count` | The number of times we want to repeat the examine | `2`, `3`, `10` |
| `Format` | The format we want the result to be represented in | `x(hex)`, `s(string)`, `i(instruction)` |
| `Size` | The size of memory we want to examine | `b(byte)`, `h(halfword)`, `w(word)`, `g(giant, 8 bytes)` |

`Size` and `Format` defaults to last used

**Viewing Instructions**

`x/4ig $rip`

- View next `4`
- next 4 `instructions`
- read `g` bytes at a time (8 bytes/ 64 bits)

*The `$` in front of rip is GDB syntax to mean "the contents of the register rip."
Without `$`, GDB would interpret rip as a symbol name (like a variable or label).*

**Viewing Strings**

`x/s ADDRESS`

- `s` will show the string at `ADDRESS`

**Viewing Hex**

`x/wx 0x401000`

output: `0x401000 <_start>:	0x000001b8`

- Hex value to the right is little-endian

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image%207.png)

**Examine Registers**

`registers`

- Outputs current values of all registers

**Stepping Through Instructions**

`stepi` or `si`

- Steps through one instruction
- `→` arrow indicates next instruction; it has not been executed yet

`si {num}`

- Step through instructions `num` times

`nexti` or `ni`

- Same as step
- But skips over function calls

<aside>
🔍

press `return`/`enter` key to repeat last entered command

</aside>

**Stepping Through a Line in Source Code**

`step` or `s`

- Steps through one source line (in C, Python, etc.)
- If the line contains a function call, it steps into that function
    - Breaks/stops at beginning function

`next` or `n`

- Same as step
- But skips over functions
    - Where as `step` breaks at start of function calls

**Modifying Values**

`set`

- General command to change variables, registers, or GDB settings
- More flexible and syntax varies

Example:

`set $rdx=0x9`

- sets `rdx` register to 0x9

`patch (qword|dword|word|byte|string) {LOCATION} {VALUES}`

- From GEF
- Mainly used for modifying memory or code bytes

Example:

`patch string 0x402000 "Patched!\\x0a"`

- `\\x0a` is hex for a newline character

# **Linux x86_64 Sys Calls**

[Linux System Call Table for x86 64 · Ryan A. Chapman](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)

- **Syscall number** → `rax`

**Arguments** → registers:

| # | Register |
| --- | --- |
| 1 | `rdi` |
| 2 | `rsi` |
| 3 | `rdx` |
| 4 | `r10` |
| 5 | `r8` |
| 6 | `r9` |
- **Invoke syscall** → `syscall` instruction
- **Example: write("Hello\n") + exit**

```nasm
mov rax, 1      ; write
mov rdi, 1      ; stdout
mov rsi, msg    ; msg ptr
mov rdx, len    ; length
syscall
mov rax, 60     ; exit
xor rdi, rdi    ; code 0
syscall
```

# Data Movement

Data Movement instructions:

| **Instruction** | **Description** | **Example** |
| --- | --- | --- |
| `mov` | Move data or load immediate data | `mov rax, 1` -> `rax = 1` |
| `lea` | Load an address pointing to the value | `lea rax, [rsp+5]` -> `rax = rsp+5` |
| `xchg` | Swap data between two registers or addresses | `xchg rax, rbx` -> `rax = rbx, rbx = rax` |

<aside>
💡

*Note: In assembly, moving data does not affect the source operand. So, we can consider `mov` as a copy function, rather than an actual move.*

</aside>

Size of the loaded data depends on the size of the destination register (`rdi`)

## Address Pointers

- Includes pointers like `rsp`, `rip`, `rbp`
- `mov rax, rsp` will copy an address over to `rax`, not the deferenced value of that address
- `[operand]` in Intel syntax is “load value at address”
    - Dereferences whatever is in those brackets
- `mov rax, [rsp]` will deference that pointer and copy over the value at that address
    - `mov rax, [rsp+10]` will add 10 to the address in `rsp` before dereferencing final address

<aside>
💡

When using `[]`, we may need to set the data size before the square brackets

- `byte`,`qword`, etc.
- In most cases, `nasm` will automatically do that for us
- `mov rax, [rsp]` → `mov rax, QWORD PTR [rsp]`
</aside>

## Loading Effective Address

- Opposite from above; dereferencing pointer and moving that value
    - LEA = Loads an address referencing a value
    - Referencing - taking the address of something; usually creating a pointer for that data
- When data is too big to fit into a register
    - We reference that data’s address

both `mov rax, rsp` and `lea rax, [rsp]` will do the same thing of storing the pointer to `message` at `rax`

- Always use `lea` to load an address with an offset

<aside>
💡

`lea` expects a memory address

- Brackets are required for the source operand if a register
- Won’t be allowed without brackets
</aside>

- Brackets in mov = dereference
- Backets in lea = reference

# **Arithmetic Instructions**

Two types: `Unary` (takes on operand) and `Binary` (takes two operands)

## **Unary Instructions**

| **Instruction** | **Description** | **Example** |
| --- | --- | --- |
| `inc` | Increment by 1 | `inc rax` -> `rax++` |
| `dec` | Decrement by 1 | `dec rax` -> `rax--`  |

## **Binary Instructions**

| **Instruction** | **Description** | **Example** |
| --- | --- | --- |
| `add` | Add both operands | `add rax, rbx` -> `rax = 1 + 1` |
| `sub` | Subtract Source from Destination (*i.e `rax = rax - rbx`*) | `sub rax, rbx` -> `rax = 1 - 1` |
| `imul` | Multiply both operands | `imul rax, rbx` -> `rax = 1 * 1` |

<aside>
💡

Result is always stored in the destination operand for those 3 instructions

the source operand is not affected

</aside>

## **Bitwise Instructions**

| **Instruction** | **Description** | **Example** |
| --- | --- | --- |
| `not` | Bitwise NOT (invert all bits, 0->1 and 1->0) | `not rax` |
| `and` | Bitwise AND (if both bits are 1 -> 1, if bits are different -> 0) | `and rax, rbx` |
| `or` | Bitwise OR (if either bit is 1 -> 1, if both are 0 -> 0) | `or rax, rbx` |
| `xor` | Bitwise XOR (if bits are the same -> 0, if bits are different -> 1) | `xor rax, rbx` |

<aside>
💡

XORing any register with itself will zero out that register

</aside>

# Program Control Instructions

Enables changing the flow of the program and direct it to another line

## Loops

A set of instruction that repeats for `rcx` times

`rcx` - Register commonly used for loops; 

a caller-saved register - it’s value can be changed by the caller

Example:

```nasm
exampleLoop:
    instruction 1
    instruction 2
    instruction 3
    instruction 4
    instruction 5
    loop exampleLoop
```

- When hitting `loop` instruction, `rcx--` or `dec rcx`
- Then jump back to the `exampleLoop` label (start of the loop)

| **Instruction** | **Description** | **Example** |
| --- | --- | --- |
| `mov rcx, x` | Sets loop (`rcx`) counter to `x` | `mov rcx, 3` |
| `loop` | Jumps back to the start of `loop` until counter reaches `0` | `loop exampleLoop` |

Main Fibonacci Sequence Logic

 

```nasm
global  _start

section .text
_start:
    xor rax, rax    ; initialize rax to 0
    xor rbx, rbx    ; initialize rbx to 0
    inc rbx         ; increment rbx to 1
    mov rcx, 10
loopFib:
    add rax, rbx    ; get the next number
    xchg rax, rbx   ; swap values
    loop loopFib
```

- What the registers will look like during the loop after each instruction:
    
    
    | **Instruction** | **`rax`**  | `rbx` |
    | --- | --- | --- |
    | add `rax`, `rbx` | 1 | 1 |
    | xchg `rax`, `rbx` | 1 | 1 |
    | loop loopFib |  |  |
    | add `rax`, `rbx` | 2 | 1 |
    | xchg `rax`, `rbx` | 1 | 2 |
    | loop loopFib |  |  |
    | add `rax`, `rbx` | 3 | 2 |
    | xchg `rax`, `rbx` | 2 | 3 |
    | loop loopFib |  |  |
    | add `rax`, `rbx` | 5 | 3 |
    | xchg `rax`, `rbx` | 3 | 5 |
    | loop loopFib |  |  |
    | add `rax`, `rbx` | 8 | 5 |
    | xchg `rax`, `rbx` | 5 | 8 |
    | loop loopFib |  |  |
    
    Fib Sequence: 0, 1, 1, 2, 3, 5, 8
    
    `rbx` represents that fib number
    

## Branching Instructions

*general instructions that allow us to `jump` to any point in the program if a specific condition is met*

### **Unconditional Branching**

`jmp {operand}`

- Jumps to a label or specified location
- No returning after jumping
    - You’d need use functions for returning
- Not suitable for loops, as it will loop forever

### Conditional Branching

*Based on operands, instructions are only processed when a specific condition is met*

| **Instruction** | **Condition** | **Description** |
| --- | --- | --- |
| `jz` | `D = 0` | Destination `equal to Zero` |
| `jnz` | `D != 0` | Destination `Not equal to Zero` |
| `js` | `D < 0` | Destination `is Negative` |
| `jns` | `D >= 0` | Destination `is Not Negative` (i.e. 0 or positive) |
| `jg` | `D > S` | Destination `Greater than` Source |
| `jge` | `D >= S` | Destination `Greater than or Equal` Source |
| `jl` | `D < S` | Destination `Less than` Source |
| `jle` | `D <= S` | Destination `Less than or Equal` Source |

Other conditional instructions

`CMOVcc` - Conditional MOV

`SETcc` - Conditional SET

`cc` is the condition code; like equal to zero, greater than, etc.

### **RFLAGS Register**

- Defines how to determine when condition are met or where they’re stored
- A register of different flags; either set 1 or 0 because of conditions
- Arithmetic instructions set the necessary 'RFLAG' bits depending on their outcome

| **Bit(s)** | **0** | **1** | **2** | **3** | **4** | **5** | **6** | **7** | **8** | **9** | **10** | **11** | **12-13** | **14** | **15** | **16** | **17** | **18** | **19** | **20** | **21** | **22-63** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Label** (`1`/`0`) | `CF` (`CY`/`NC`) | `1` | `PF` (`PE`/`PO`) | `0` | `AF` (`AC`/`NA`) | `0` | `ZF` (`ZR`/`NZ`) | `SF` (`NC`/`PL`) | `TF` | `IF` (`EL`/`DI`) | `DF` (`DN`/`UP`) | `OF` (`OV`/`NV`) | `IOPL` | `NT` | `0` | `RF` | `VM` | `AC` | `VIF` | `VIP` | `ID` | `0` |
| **Description** | Carry Flag | *Reserved* | Parity Flag | *Reserved* | Auxiliary Carry Flag | *Reserved* | Zero Flag | Sign Flag | Trap Flag | Interrupt Flag | Direction Flag | Overflow Flag | I/O Privilege Level | Nested Task | *Reserved* | Resume Flag | Virtual-x86 Mode | Alignment Check / Access Control | Virtual Interrupt Flag | Virtual Interrupt Pending | Identification Flag | *Reserved* |

The flags we would mostly be interested in are:

- The Carry Flag `CF`: Indicates whether we have a float.
- The Parity Flag `PF`: Indicates whether a number is odd or even.
- The Zero Flag `ZF`: Indicates whether a number is zero.
- The Sign Flag `SF`: Indicates whether a register is negative.

`loop {operand}` is actual two commands

- `dec rcx`
- `jnz {operand}`

If `dec rcx` results in zero, `zf` flag is set, and `jnz` won’t jump

<aside>
🚧

In GEF GDB, flags written in bold UPPERCASE letters are on/set

</aside>

`cmp {destination}, {source}`

- Compares two things
- Subtracts `{destination} - {source}` in that order
- Does not store result in `{destination}`
- Only flags will be set
- `{destination}` has to be a register

### conditional breakpoints in `gdb`

- `b label if $register > num`
- Example: `b *0x401012 if $rbx > 10`
- `*` Refers to a memory location

`jl {destination}, {source}`

- Jump if destination > source

JMP Equal `je`, or JMP Not Equal `jne` is just an alias of `jz` and `jnz`

- since if both operands are equal, the outcome of `cmp rax`
- `rax` would be 0 in all cases

The same applies to `jge` and `jnl`, since `>=` is the same as `!`

# **The Stack**

*Segment of memory allocated for program to store data and retrieve data temporarily*

- Top of the stack is referred to by the Top Stack Pointer `rsp`
- Bottom is referred to by the Base Stack Pointer `rbp`

Moving things onto the stack:

| **Instruction** | **Description** | **Example** |
| --- | --- | --- |
| `push` | Copies the specified register/address to the top of the stack | `push rax` |
| `pop` | Moves the item at the top of the stack to the specified register/address | `pop rax` |

Stack is `Last-in First-out` (`LIFO`)

- popping and pushing will affect the top of the stack only

- Before calling a `function` or `syscall`, we’d push data into the stack to retrieve after the function or syscall is complete
- To preserve our registers, we will need to `push` to the stack all of the registers we are using and then pop them back after completing a function/syscall

<aside>
🧐

Since stack is a **LIFO** design

- when we restore our registers, we have to do them in **reverse order**
- If we **push rax** and then **push rbx**
- we have to **pop rbx** and then **pop rax**.
</aside>

# **Syscalls**

*A globally available function written in C, provided by the Operating System Kernel*

*Takes the required arguments in the registers and executes the function with the provided arguments*

View list of syscall numbers

64-bit CPU: `cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h`

32-bit CPU: `cat /usr/include/x86_64-linux-gnu/asm/unistd_32.h`

<aside>
📢

You can pull up man pages for each syscall to find required arguments

`man write`

fd = File Descriptor (0 for standard input, 1 for standard output, and 2 for standard error)

</aside>

## Calling Convention

1. Preserve registers by pushing them to Stack
2. Set syscall number in `rax`
3. Set syscall arguments in registers
4. Use `syscall` assembly instruction to call

Syscall Arguments

| **Description** | **64-bit Register** | **8-bit Register** |
| --- | --- | --- |
| Syscall Number/Return value | `rax` | `al` |
| Callee Saved | `rbx` | `bl` |
| 1st arg | `rdi` | `dil` |
| 2nd arg | `rsi` | `sil` |
| 3rd arg | `rdx` | `dl` |
| 4th arg | `rcx` | `cl` |
| 5th arg | `r8` | `r8b` |
| 6th arg | `r9` | `r9b` |

Print `write`

- We can use `mov rcx, 'string’` but…
- A 64-bit register only stores 64 bits (8 bytes or 8 ASCII characters)
- We should create a variable and mov that into the register

## Exiting

- We need to exit the program properly
- Using exit syscall

`exit` takes one argument: `status`

- the exit code usually 0 or 1

# Procedure/Subroutines

*A set of instructions to execute at specific points in a program*

- Defined under a procedure label and called whenever needed

```jsx
label:
	instructions
	

label:
	calling label
```

# CALL/RET

`call {procedure}`

- Pushes `rip` to stack then jumps to a specified procedure

`ret`

- Pops into `rip`

# **Functions**

*A form of procedures expected to fully use stack and all registers*

Calling Convention

1. Preserve register in stack (Caller Saved)
2. Pass Function Arguments
3. Fix Stack Alignment
4. Get Function’s Return Value in `rax`

Writing Functions

1. Saving Callee Saved (into `rbx` and `rbp`)
2. Get arguments from registers
3. Align the Stack
4. Return value in `rax`

## **Using External Functions**

`libc` is an external library of C functions like `printf`

Import like so:

```nasm
global  _start
extern  printf
```

Using `printf`

- Create a variable with format specifier

```nasm
global  _start
extern  printf

section .data
    message db "Fibonacci Sequence:", 0x0a
    outFormat db  "%d", 0x0a, 0x00
```

- `%d` is format specifier for integer
- `0x0a` is a new line character
- `0x00` is a null terminator, which is needed in printf

## **Stack Alignment**

*Whenever we want to make a `call` to a function, we must ensure that the `Top Stack Pointer (rsp)` is aligned by the `16-byte` boundary from the `_start` function stack*

- At least 16-bytes (or a multiple of 16-bytes) to the stack before making a call
- Each procedure call adds an 8-byte address to the stack, which is then removed with ret
- Each push adds 8-bytes to the stack as well
- we should have 16-bytes (or a multiple of 16) on top of the stack before making a call
- We can count the number of (un`pop`ed) `push` instructions and (un`ret`urned) `call` instructions, and we will get how many 8-bytes have been pushed to the stack.

If we were in a case where we wanted to bring the boundary up to 16, we can subtract bytes from `rsp`, as follows:

```nasm
    sub rsp, 16
    call function
    add rsp, 16
```

Example

```nasm
global  _start
extern  printf

section .data
    outFormat db  "It's %s", 0x0a, 0x00
    message db "Aligned!", 0x0a

section .text
_start:
    call print          ; print string
    call Exit           ; Exit the program

print:
    sub rsp, 8
    mov rdi, outFormat  ; set 1st argument (Print Format)
    mov rsi, message    ; set 2nd argument (message)
    call printf         ; printf(outFormat, message)
    ret

Exit:
    mov rax, 60
    mov rdi, 0
    syscall
```

- Calling `print` subs 8 bytes from stack
- Calling `printf` inside `print` subs another 8 bytes from stack
- `ret` will only add back 8 bytes to stack
    - We’re still offset by 8 bytes
- `add rsp, 8` will bring the stack pointer back down to where it was before `print` was called

## **Dynamic Linker**

`ld` with `-lc --dynamic-linker` to dynamically link the libc library

example:

`ld fib.o -o fib -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2`

## Scanf

- Scanf takes an input format specifier and a buffer to save the user input into
- Add a variable for the format specifier
    - Ex: `variableNamedb  "%d", 0x00`
- Then reverse space for user input by adding a variable in `.bss` section

### uninitialized buffer space

```nasm
section .bss
    variableName resb 1
```

- `.bss` memory segment
    - `resb` - reserved buffer space (in bytes)
- a memory area for uninitialized global and static variables in a program
- This segment has read-write permissions and can be dynamically changed by the running program

**`cmp` on .bss variable**

- `cmp rax, [var]` → compare **value in memory at var** (dereference).
- `cmp rax, var` → compare **address of var** (pointer).

# Shellcode

- A binary’s executable machine/compiled code
- Binary Exploitation
    - We may pass shellcode to memory and have it executed
- Rely on infecting existing executables (like elf or .exe) or libraries (like .so or .dll)
- Nothing written to disk, great for stealth
- represents a programs executable `.text` section only
    - as shellcodes are meant to be directly executable

Each x86 instruction and each register has its own binary machine code (usually represented in hex for human readability in binary exploitation)

- Common combinations of instructions and registers have their own machine code
    - Example: push rax = 50; push rbx =53

## pwntools

Binary exploitation tool used to assemble and disassemble machine code

Example:

```bash
pwn asm 'push rax'  -c 'amd64'

#output: 50
```

```bash
pwn disasm '50' -c 'amd64'

#output: push rax
```

[pwnlib.asm — Assembler functions — pwntools 4.14.1 documentation](https://docs.pwntools.com/en/stable/asm.html)

[Command Line Tools — pwntools 4.14.1 documentation](https://docs.pwntools.com/en/stable/commandline.html)

### Extracting .text

1. Run python3
2. Import pwn
3. Use the ELF library to load an elf binary

```bash
happytilt@htb[/htb]$ python3

>>> from pwn import *
>>> file = ELF('helloworld')
```

1. After loading the elf binary, we can use pwntool functions on it
    
    [pwnlib.elf.elf — ELF Files — pwntools 4.14.1 documentation](https://docs.pwntools.com/en/stable/elf/elf.html)
    

`section()` - Dumps machine code from elf binary

- Pair with `hex()` to get the shellcode

Example:

```bash
>>> file.section(".text").hex()

#output:'48be0020400000000000bf01000000ba12000000b8010000000f05b83c000000bf000000000f05'
```

`run_shellcode()` - Runs a given shellcode

- Used `unhex()` for shellcode converted to hex
- 

### Quick pwntools Script

Dumping .text as shellcode

```python
#!/usr/bin/env python3
import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")
# "context()" object in pwntools is a global variable that manages the settings
# and configuration for the entire library

file = ELF(sys.argv[1]) # we can pass the elf binary as an arguement in the cli
shellcode = file.section(".text") # loads .text section of binary into "shellcode"
print(shellcode.hex()) # prints out .text in hex format
```

Running shellcode

```python
#!/usr/bin/env python3
import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")

run_shellcode(unhex(sys.argv[1])).interactive()
```

### Quick Bash Script (shellcode with objdump)

```bash
#!/bin/bash

for i in $(objdump -d $1 |grep "^ " |cut -f2); do echo -n $i; done; echo;
```

## **Debugging Shellcode**

1. Attaching the gdb debugger to the shellcode process
- `gdb -p {PID}`
    - Only works if the process does not exit before gdb attaches

1. Loading shellcode as a elf binary with pwntools
- We can then use gdb on that elf binary
    - `ELF.from_bytes(unhex('SHELLCODEHERE')).save('outputfilename')`
    - `save()` - saves to a file
    
    ## Assembling Shellcode into ELF with pwntools Script
    
    ```python
    #!/usr/bin/env python3
    import sys, os, stat
    from pwn import *
    
    context(os="linux", arch="amd64", log_level="error")
    ELF.from_bytes(unhex(sys.argv[1])).save(sys.argv[2])
    os.chmod(sys.argv[2], stat.S_IEXEC)
    ```
    
    - `stat.S_IEXEC()`
        - stat.S_IEXEC - Execute by owner

## Shellcoding Requirements

*not all binaries give working shellcodes that can be loaded directly to the memory and run*

For shellcode to run,

Shellcode must meet these requirements:

1. Does not contain variables
2. Does not refer to direct memory addresses
    1. Relative addresses are okay
    2. We’d have to replace memory addresses with calls to labels or rip-relative addresses (for calls and loops)
    3. We can push the actual memory address to stack and use rsp to reference it
3. Does not contain any NULL bytes `00`
    1. we must use registers that match our data size

A shellcode is expected to be directly executable once loaded into memory, without loading data from other memory segments, like .data or .bss

- Because .text is not writable, only executable; vice versa with .data
- Entire shellcode payload must be under .text section so no variables

Alternatives to avoid using variables

1. Moving immediate strings to registers
    1. Registers are then limited to only storing 8 characters at a time
2. Pushing strings to the stack then using them
    1. Pushing string 16 bytes at a time in reverse order (because stack)
    2. Then using the stack pointer as a string pointer
    3. We’d need to store strings in a register first then pushing
        1. Registers store 8 bytes at a time
        2. While pushing immediate strings have allowed bounds of a dword (4 bytes)

<aside>
📢

Remember to push 0x00 (null terminator) for end of string

Or setting a fixed length with write syscall

</aside>

Avoiding NULL bytes

1. Zero out a register with XOR
    
    `pwn asm 'xor rax, rax' -c 'amd64’` = `4831c0`
    
2. Use register matching exact data size
    
    `pwn asm 'mov al, 1' -c 'amd64’` = `b001`
    

<aside>
📢

If we ever need to `push 0` to the stack (e.g. for String Termination) we can zero-out any register, and then push that register to the stack.

</aside>

Before:

```nasm
global _start

section .text
_start:
    xor rbx, rbx
    mov bx, 'y!'
    push rbx
    mov rbx, 'B Academ'
    push rbx
    mov rbx, 'Hello HT'
    push rbx
    mov rsi, rsp
    xor rax, rax
    mov al, 1
    xor rdi, rdi
    mov dil, 1
    xor rdx, rdx
    mov dl, 18
    syscall

    xor rax, rax
    add al, 60
    xor dil, dil
    syscall
```

After:

```nasm
global _start

section .data
    message db "Hello HTB Academy!"

section .text
_start:
    mov rsi, message
    mov rdi, 1
    mov rdx, 18
    mov rax, 1
    syscall

    mov rax, 60
    mov rdi, 0
    syscall
```

Checking for NULL Bytes in hex shellcode

`print("%d bytes - Found NULL byte" % len(shellcode)) if [i for i in shellcode if i == 0] else print("%d bytes - No NULL bytes" % len(shellcode))`

# Crafting a `/bin/sh` shellcode

- Using the `execve` syscall; syscall number `59`
- int execve(const char *pathname, char *const argv[], char *const envp[]);
    - `execve("/bin//sh", ["/bin//sh"], NULL)`

Assembly syscall arguements

1. `rax` -> `59` (`execve` syscall number)
2. `rdi` -> `['/bin//sh']` (pointer to program to execute)
3. `rsi` -> `['/bin//sh']` (list of pointers for arguments)
4. `rdx` -> `NULL` (no environment variables)

<aside>
🧠

Extra slashes are ignored in Linux

Added an extra `/` in '`/bin//sh`' so that the total character count is 8

Fill ups a 64-bit register so we don't have to XOR it out

</aside>

```nasm
global _start

section .text
_start:
    mov rax, 59
    xor rdx, rdx
    push rdx
    mov rdi, '/bin//sh'
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    push rdx
    push rdi
    mov rsi, rsp
    mov rdx, 0
    syscall
```

## Shellcraft

- a pwntools library that generates shellcode for various syscalls
- `pwn shellcraft -l 'amd64.linux’`
    - Lists all Linux syscalls the tool accepts

```bash
pwn shellcraft amd64.linux.sh

#output: 6a6848b82f62696e2f2f2f73504889e768726901018134240101010131f6566a085e4801e6564889e631d26a3b580f05

#running the shellcode
pwn shellcraft amd64.linux.sh -r
```

within CLI python

```bash
>>> from pwn import *
>>> context(os="linux", arch="amd64", log_level="error")
>>> dir(shellcraft)
```

- this lists all available syscalls

```bash
>>> syscall = shellcraft.execve(path='/bin/sh',argv=['/bin/sh'])
>>> asm(syscall).hex()
```

- loads the shellcraft into a variable
- prints the variable using asm() in hex

[pwnlib.shellcraft.amd64 — Shellcode for AMD64 — pwntools 4.14.1 documentation](https://docs.pwntools.com/en/stable/shellcraft/amd64.html)

## MsfVenom

*a Metasploit standalone payload generator*

lists payloads for x86_64 Linux

`msfvenom -l payloads | grep 'linux/x64'`

payload for exec on Linux is: `linux/x64/exec`

Generating the shellcode in hex format

- `msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex’`

## **Shellcode Encoding**

- To bypass anti-virus or certain security protections
- Common encoders may be easy to detect

msfvenom generate and encoding

`msfvenom -l encoders` - lists available encoders

- `-e` flag to specify an encoder when generating shellcode

Example:

`msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor’`

- `-i {count}` flag can encode our generated shellcode `{count}` times

Encoded shellcode is always longer than non-encoded shellcode

- Encoding includes a built-in decoder for decoding at runtime

msfvenom encoding only

- We’d bass that shellcode to msfvenom with `-p -` flag
- Shellcode should be in bytes and written to a file

```bash
python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('SHELLCODE'))" > shell.bin
msfvenom -p - -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor' < shell.bin
```

Online existing shellcodes

[Shellcodes database for study cases](http://shell-storm.org/shellcode/)

[OffSec’s Exploit Database Archive](https://www.exploit-db.com/shellcodes)

Shell code for the lab:

![image.png](Intro%20to%20Assembly%20Language%2026c6c31c8f4a804ba4d7ca643c4dd9b1/image%208.png)

Task1:

4831c05048bbe671167e66af44215348bba723467c7ab51b4c5348bbbf264d344bb677435348bb9a10633620e771125348bbd244214d14d244214831c980c1044889e748311f4883c708e2f74831c0b0014831ff40b7014831f64889e64831d2b21e0f054831c04883c03c4831ff0f05

Task2:

```nasm
global _start

section .text

_start:
    xor sil,sil
    push si
    mov rdi, '/flg.txt'
    push rdi

    mov al, 2
    mov rdi, rsp
    syscall

    lea rsi, [rdi]
    mov rdi, rax
    xor al, al
    mov dl, 24
    syscall
    mov al, 1
    mov dil, 1
    mov dl, 24
    syscall
```