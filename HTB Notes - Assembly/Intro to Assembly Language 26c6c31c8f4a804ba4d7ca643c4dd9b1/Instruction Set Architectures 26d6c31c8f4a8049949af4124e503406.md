# Instruction Set Architectures

- Defines core design of a CPU
- Also defines syntax for assembly language

### **Components of an ISA**

| **Component** | **Description** | **Example** |
| --- | --- | --- |
| `Instructions` | The instruction to be processed in the `opcode operand_list` format. There are usually 1,2, or 3 comma-separated operands. | `add rax, 1`, `mov rsp, rax`, `push rax` |
| `Registers` | Used to store operands, addresses, or instructions temporarily. | `rax`, `rsp`, `rip` |
| `Memory Addresses` | The address in which data or instructions are stored. May point to memory or registers. | `0xffffffffaa8a25ff`, `0x44d0`, `$rax` |
| `Data Types` | The type of stored data. | `byte`, `word`, `double word` |

## **2 Common ISAs**

`Complex Instruction Set Computer` (`CISC`)

- Used in `Intel` and `AMD` processors in most computers and servers.
- Combines minor instructions into a complex one; shorter assembly code
- Support ~1500 instructions

`Reduced Instruction Set Computer` (`RISC`)

- Used in `ARM` and `Apple` processors, in most smartphones, and some modern laptops.
- Splits instructions into minor ones; long assembly machine clock code
- Support ~200 instructions
- Ensures all instructions take only one cycle
    - More power efficient (uses less than CISC)
    - Great for phones and laptops

![image.png](Instruction%20Set%20Architectures%2026d6c31c8f4a8049949af4124e503406/image.png)

- **CISC vs. RISC**
    
    
    | **Area** | **CISC** | **RISC** |
    | --- | --- | --- |
    | `Complexity` | Favors complex instructions | Favors simple instructions |
    | `Length of instructions` | Longer instructions - Variable length 'multiples of 8-bits' | Shorter instructions - Fixed length '32-bit/64-bit' |
    | `Total instructions per program` | Fewer total instructions - Shorter code | More total instructions - Longer code |
    | `Optimization` | Relies on hardware optimization (in CPU) | Relies on software optimization (in Assembly) |
    | `Instruction Execution Time` | Variable - Multiple clock cycles | Fixed - One clock cycle |
    | `Instructions supported by CPU` | Many instructions (~1500) | Fewer instructions (~200) |
    | `Power Consumption` | High | Very low |
    | `Examples` | Intel, AMD | ARM, Apple |