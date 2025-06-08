# Coopers Drone (rev, hard)

**Context**

In Fall 2024, I participated in MinutemanCTF 2024, a beginner CTF hosted by UMass Amherst, and this submission won a prize for being in the top 5 medium/hard challenge writeups.

## Initial Analysis

We are given an ELF binary "drone" with the description, "Cooper captured a drone, but can you crack the secret key to get root access? Recommended tools - GDB, Ghidra".

Running checksec shows that it has minimal protections:

```bash
$ checksec drone
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
```

Running it shows that it reads one integer from stdin:

```bash
$ ./drone
Enter the secret key: a
Invalid input character encountered
$ ./drone
Enter the secret key: 1
Wrong key, try again!
$ ./drone
Enter the secret key: 1.0
Invalid input character encountered
$ ./drone
Enter the secret key: 1 2
Invalid input character encountered
```

Looking inside Ghidra, we see that we are left without symbols and other useful information:

```c
void processEntry entry(void)
   {
   int in_ECX;
   undefined4 in_register_0000000c;

   FUN_004010b6();
   FUN_004010a1();
   FUN_00401066();
   if (CONCAT44(in_register_0000000c,in_ECX) != -1) {
      FUN_00401000(0x3c6ef35f);
      FUN_00401021();
      if (in_ECX == -0x21524111) {
         FUN_0040104c();
         FUN_004010b6();
      }
      else {
         FUN_004010b6();
      }
   }
   syscall();
   halt_baddata();
}
```

In the "Functions" window we can see that there are 7 functions, but all of them are unnamed except for entry(). In the data section there are a few symbols: "Enter the secret key: ", "Invalid input character encountered\n", "Wrong key, try again!\n", and an array with what seems to be random characters. Notably, there is no explicit flag in memory but we can assume that the flag is generated using that character array. We also see a comparison `if (in_ECX == -0x21524111)` which might be useful. Outside of this, I'm not really good at reading these kind of barebones binaries so let's explore inside GDB:

### Manipulating User Input

Stepping through GDB, we see that the first function FUN_004010b6() prints "Enter the secret key: ", the second function FUN_004010a1() reads in user input, and the third function FUN_00401066() converts the input from ascii to int.

Later, there is an equality check between the ecx register and 0xdeadbeef, which if failed leads to "Wrong key, try again!\n" being printed out and the program exiting. Therefore, we have to find an input that would eventually lead to ecx equalling 0xdeadbeef.

After parsing our input, ecx doesn't change until FUN_0x401021() is called so let's look inside that:

Ghidra:

```c
undefined8 FUN_00401021(void)
{
   DAT_0040209d = (ulong)(uint)((int)DAT_0040209d \* (int)DAT_004020a5 + (int)\_DAT_004020ad);
   return 0;
}
```

GDB:

```c
   0x401021    xor   rax, rax
   0x401024    mov   rcx, qword ptr [0x40209d]
   0x40102c    mov   r13, qword ptr [0x4020a5]
   0x401034    imul  rcx, r13
   0x401038    add   rcx, qword ptr [0x4020ad]
   0x401040    and   ecx, 0xffffffff
   0x401043    mov   qword ptr [0x40209d], rcx
   0x40104b    ret
   ↓
   0x401131    cmp   ecx, 0xdeadbeef
```

Here rcx is multiplied by the value at 0x4020a5 and then added with the value at 0x4020ad. From GDB and Ghidra, we can see that at 0x4020a5 is 0x19660d, at 0x4020ad is 0x3c6ef35f, and that these values are hardcoded (and never change). Finally, ecx is ANDed with 0xffffffff, essentially only keeping the lower 4 bytes. Immediately after returning is the comparison, so with this we have enough information to formulate a math equation.

$$
0xDEADBEEF = ((x \cdot 0x19660D) + 0x3C6EF35F) \wedge 0xFFFFFFFF \\
\text{} \\
x \cdot 0x19660D = (0xDEADBEEF - 0x3C6EF35F) \wedge 0xFFFFFFFF \\
x \cdot 0x19660D = 0xA0BDFE10 \wedge 0xFFFFFFFF \\
x \cdot 0x19660D = 0xA0BDFE10 \\
\text{} \\
x = \dfrac{0xA0BDFE10}{0x19660D} \\
$$

Unfortunately, this results in a non-integer (1620.16...) which we won't be able to input into the program. However, we can take advantage of the AND with 0xffffffff since it allows us to input numbers larger than 0xdeadbeef because it extracts the lower 4 bytes. If we find an input that after being multiplied and added as above equals a number like 0x123deadbeef, then we can input it in decimal form to end up with 0xdeadbeef. (This also means that there is more than one solution!)

## Calculating the Input

### Representing 0xffffffff as a modulus

We can rewrite the equation as a congruence relation modulo 0xffffffff + 1, or 0x100000000, since this is essentially truncating the number to its lower 4 bytes:

$$ x \equiv \dfrac{0xA0BDFE10}{0x19660D} \mod{0x100000000} $$

This only works because the bitmask 0xffffffff contains only f's i.e. is of the form $2^n - 1$, where n is the number of bits. To understand this, first remember that 0xf = 0b1111 and so these types of bitmasks contain only 1's, which when ANDing with another number would extract the lower n bits without modifying them. In other words, only when the bitmask is of this form, the AND operation simply truncates the number to fit within a certain range.

Modular arithmetic works in a similar way where a number can be "truncated" to fit within a certain range starting from 0 by returning the remainder when dividing it by the modulus. In this case, our range is from 0 to 0xffffffff = $2^{4(8)} - 1$ = $2^{32} - 1$ inclusive, so we would need to add 1 to ensure that the system also includes $2^{32} - 1$ itself. This gives us a modulus of $2^{32}$ or 0x100000000, effectively truncating the number to its lower 32 bits.

If the bitmask weren't of the form $2^n - 1$, then it wouldn't be possible to represent the AND operation using modulus because it wouldn't act as a simple, contiguous range anymore like the modulus, so the organizers blessed us here 🙏.

### Using the modular inverse

Now, we are guaranteed to have an integer solution since division in a modular system is not the same as traditional division. Instead of the number becoming some non-integer, division by some number $b$ is defined as multiplying by its modular inverse, $b^{-1}$ mod m where $m$ is the modulus.

The modular multiplicative inverse of a number $b$ mod $m$ is a number $a$ (= $b^{-1}$) such that

$$ ab \equiv 1 \mod m $$

This means that when $b$ is multiplied by $a$, their product "wraps around" to 1 modulo $m$ (the remainder after dividing $ab$ by $m$ is 1), and this new product is still congruent to the original quotient modulo $m$. This is useful because it means that the division would be canceled out to 1 where in our case, $b$ would be 0x19660d. Instead of dividing by 0x19660d, if we multiply by its inverse, then we would get a larger integer that when ANDed with 0xffffffff would equal 0xdeadbeef after truncating to 4 bytes.

Here's a short proof:

$$
\text{let } a = 0xDEADBEEF \\
b = 0x19660D \\
c = 0x3C6EF35F \\
m = 0xFFFFFFFF + 1 = 0x100000000 \\

\text{} \\
\text{let } x \equiv (a - c) \cdot b^{-1} \mod{m} \\
\text{Now input $x$ into the program:}
$$

$$
\begin{aligned}
y &= (x \cdot 0x19660D + 0x3C6EF35F) \wedge 0xFFFFFFFF \\
&= (x \cdot b + c) \wedge (m - 1) \\
&\equiv (((a - c) \cdot b^{-1}) \cdot b + c) \mod{m} \\
&\equiv ((a - c) \cdot ( b^{-1} \cdot b) + c) \mod{m} \\
&\equiv ((a - c) \cdot 1 + c) \mod{m} \hspace{3em} \text{by def. of mod. inv.} \\
&\equiv a \mod{m} \\
&\equiv 0xDEADBEEF \wedge 0xFFFFFFFF \\
&= 0xDEADBEEF \\
\end{aligned}
$$

Now, as long as the input is an 8 byte integer (0 to $2^{64}-1$) and the resulting number's lower 4 bytes are 0xdeadbeef, ecx will always be set to 0xdeadbeef.

## Implementation

Now implementing this as a python program:

```py
from pwn import *

if args.GDB:
   p = gdb.debug(
   "./drone",
   """
   alias -a dsm = disassemble
   b *0x40112c
   b *0x401131
   continue
   """,
   )
else:
   p = process("./drone")
sleep(0.5)

numerator = (0xDEADBEEF - 0x3C6EF35F) & 0xFFFFFFFF # 0xa23ecb90
modulus = 0xFFFFFFFF + 1   # 0x100000000
inverse = pow(0x19660D, -1, modulus)   # 0xfee058c5
x = (numerator * inverse) % modulus    # 0x6e4c25d0 or 1850484176

print(p.clean())
# send as decimal byte str
p.sendline(str(x).encode())
print(p.read().decode()) # flag
```

Running this inside GDB, we can see that our input in RCX was changed into 0xaf167deadbeef just before being ANDed with 0xffffffff:

```c
pwndbg>
0x0000000000401040 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────[ REGISTERS / show-flags off / show-compact-regs off ]───────
 RAX 0x0
 RBX 0x0
*RCX 0xaf167deadbeef
 RDX 0x20
 RDI 0x0
 RSI 0x40207c ◂-- '1850484176\n'
 R8 0x0
 R9 0x0
 R10 0x0
 R11 0x246
 R12 0x16
 R13 0x19660d
 R14 0x0
 R15 0x0
 RBP 0x6e4c25d0
 RSP 0x7ffd4f31b988 --▸ 0x401131 ◂-- cmp ecx, 0xdeadbeef
*RIP 0x401040 ◂-- and ecx, 0xffffffff
───────────────[ DISASM / x86-64 / set emulate on ]───────────────
   0x401021    xor   rax, rax
   0x401024    mov   rcx, qword ptr [0x40209d]
   0x40102c    mov   r13, qword ptr [0x4020a5]
   0x401034    imul  rcx, r13
   0x401038    add   rcx, qword ptr [0x4020ad]
►  0x401040    and   ecx, 0xffffffff
   0x401043    mov   qword ptr [0x40209d], rcx
   0x40104b    ret
      ↓
   0x401131    cmp   ecx, 0xdeadbeef
   0x401137    jne   0x40115d                   <0x40115d>

   0x401139    movabs rbp, 0x402053
```

Looks like we didn't have to reverse the flag generation and that was it! We get the flag `MINUTEMAN{what's_a_calling_convention?}`

## Final Thoughts

This was my first time ever participating in a CTF and it was really fun to reverse this challenge, although I'd never thought that I'd actually use the modulus concepts I learned in my discrete math class...

Thanks to the organizers for hosting MinutemanCTF 2024!
