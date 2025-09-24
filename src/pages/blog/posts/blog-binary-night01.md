---
layout: /src/layouts/MarkdownPostLayout.astro
title: Binary Night 1
author: 5alv1.py
description: "In this article I will show you a basic path traversal vulnerability I've found in a CTF challenge."
pubDate: 2024-11-01
tags: ["blog", "event", "asm"]
image:
  url: "/images/posts/roadmap.webp"
  alt: "Binary Night"
languages: ["c"]
---

We started with an overview of this very picture, we talked mainly about these topics:
- Buffer overflow
- ret2win
- Stack canaries
- ROP
- ASLR
- Heap overflow
- ARM PAC (mini review)
- CFI (Shadow Stack)

### Buffer overflow (stack)
It's a vulnerability that allows you to write over a buffer's end, that could result into data corruption and/or in the program crashing. Here is an example of a simple C program vulnerable to buffer overflow:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
char name[16];

printf("Tell me your name!\n");

gets(name);
printf("Hi, %s", name);

// exit(0);
return 0;
}
```

![Placeholder text](https://5alv1.github.io/assets/images/layout.png)

This is approximately the memory layout we have when we're executing a process.
The stack is that part of the memory where we put all the local variables (it's sometimes referred as static memory), the peculiar thing about it is that it also contains all the return addresses we need so basically when we have

```asm
01: call rax
02: ; code...
```
After we call `rax` the return address will be store in the stack and when we have 
```asm
; ...something
ret
```
in the function we called, we're returning to the address `01`. We're effectively doing:
```asm
01: push 02
    jmp rax
02: ; code...
```
and
```asm
; ...something
pop rip
```
(You can't actually edit `rip` manually, the example is for clarity)

Since the stack has return addresses in it, having control over the stack content means having control over what code will be executed, if you override the current function's return address, you can call an arbitrary function, as long as you know where it is in the memory and it doesn't need any parameters to work (This will be important later).
This technique is called ret2win, and originally, what you had to do was to write machine code in the stack, and write the address of your code's beginning where the return address is located; this is now impossible in most cases, because of NX (Non executable stack), so you are forced to reuse code.

### ROP (Return Oriented Programming)

This is not a vulnerability, but a technique we use to exploit one. It's an extension of ret2win where you jump to little pre-existing code snippets (called gadgets) that end with `ret`, you achieve this by writing multiple return addresses instead of just one; so basically at the end of one snippet `ret` is executed and `rip` will have the next gadget's address in it. We call these return addresses a **ROP chain**.

#### Back in my day, we could put parameters in the stack

ROP is great for a few reasons, (among all, it's Turing complete) but it was certainly easier to exploit back when 32-bit CPUs dominated, that's because the calling convention in x86 for C was to put all the parameters you needed in the stack, well that was convenient, a simple buffer overflow could have resulted in an arbitrary function call with arbitrary parameters; the dream!

It's slightly harder to put parameters in functions on x86-64, we just need a few additional gadgets. Generally, what we want when we need to fill a register `reg` is a gadget that does `pop reg`, if the gadget is at some fixed address, we can just put its address in the chain, followed by the value we need in the register.

### Bibliography
[This paper](http://cecs.wright.edu/~tkprasad/courses/cs781/alephOne.html) contains most informations about the buffer overflow part <br>
[ROP paper](https://hovav.net/ucsd/dist/rop.pdf) <br>
[About ROP being Turing complete and some techniques to use it](https://www.blackhat.com/presentations/bh-usa-08/Shacham/BH_US_08_Shacham_Return_Oriented_Programming.pdf) <br>
[Calling conventions for x86](https://en.wikipedia.org/wiki/X86_calling_conventions)
