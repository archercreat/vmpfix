# vmpfix
*VMPfix* is a dynamic x86/x64 VMProtect 2.13-3.5 import fixer.
The main goal of this project was to build correct and reliable tool to fix imports in x86/x64 applications.

Note: this tool does not dump and rebuild import directory. You can do this from your favorite debugger.

## Before
![](media/before.png) 

## After
![](media/after.png)

## Usage
```bash
vmpfix.exe
-p: required.
Usage: Universal VMProtect Import fixer [options]

Optional arguments:
-h --help       shows help message and exits [default: false]
-v --version    prints version information and exits [default: false]
-p --pid        Target process id [required]
-s --sections   VMProtect sections in target module [default: {".vmp0" ".vmp1" ".be1" ".be0"}]
-i --iat        New IAT section name [default: ".vmp0"]
-m --module     VMProtected module name (default: main executable) [default: ""]
```

Example commands:
```
vmpfix.exe -p 3336 -m beservice_x64.exe -s .be0 -s .be1 -i .be0
vmpfix.exe -p 11250
```

VMProtect unpacking must be complete before running *VMPfix*.

## Details
There are 3 types of IAT accesses that VMProtect patches: `call`, `jmp` and `mov`.
Every stub resolves protected import with only 3 instructions:
```
lea reg, [imm]
mov reg, [reg + imm]
lea reg, [reg + imm]
```
Although stubs are obfuscated, there are only handful of instructions that matters:
```
push
pop
lea
mov
xchg
ret
```

### Call stubs
Every `call` stub ends with `xchg` instruction:

`call [IAT]` -> `call .vmp1; int3`:
```
[!] push        rax
[!] mov         rax,qword ptr [rsp+8]
[!] lea         rax,[rax+1]
[!] mov         qword ptr [rsp+8],rax
[!] lea         rax,[1401269B2h]
[!] mov         rax,qword ptr [rax+0FE1D0h]
[!] lea         rax,[rax+445A4C4Eh]
[!] xchg        rax,qword ptr [rsp]
[!] ret
```

`call [IAT]` -> `push rcx; call .vmp1`:
```
[!] pop         rsi
[!] xchg        rsi,qword ptr [rsp]
[!] push        rsi
[!] lea         rsi,[1401832EDh]
[!] mov         rsi,qword ptr [rsi+0A7558h]
[!] lea         rsi,[rsi+49C80AACh]
[!] xchg        rsi,qword ptr [rsp]
[!] ret
```
### Jmp stubs
Every `jmp` stub ends with `ret 4/8` instruction:

`jmp [IAT]` -> `push rcx; call .vmp1`:
```
[!] pop         rcx
[!] xchg        rcx,qword ptr [rsp]
[!] push        rcx
[!] lea         rcx,[1400EE9C4h]
[!] mov         rcx,qword ptr [rcx+14F6B2h]
[!] lea         rcx,[rcx+36F801BAh]
[!] xchg        rcx,qword ptr [rsp]
[!] ret         8
```
### Mov stubs
Every other stub can be considered as `mov` stub. There are some patterns as well. E.g. there is no `ret 8` or `xchg` at the end.

`mov rsi, [IAT]` -> `push rsi; call .vmp1`:
```
[!] pop         rsi
[!] xchg        rsi,qword ptr [rsp]
[!] pop         rsi
[!] lea         rsi,[rsi+1]
[!] push        rsi
[!] lea         rsi,[14015634Fh]
[!] mov         rsi,qword ptr [rsi+0EF63Ch]
[!] lea         rsi,[rsi+0C2B009Ah]
[!] ret
```

## Build
```
git clone --recurse-submodules https://github.com/archercreat/vmpfix.git
cd vmpfix
cmake -B build
cmake --build build
```

## Tests
Successfully unpacked, dumped and ran:

`steam.exe x86 752ac6ab6ec58c14bcbae0409ac732e4846a37838919806d1cf1b4cd19095f82`

`vncviewer.exe x64 4158a5e55cbd6a5a8f4ed38befe2a8c9fa0c7a7fbc91709a31592dda95110517`

## Credits
https://github.com/build-cpp/cmkr

https://github.com/can1357/linux-pe

https://github.com/DarthTon/Blackbone

## TODO
- kernel support
