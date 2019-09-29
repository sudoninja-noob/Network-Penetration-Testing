> public Enumeration  like CMS 
>default user/password

admin-admin
administrator -administrator

> complie gcc -m32 (use for 32 bit machine )


>web site (http,https)

dirb  , gobuster 

>  check phpinfo()  

function  disallow  or not

>sytem command  run with PHP

echo exec('id')

> freeBSD use facth  cmd for downloading 

but using -o for output



> find cmd using as root


find / -perm -4000 -ls 2>/dev/null
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

ind / -perm -u=s -type f 2>/dev/null


>	Find writable configuration files
 $ find /etc/ -writable -type f 2>/dev/null


Limited shell  bypass

http://securebean.blogspot.com/2014/05/escaping-restricted-shell_3.html

echo os.system('/bin/bash')


Base 64  coding and decoding 

cat pass.txt  | base64      ---> encoding

copy past base 64 code in file and us file in base 64 

cat pass.txt  | base64 -d  ----> decoding

scp file transfer using 
scp -P 222 ./nmap firefart@10.1.1.1:/root/

cross compiler (32bit/64bit )
i686-w64-mingw32-gcc -o exp exploit.c
i686-w32-mingw32-gcc -o exp exploit.c 


>>>>  image behind txt

steghide extract -sf irked.jpg
