<h2>information gathering - IP range </h2>
~~
IP range discover 
netdiscover -r 192.168.1.1/24
nbtscan  					--------------------------------------------------  additional information
~~

<h2>Scanning</h2>
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
