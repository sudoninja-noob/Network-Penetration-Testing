
<h1>NMAP</h1>
nmap   -sT -p-  -sV -A -sC   <Target IP > -oN   filename

nmap -sS -T5 -Pn 10.11.1.22

nmap  -sT -p-  -sV -A -sC   10.11.1.5

nmap --script=smb-vuln-* -p 139,445 10.11.1.31

nmap -p 1433 --script ms-sql-info 10.11.1.31
 nmap --script smb-vuln-ms17-010 -p445 10.11.1.227

 nmap   -Pn --scripts vuln IP address ----------------------------------------vuln scan

nmap -p 80 --script dns-brute.nse vulnweb.com

nmap --script http-enum 192.168.10.55

nmap -sV --script=vulscan/vulscan.nse www.example.com		-------------------------------------------vulscan

nmap -sV --script vulners/vulners.nse <target>					-------------------------------------------vulners

nmap -Pn --script vuln 10.11.1.5

locate .nse | grep smb                                     --> search scripts

nmap -sT -sC -sV --script=smb-vuln* -p445 -oN NMAP-SMB -v 10.11.1.5      >>>      serach vuln

ls -lh /usr/share/nmap/scripts/*ssh*


<h1> NSE script</h1>
NMAP Switches

https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/

https://securitytrails.com/blog/top-15-nmap-commands-to-scan-remote-hosts 

https://www.stationx.net/nmap-cheat-sheet/

