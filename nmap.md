
<h1>NMAP</h1>
nmap   -sT -p-  -sV -A -sC   <Target IP > -oN   filename

nmap -sS -T5 -Pn Target ip

nmap  -sT -p-  -sV -A -sC   Target ip

nmap --script=smb-vuln-* -p 139,445 Target ip

nmap -p 1433 --script ms-sql-info 10.11.1.31
 nmap --script smb-vuln-ms17-010 -p445 Target ip

 nmap   -Pn --scripts vuln IP address ----------------------------------------vuln scan

nmap -p 80 --script dns-brute.nse vulnweb.com

nmap --script http-enum Target ip

nmap -sV --script=vulscan/vulscan.nse www.example.com		-------------------------------------------vulscan

nmap -sV --script vulners/vulners.nse <target>					-------------------------------------------vulners

nmap -Pn --script vuln Target ip

locate .nse | grep smb                                     --> search scripts

nmap -sT -sC -sV --script=smb-vuln* -p445 -oN NMAP-SMB -v Target ip      >>>      serach vuln

ls -lh /usr/share/nmap/scripts/*ssh*


<h1> NSE script</h1>
NMAP Switches

https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/

https://securitytrails.com/blog/top-15-nmap-commands-to-scan-remote-hosts 

https://www.stationx.net/nmap-cheat-sheet/








