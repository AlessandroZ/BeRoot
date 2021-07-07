#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import subprocess

from .files.files import File
from .useful.useful import run_cmd


class SuidBins:

    def __init__(self, gtfobins):
        self.gtfobins = gtfobins
        self.list = self._get_suid_bin()
        self.is_string_present = self._is_bin_present('strings')
        self.is_objdump_present = self._is_bin_present('objdump')

    def _get_suid_bin(self):
        """
        List all suid binaries
        Using find is much faster than using python to loop through all files looking for suid binaries
        """
        # For GUID => find / -perm -g=s -type f 2>/dev/null
        print('Getting suid bins.')
        cmd = 'find / -perm -u=s -type f 2>/dev/null'
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        suid = []

        for file in out.strip().decode().split('\n'):
            fm = File(file)
            suid.append(fm)

        return suid

    def _is_bin_present(self, binary):
        out, err = run_cmd('which %s' % binary)
        if out:
            return True

    def _is_built_in_bin(self, path):
        """
        Check if a binary is called without specifying a absolute path
        we are looking for such calls: system('whoami') instead of system('/bin/whoami')
        """
        for b in ['/bin', '/usr/bin/', '/sbin', '/usr/sbin']:
            if os.path.exists(os.path.join(b, path)):
                return True

    def _check_for_system_call(self, binary):
        """
        Check if system from libc function is called
        """
        # To much false positive using strings on system
        # cmd = 'strings %s | grep "^system$"' % binary
        cmd = 'objdump -T %s | grep " system"' % binary
        out, _ = run_cmd(cmd)
        results = []
        if out:
            # system call detected
            cmd = 'strings %s' % binary
            out, _ = run_cmd(cmd)
            for line in out.split(b'\n'):

                if not isinstance(line, str):
                    line = line.decode(sys.getfilesystemencoding())

                for string in line.split():
                    if not string.startswith('/') and self._is_built_in_bin(string):
                        results.append('%s -> %s'% (line, string))
        return results

    def _check_for_exec_call(self, binary, user):
        """
        Check if exec functions are used and try to check if writable files are present
        exec functions run an executable with absolute path so it's different from system function
        """
        cmd = 'strings %s | grep -E "execve|execl|execlp|execle|execv|execvp|execvpe"' % binary
        out, _ = run_cmd(cmd)
        results = []
        # Remove false positive
        blacklist_path = ('/dev/', '/var/', '/tmp/')

        if out:
            cmd = 'strings %s' % binary
            out, _ = run_cmd(cmd)
            for line in out.decode().split('\n'):
                if line.startswith('/') and os.path.exists(line):
                    if not line.startswith((blacklist_path)):
                        f = File(line)
                        if f.is_writable(user):
                            results.append('%s [writable]' % line)
        return results

    def check_suid_bins(self, user):
        suids = []
        for suid in self.list:
            perm = ''
            if suid.is_writable(user):
                perm = '[writable]'

            values = {'suid': '%s %s' % (suid.path, perm)}
            shell_escape = self.gtfobins.find_binary(suid.basename)
            if shell_escape:
                escapes = shell_escape.split('\n')
                values['[+] gtfobins found'] = escapes

            if self.is_string_present and self.is_objdump_present:
                found = self._check_for_system_call(suid.path)
                if found:
                    values['[+] system calls found'] = found

            if self.is_string_present:
                found = self._check_for_exec_call(suid.path, user)
                if found:
                    values['[+] exec calls found'] = found

            suids.append(values)

        return suids
