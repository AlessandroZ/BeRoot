#!/usr/bin/env python
# -*- coding: utf-8 -*-
import subprocess

from .files.files import File


class SuidBins:

    def __init__(self, gtfobins):
        self.gtfobins = gtfobins
        self.list = self.get_suid_bin()

    def get_suid_bin(self):
        """
        List all suid binaries
        Using find is much faster than using python to loop through all files looking for suid binaries
        """
        # For GUID => find / -perm -g=s -type f 2>/dev/null
        print('Checking for suid bins. Could take some time...')
        cmd = 'find / -perm -u=s -type f 2>/dev/null'
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        suid = []

        for file in out.strip().decode().split('\n'):
            fm = File(file)
            suid.append(fm)

        return suid

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
                values['gtfobins found'] = escapes

            suids.append(values)

        return suids
