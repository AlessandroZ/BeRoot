#!/usr/bin/env python
# -*- coding: utf-8 -*-
import getpass
import os
import sys

from .files.files import File
from .useful.useful import tab_of_dict_to_string, tab_to_string, run_cmd


def get_capabilities():
    """
    List capabilities found on binaries stored on /sbin/
    """
    bins = []
    getcap = '/sbin/getcap'
    if os.path.exists(getcap):
        for path in ['/usr/bin/', '/usr/sbin/']:
            cmd = '{getcap} -r -v {path} | grep "="'.format(getcap=getcap, path=path)
            output, err = run_cmd(cmd)
            if output:
                for line in output.decode().split('\n'):
                    if line.strip():
                        binary, capabilities = line.strip().split('=')
                        bins.append('%s: %s' % (binary, capabilities))

    if bins: 
        return tab_to_string(bins)

    return False


def get_ptrace_scope():
    try:
        with open('/proc/sys/kernel/yama/ptrace_scope', 'rb') as f:
            ptrace_scope = int(f.read().strip())

        if ptrace_scope == 0:
            return 'PTRACE_ATTACH possible ! (yama/ptrace_scope == 0)'

    except IOError:
        pass


def check_nfs_root_squashing():
    """
    Parse nfs configuration /etc/exports to find no_root_squash directive
    """
    path = '/etc/exports'
    if os.path.exists(path):
        try:
            with open(path) as f:
                for line in f.readlines():
                    if line.startswith('#'):
                        continue

                    if 'no_root_squash' in line.decode():
                        return 'no_root_squash directive found'
        except Exception:
            pass

    return False


def check_python_library_hijacking(user):
    lib_path = []

    # Do not check current directory (it would be writable but no privilege escalation could be done)
    for path in sys.path[1:]:
        if getpass.getuser() not in path:
            f = File(path)
            if f.is_writable(user):
                lib_path.append(path)

    return lib_path
