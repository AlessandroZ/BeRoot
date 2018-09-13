#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import time

from beroot.analyse.analyse import Analyse
from beroot.checks.checks import Checks


if __name__ == '__main__':
    banner = '|====================================================================|\n'
    banner += '|                                                                    |\n'
    banner += '|                      Linux Privilege Escalation                    |\n'
    banner += '|                                                                    |\n'
    banner += '|                          ! BANG BANG !                             |\n'
    banner += '|                                                                    |\n'
    banner += '|====================================================================|\n'

    parser = argparse.ArgumentParser(description='Find a way to BeRoot')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    # parser.add_argument('--docker', dest='docker', action='store_true', help='check if docker service installed')
    # parser.add_argument('--exploit', dest='exploit', action='store_true', help='list possible exploit')
    # parser.add_argument('--nfs', dest='nfs_squashing', action='store_true', help='check if nfs squashing as root possible')
    # parser.add_argument('--files', dest='file_permission', action='store_true', help='check for bad file permission')
    # parser.add_argument('--suid', dest='suid', action='store_true', help='check suid binaries')
    # parser.add_argument('--sudo', dest='sudo', action='store_true', help='check for bad sudo rules')

    args = vars(parser.parse_args())

    start_time = time.time()

    c = Checks()
    analyse = Analyse(c)

    analyse.print_log('', banner)
    analyse.run()

    elapsed_time = time.time() - start_time
    analyse.print_log('info', 'Elapsed time = {elapsed_time}'.format(elapsed_time=elapsed_time))

