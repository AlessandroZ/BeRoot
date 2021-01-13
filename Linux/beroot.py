#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import getpass
import time

from beroot.run import run


if __name__ == '__main__':

    banner = '''
|====================================================================|
|                                                                    |
|                      Linux Privilege Escalation                    |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|
'''
    parser = argparse.ArgumentParser(description='%s\nFind a way to BeRoot' % banner, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--version', action='version', version='%(prog)s 1.1')
    parser.add_argument('--password', dest='password', help='if no NOPASSWD in sudoers, sudo -ll needs user password')
    parser.add_argument('-p', dest='pwd', action='store_true', default=False, help='enter password interactively')

    arguments = parser.parse_args()
    start_time = time.time()

    print(banner)

    # Manage password
    password = None
    if arguments.pwd:
        password = getpass.getpass('Password:')
    else: 
        password = arguments.password

    run(password)

    elapsed_time = time.time() - start_time
    print('\nElapsed time = %s' % elapsed_time)
