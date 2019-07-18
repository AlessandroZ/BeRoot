#!/usr/bin/python
# -*- coding: utf-8 -*-
from beroot.run import check_all, get_sofwares
import argparse
import time
import os


def print_output(output, write=False, file=None):
    to_print = True
    if 'NotPrint' in output:
        to_print = False

    st = '\n################ {category} ################\n'.format(category=output['Category'])

    if 'list' in str(type(output['All'])):
        output['All'] = sorted(output['All'], key=lambda x: output['All'])
        for resultss in output['All']:
            st += '\n[!] %s\n' % resultss['Function'].capitalize()
            results = resultss['Results']

            # Return only one result (True or False)
            if 'bool' in str(type(results)):
                st += '%s\n' % str(results)

            elif 'dict' in str(type(results)):
                for result in results:
                    if 'list' in str(type(results[result])):
                        st += '%s\n' % str(result)
                        for w in results[result]:
                            st += '\t- %s\n' % w
                    st += '\n'

            elif 'list' in str(type(results)):
                for result in results:
                    if 'str' in str(type(result)):
                        st += '%s\n' % result
                    else:
                        for r in sorted(result, key=result.get, reverse=True):
                            if 'list' in str(type(result[r])):
                                st += '%s:\n' % r
                                for w in result[r]:
                                    st += '\t- %s\n' % w
                            else:
                                st += '%s: %s\n' % (r, str(result[r]))
                        st += '\n'
    elif 'str' in str(type(output['All'])):
        st += output['All']

    if to_print:
        print(str(st))

    if write:
        f = open(file, 'a')
        f.write(st)
        f.close()


def run_check_all(list_softwares, write):
    if not list_softwares:
        # Realize all classic checks
        for r in check_all():
            yield r

    # List softwares only when it is asked by the user or when the result is written on a file
    if list_softwares or write:
        # Retrieve all softwares installed
        for r in get_sofwares():
            yield r


if __name__ == '__main__':
    banner = '|====================================================================|\n'
    banner += '|                                                                    |\n'
    banner += '|                    Windows Privilege Escalation                    |\n'
    banner += '|                                                                    |\n'
    banner += '|                          ! BANG BANG !                             |\n'
    banner += '|                                                                    |\n'
    banner += '|====================================================================|\n\n'

    print(banner)

    parser = argparse.ArgumentParser(description="Windows Privilege Escalation")
    parser.add_argument("-l", "--list", action="store_true", help="list all softwares installed (not run by default)")
    parser.add_argument("-w", "--write", action="store_true", help="write output")
    args = parser.parse_args()

    path = None
    if args.write:
        path = os.path.join(os.getcwd(), 'results.txt')
        f = open(path, 'w')
        f.write(banner)
        f.close()

    start_time = time.time()
    for r in run_check_all(args.list, args.write):
        try:
            print_output(r, args.write, path)
        except Exception:
            # Manage unicode
            pass

    elapsed_time = time.time() - start_time
    print('\n[!] Elapsed time = ' + str(elapsed_time))
