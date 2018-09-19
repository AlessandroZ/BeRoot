#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import stat
import traceback

from beroot.analyse.binaries import Binaries


class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OK = '\033[92m'
    WARNING = '\033[96m'
    FAIL = '\033[91m'
    TITLE = '\033[93m'
    ENDC = '\033[0m'


# ######## ANALYSE RESULTS #########


class Analyse:
    """
    Analyse results to have an output by module
    """

    def __init__(self, checks, color=True):
        self.checks = checks
        self.interesting_bin = Binaries()
        self.users = self.checks.users
        self.nothing_found = True
        self.sensitive_files = None
        self.suid_files = None
        self.color = color
        self.bcolors = Bcolors
        self.results = []

    def print_log(self, level='', msg=''):
        prefix = ''

        if level == 'ok':
            if self.color:
                prefix = self.bcolors.OK + '[+] ' + self.bcolors.ENDC
            else:
                prefix = '[+] '
            self.nothing_found = False

        elif level == 'error':
            if self.color:
                prefix = self.bcolors.FAIL + '[-] ' + self.bcolors.ENDC
            else:
                prefix = '[-] '

        elif level == 'info':
            prefix = '[!] '

        elif level == 'debug':
            prefix = '[?] '

        self.results.append((level, msg))

        print('{prefix}{msg}'.format(prefix=prefix, msg=msg))

    def is_writable(self, file, user):
        """
        Check writable access to a file from a wanted user
        https://docs.python.org/3/library/stat.html
        """
        uid = user.pw_uid
        gid = user.pw_gid
        if file.permissions:
            mode = file.permissions[stat.ST_MODE]
            return (
                    ((file.permissions[stat.ST_UID] == uid) and (mode & stat.S_IWUSR)) or  # Owner has write permission.
                    ((file.permissions[stat.ST_GID] == gid) and (mode & stat.S_IWGRP)) or  # Group has write permission.
                    (mode & stat.S_IWOTH)  # Others have write permission.
            )

    def get_user(self, user):
        """
        Find a user pw object from his name
        - user is a string
        - u is an object
        """
        for u in self.users.list:
            if u.pw_name == user:
                return u

        return False

    def anaylyse_files_permissions(self, files, user, check_wildcards=True):
        for fm in files:

            # Check if file has write access
            if self.is_writable(fm.file, user):
                self.print_log('ok', 'Writable file: {file}\n'.format(file=fm.file.path))

            # Check path found inside files
            for sub in fm.subfiles:
                ok = False
                for p in sub.paths:
                    if self.is_writable(p, user):
                        ok = True
                        break

                # Something has been found
                if ok:
                    self.print_log('info', 'Inside: {file}'.format(file=fm.file.path))
                    self.print_log('info', 'Line: {line}'.format(line=sub.line))
                    for p in sub.paths:
                        if self.is_writable(p, user):
                            self.print_log('ok', 'Writable path: {file}'.format(file=p.path))
                    self.print_log()

                # Check for wildcards
                if '*' in sub.line and check_wildcards:
                    for p in sub.paths:
                        shell_escape = self.interesting_bin.find_binary(p.basename)
                        if shell_escape:

                            # IMPROVEMENT: could be interesting to check if write permission on directory
                            # => to exploit wildcard, a file should be created.
                            # Check from where the script has been called
                            name = p.path if not p.alias else p.alias

                            # Check that the wildcard is added after the interesting binary
                            if sub.line.index(name) < sub.line.index('*'):
                                self.print_log('info', 'Inside: {file}'.format(file=fm.file.path))
                                self.print_log('info', 'Wildcard found on line: {line}'.format(line=sub.line))
                                self.print_log('ok', 'Interesting bin: {bin}'.format(bin=name))
                                self.print_log('info', 'Shell escape method: \n{cmd}\n'.format(cmd=shell_escape))

    def anaylyse_sudo_rules(self, sudoers_info, ld_preload, user, user_chain=''):
        """
        sudoers_info is a didctonary containing all rules found on the sudoers file
        ld_preload variable is a boolean saying that LD_PRELOAD on the env_keep variable
        user is an object containing the current user properties
        """

        if ld_preload:
            self.print_log('ok', 'Environment for LD_PRELOAD set as default specification')

        # Get associated groups for the current user
        user_groups = [g.gr_name for g in self.users.groups.getgrall() if user.pw_name in g.gr_mem]

        for sudoers in sudoers_info:

            need_password = True
            # NOPASSWD present means that no password is required to execute the commands
            if 'NOPASSWD' in sudoers['directives']:
                need_password = False

            # Check if the sudoers line affects the current user or his group
            rule_ok = False
            for user_or_group in sudoers['users']:
                if user_or_group.startswith('%') and user_or_group[1:] in user_groups:
                    rule_ok = True
                elif user.pw_name == user_or_group:
                    rule_ok = True

            if rule_ok:

                for cmd in sudoers['cmds']:
                    ok = False
                    msg = []

                    # Action denied, continue
                    if cmd.line.startswith('!'):
                        continue

                    # All access
                    elif cmd.line.strip() == 'ALL':
                        ok = True

                    # All cmds available by the rule
                    for c in cmd.paths:

                        # If write permission on the file
                        if self.is_writable(c, user):
                            ok = True
                            msg.append(('ok', 'Write permission on {file}'.format(file=c.path)))

                        # Interesting binary found
                        shell_escape = self.interesting_bin.find_binary(c.basename)
                        if shell_escape:
                            args = cmd.line.strip()[cmd.line.strip().index(c.basename) + len(c.basename):].strip()
                            ok = True

                            # Check if no args but *
                            if not args.strip():
                                pass  # Exploitable (message is printed at the end)

                            # Check for wildcards
                            elif '*' in args:
                                msg.append(('info', 'Should be exploitable using wildcards'))

                            # Let the user find if it's still exploitable => but not sure (could be a false positive)
                            else:
                                msg.append(('info', 'Could be a false positive'))

                            msg.append(('ok', 'Interesting bin found: {bin}'.format(bin=c.basename)))
                            msg.append(('info', 'Shell escape method: \n{cmd}'.format(cmd=shell_escape)))

                        if c.basename == 'su':
                            args = cmd.line.strip()[cmd.line.strip().index(c.basename) + len(c.basename):].strip()

                            # Every users could impersonated or at least root
                            if args.strip() == 'root' or not args.strip():
                                ok = True
                                msg.append(('ok', 'Impersonation can be done on root user'))

                            else:
                                if args.strip() == '*':
                                    users = [u for u in self.users.list if u.pw_uid != os.getuid()]
                                else:
                                    users = [self.get_user(user=args.strip())]
                                
                                if users:
                                    for u in users:
                                        self.print_log('info', 'Impersonating user "{user}" using line: {line}'.format(
                                            user=u.pw_name, line=cmd.line.strip()))

                                        # Check all sensitive files for write access using the impersonated user
                                        self.anaylyse_files_permissions(self.sensitive_files, user=u, check_wildcards=False)

                                        # Check suid files for write access using the impersonated user
                                        self.anaylyse_suids(self.suid_files, user=u, ckeck_only_write_access=True)

                                        # Realize same check on sudoers file using the impersonated user
                                        self.anaylyse_sudo_rules(sudoers_info=sudoers_info, ld_preload=False, user=u, user_chain=user_chain + ' -> ' + u.pw_name)

                                else:
                                    ok = True  # should be a false positive but I prefer to print it anyway
                                    msg.append(('error', 'User not found: {user}'.format(user=args.strip())))

                    if ok:
                        if need_password:
                            self.print_log('error', 'Rule (Password required): {line}'.format(line=cmd.line.strip()))
                        else:
                            self.print_log('ok', 'Rule (NOPASSWD used): {line}'.format(line=cmd.line.strip()))

                        self.print_log('info', 'From user {user}'.format(user=user_chain))
                        for m in msg:
                            self.print_log(m[0], m[1])
                        self.print_log('', '')

    def anaylyse_suids(self, suids, user, ckeck_only_write_access=False):

        for suid in suids:
            if not ckeck_only_write_access:
                # Print every suid file (because a manually check should be done on these binaries)
                self.print_log('info', '{suid}'.format(suid=suid.file.path))

            if self.is_writable(suid.file, user):
                self.print_log('ok', 'Writable suid file: {suid_file}'.format(suid_file=suid.file.path))

            if not ckeck_only_write_access:
                shell_escape = self.interesting_bin.find_binary(suid.file.basename)
                if shell_escape:
                    self.print_log('ok', 'Interesting bin: {bin}'.format(bin=suid.file.path))
                    self.print_log('info', 'Shell escape method: \n{cmd}'.format(cmd=shell_escape))

    def anaylyse_nfs_conf(self, result, user):

        if result['result']:
            self.print_log('ok', 'Directive no_root_squash found: "{line}"'.format(line=result['result']))

    def anaylyse_docker(self, is_docker_installed):

        if is_docker_installed:
            self.print_log('ok', 'Docker service found !')
            self.print_log('info',
                           'Shell escape method: \n{cmd}'.format(cmd=self.interesting_bin.find_binary('docker')))

    def anaylyse_result(self, module, result):
        """
        Launch parsing of results depending of the module
        """
        if module == 'files_permissions':
            self.sensitive_files = result  # Store data to do tests later
            self.anaylyse_files_permissions(result, user=self.users.current)  # users is a pwd objet

        elif module == 'sudo_rules':
            self.anaylyse_sudo_rules(sudoers_info=result[0], ld_preload=result[1], user=self.users.current, user_chain=self.users.current.pw_name)

        elif module == 'suid_bin':
            self.suid_files = result
            self.anaylyse_suids(result, user=self.users.current)

        elif module == 'nfs_root_squashing':
            self.anaylyse_nfs_conf(result, user=self.users.current)

        elif module == 'docker':
            self.anaylyse_docker(result)

        elif module == 'exploit':
            prefix = 'error'
            output = result.decode()
            if 'CVE' in output:
                prefix = 'ok'
            self.print_log(prefix, 'CVE found!\n{output}'.format(output=output))

    def run(self):
        """
        Analyse all results found on the Checks classes
        """
        if os.geteuid() == 0:
            self.print_log('error', 'You are already root.')
        else:
            for module, result in self.checks.run():
                try:
                    self.print_log('', '\n################# {module} #################\n'.format(
                        module=module.replace('_', ' ').capitalize()))

                    self.nothing_found = True
                    self.anaylyse_result(module, result)
                    if self.nothing_found:
                        self.print_log('error', 'Nothing found !')

                except Exception:
                    # Print full stracktrace to understand the error
                    self.print_log('error', traceback.format_exc())

        return self.results