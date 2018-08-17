#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import os


class File:
    """
    File properties
    alias: if binary are directly called inside files (ex: chmod +x ... => path = /bin/chmod and alias = chmod)
    """

    def __init__(self, path, alias=None):
        self.path = os.path.realpath(path)  # Follow symbolic link
        self.alias = alias
        self.basename = os.path.basename(self.path)
        self.dirname = os.path.dirname(self.path)
        self.is_readable = self.is_readable(self.path)
        self.permissions = self.get_permissions(self.path)

    def get_permissions(self, path):
        try:
            return os.stat(path)
        except Exception:
            return None

    def is_readable(self, path):
        """
        Check read permission on a file for the current user
        """
        return True if os.access(path, os.R_OK) else False

    # def is_suid(self, path):
    #     """
    #     Check if the file is SUID (not used, should be removed)
    #     """
    #     return True if (os.stat(path).st_mode & stat.S_ISUID) != 0 else False


class PathInFile:
    """
    Path found inside configuration files (such as crons, services, etc.)
    """

    def __init__(self, line, paths=[]):
        self.line = line
        self.paths = paths  # Tab of File object


class FileManager:
    """
    Manage file objects
    """

    def __init__(self, path, check_inside=False):
        self.file = File(path)
        self.subfiles = []  # Tab of PathInFile object
        self.path_pattern = re.compile(r"^[\'\"]?(?:/[^/]+)*[\'\"]?$")
        self.sudoers_pattern = re.compile(r"(\((?P<runas>\w+)\)* )*(((\w+): *)*)(?P<cmds>.*)")
        self.sudoers_info = None

        if self.file.is_readable and check_inside:
            self.subfiles = self.parse_file(path)

    def extract_paths_from_string(self, string):
        """
        Extract paths from string and check if we have write access on it
        """
        paths = []
        blacklist = ['/dev/null', '/var/crash']  # Remove false positive
        built_in = ['/bin', '/usr/bin/', '/sbin', '/usr/sbin']
        string = string.replace(',', ' ')

        # Split line to manage multiple path on a line - will not work for path containing quotes and a space
        for path in string.strip().split():
            m = self.path_pattern.search(path.strip())
            if m and m.group():
                filepath = m.group().strip()
                if os.path.exists(filepath) and os.path.realpath(filepath) not in blacklist:
                    paths.append(
                        File(filepath)
                    )

            # If the regex does not match a path, it could be a built-in binary inside /bin or /usr/bin
            else:
                for b in built_in:
                    filepath = os.path.join(b, path)
                    if os.path.exists(filepath) and filepath not in ['/', '.']:  # Remove false positive
                        paths.append(
                            File(filepath, alias=path)
                        )
        return paths

    def parse_file(self, path):
        """
        Try to find paths inside a file using regex
        """
        result = []
        with open(path) as f:
            try:
                for line in f.readlines():
                    paths = self.extract_paths_from_string(line.strip())
                    if paths:
                        result.append(
                            PathInFile(line=line.strip(), paths=paths)
                        )
            except Exception:
                pass
        return result

    def manage_alias(self, kind_alias, data, alias_name):
        """
        Replace the value with the alias if an alias exists
        ex:
        - User_Alias ADMINS = admin, test, root
        - user,ADMINS ALL = (ALL) su root => users tab will be considered as ['user', 'admin', 'test', 'root']
        """
        if data:
            for alias in kind_alias[alias_name]:
                if alias in data:
                    return [d.strip() for d in data.split(',') if d != alias] + kind_alias[alias_name][alias]

            # No alias found, return the result as tab
            return [d.strip() for d in data.split(',')]

    def parse_sudoers(self, path):
        """
        Parse sudoers file to check write permissions on all files with the NOPASSWD directive
        """
        alias = []
        sudoers_info = []
        tmp_line = ''
        ld_peload = False
        kind_alias = {
            'User_Alias': {},
            'Runas_Alias': {},
            'Host_Alias': {},
            'Cmnd_Alias': {},
        }

        with open(path) as f:
            for line in f.readlines():
                # Comment line
                if line.startswith('#'):
                    continue

                # "Defaults" directive only check for env_keep
                if line.startswith('Defaults'):
                    if 'env_keep' in line and 'LD_PRELOAD' in line:
                        ld_peload = True
                        continue

                # Manage when lines are written in multiple lines (lines ending with "\"")
                if line.strip().endswith('\\'):
                    tmp_line += line.strip()[:-1]
                    continue
                else:
                    if tmp_line:
                        line = tmp_line + line.strip()
                        tmp_line = ''

                # ----- Manage all kind of alias -----

                alias_line = False
                for alias in kind_alias:
                    if line.startswith(alias):
                        for l in line.split(':'):
                            alias_name, alias_cmd = l.split('=')
                            alias_name = alias_name.replace(alias, '').strip()

                            if alias_name in kind_alias[alias]:
                                kind_alias[alias][alias_name] += [a.strip() for a in alias_cmd.split(',')]
                            else:
                                kind_alias[alias][alias_name] = [a.strip() for a in alias_cmd.split(',')]
                            alias_line = True
                        break

                if alias_line:
                    continue

                # ----- End of Alias -----

                # Basic command pattern: "users  hosts = (run-as) directive: commands"
                try:
                    owner, cmds = line.strip().split('=')
                    users, hosts = owner.split()

                    m = self.sudoers_pattern.search(cmds.strip())
                    runas = m.group("runas")
                    cmds = m.group("cmds")

                    # Manage alias
                    users = self.manage_alias(kind_alias, users, 'User_Alias')
                    hosts = self.manage_alias(kind_alias, hosts, 'Host_Alias')
                    runas = self.manage_alias(kind_alias, runas, 'Runas_Alias')
                    cmds = self.manage_alias(kind_alias, cmds, 'Cmnd_Alias')

                    # cmds could be a list of many cmds with many path (split all cmd and check if writable path inside)
                    commands = [PathInFile(line=cmd.strip(), paths=self.extract_paths_from_string(cmd.strip())) for cmd
                                in cmds if cmd.strip()]
                    sudoers_info.append(
                        {
                            'users': users,  # if begins with % it's a group => to manage soon
                            'hosts': hosts,
                            'runas': runas,
                            'directives': [directive.strip() for directive in m.group(3).split(':') if
                                           directive.strip()],
                            'cmds': commands,
                        }
                    )
                except Exception as e:
                    pass

        return (sudoers_info, ld_peload)

    def parse_nfs_conf(self, path):
        """
        Parse nfs configuration /etc/exports to find no_root_squash directive
        """
        with open(path) as f:
            for line in f.readlines():
                if line.startswith('#'):
                    continue

                if 'no_root_squash' in line.decode():
                    return line.decode()

        return False
