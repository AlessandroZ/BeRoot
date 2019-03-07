
import os
import pwd
import random
import re
import string
import tempfile
import traceback

from subprocess import Popen, PIPE

from beroot.conf.files import PathInFile, FileManager
from beroot.conf.users import Users


class SudoList:
    """
    Get sudo rules from sudo -l
    """
    def __init__(self):
        self.sudoers_pattern = re.compile(r"(\( ?(?P<runas>.*) ?\)) ?(?P<directives>(\w+: ?)*)(?P<cmds>.*)")
        self.all_rules = []
        self.sudo_cmd = 'echo "test" | sudo -S -ll'

    def run_cmd(self, cmd, is_ok=False):
        """
        If is_ok return True if success and not the output
        """
        p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
        out, err = p.communicate()
        if p.returncode:
            return False
        else:
            if is_ok:
                return True
            else:
                return out

    def parse_sudo_list(self, sudo_list):
        """
        Parse output from sudo -ll
        """
        sudoers_info = []
        fm = FileManager('')
        user = sudo_list[sudo_list.index('User '):].split(' ')[1]
        sudoers_entries = sudo_list.lower().split('sudoers entry')
        for sudo_rule in sudoers_entries:

            if not sudo_rule.startswith(':'):
                continue
            pattern = re.compile(
                r"\s*" +
                "runasusers:\s*(?P<runasusers>\w*)" +
                "\s*" +
                "(runasgroups:\s*(?P<runasgroups>\w*))*" +
                "\s*" +
                "(options:\s*(?P<options>[\!\w]*))*" +
                "\s*" +
                "(commands:\s*(?P<commands>.*))*",
                re.DOTALL
            )
            m = pattern.search(sudo_rule)
            # Default to empty string '' for values we didn't match
            data = m.groupdict('')
            # Remove whitespace and extra tabs from list of commands
            cmds = [PathInFile(line=cmd.strip(), paths=fm.extract_paths_from_string(cmd.strip()))
                    for cmd in data['commands'].strip().replace('\t', '').split('\n')]

            sudoers_info.append({
                'users': [user],
                'runas': data['runasusers'],
                'directives': data['options'],
                'cmds': cmds,
            })

        self.all_rules += sudoers_info
        return sudoers_info

    def get_user_to_impersonate(self, sudo_rules):
        """
        Check if in the sudo rule, user impersonation is possible (using su bin)
        """
        users = []
        for rules in sudo_rules:
            for cmd in rules['cmds']:
                for c in cmd.paths:
                    if c.basename == 'su':
                        u = cmd.line.strip()[cmd.line.strip().index(c.basename) + len(c.basename):].strip()
                        if u.strip() == '*':
                            users = [u.pw_name for u in pwd.getpwall() if u.pw_uid != os.getuid()]
                        else:
                            users.append(u)
        return users

    def impersonate_user(self, users_chain=[]):
        """
        Get the user to impersonate and return his sudo -l output

        For example:
        - The current user has "su" rule to impersonate user A
        - The user A can impersonate user B (but the current user cannot)
        - User B has root privilege
        => users_chain = ["user A", "user B"]

        sudo -l return only rules concerning the user launching this command. 
        
        The trick is to use a temporary file like following: 
        sudo su test << 'EOF'         
        echo "test" | sudo -S -l
        EOF
        """
        data = ''
        for u in users_chain:
            data += "sudo su {user} << 'EOF'\n".format(user=u)

        data += self.sudo_cmd + '\n'
        
        if users_chain: 
            data += '\nEOF'

        rand = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
        path = os.path.join(tempfile.gettempdir(), rand) + '.sh'
        with open(path, 'w') as file:
            file.write(data)

        out = None
        if os.path.exists(path):
            out = self.run_cmd(cmd='chmod +x {path}'.format(path=path), is_ok=True)
            if out:
                out = self.run_cmd(cmd=path)
            os.remove(path)
            return out

    def impersonate_mechanism(self, user, sudo_rules, users_chain=[], already_impersonated=[]):
        """
        Recursive function to retrieve all sudo rules
        All rules for all possible users are stored on "all_rules"
        """
        users_to_imp = self.get_user_to_impersonate(sudo_rules)
        if not users_to_imp:
            return ''

        for u in users_to_imp:
            if u not in already_impersonated:
                sudo_list = self.impersonate_user(users_chain=[user, u])
                if sudo_list:
                    try:
                        sudo_rules = self.parse_sudo_list(sudo_list)
                        self.impersonate_mechanism(u, sudo_rules, [user, u], already_impersonated)
                    except Exception:
                        print(traceback.format_exc())
                        continue

                    already_impersonated.append(u)

    def parse(self):
        sudo_list = self.run_cmd(self.sudo_cmd)
        if sudo_list:
            sudo_rules = self.parse_sudo_list(sudo_list)
            current_user = Users().current.pw_name
            self.impersonate_mechanism(current_user, sudo_rules, users_chain=[])
        return self.all_rules, False
