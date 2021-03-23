#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .sudo.sudo import Sudo
from .useful.useful import tab_of_dict_to_string, tab_to_string


def check_sudoers_misconfigurations(file_info, services, suids, user, rules, already_impersonated=[], result=''):
    """
    Recursive function to analyse sudoers rules
    If a user could impersonate other users others paths using these users are checked
    file_info, services and suids are class to performs checks if user are impersonated
    """
    if rules:

        sudo = Sudo(user)
        paths_found = sudo.anaylyse_sudo_rules(rules)
        if paths_found:
            result += '### Rules for {user} ###\n\n'.format(user=user.pw_name)
            result += tab_of_dict_to_string(paths_found, new_line=False)

            # If this tab is not empty means that we are impersonating another user
            if already_impersonated:
                # Check for other misconfiguration path
                result += tab_of_dict_to_string(file_info.write_access_on_files(user))
                result += tab_of_dict_to_string(services.write_access_on_binpath(user))
                result += tab_of_dict_to_string(suids.check_suid_bins(
                    user),
                    new_line=False,
                    title=False,
                )
                result += tab_to_string(check_python_library_hijacking(user)),

            # Use recursively to realize same checks for impersonated users
            for impersonate in sudo.can_impersonate:
                if impersonate not in already_impersonated:
                    already_impersonated.append(impersonate)
                    result += check_sudoers_misconfigurations(impersonate, rules, already_impersonated, result)

    return result
