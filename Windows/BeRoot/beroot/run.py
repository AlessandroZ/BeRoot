# -*- coding: utf-8 -*-
import traceback

from .modules.checks.path_manipulation_checks import is_root_dir_writable, space_and_no_quotes, \
    exe_with_writable_directory
from .modules.checks.services_checks import check_services_creation_with_openscmanager, check_service_permissions
from .modules.checks.filesystem_checks import check_unattended_files, check_sysprep_files, \
    checks_writeable_directory_on_path_environment_variable, check_well_known_dll_injections
from .modules.checks.registry_checks import registry_key_with_write_access, check_msi_misconfiguration
from .modules.checks.system import can_get_admin_access
from .modules.get_info.from_scmanager_services import GetServices
from .modules.get_info.from_registry import Registry
from .modules.get_info.from_taskscheduler import GetTaskschedulers
from .modules.get_info.softwares_list import Softwares
from .modules.get_info.system_info import System


class RunChecks(object):

    def __init__(self):

        # Load info from registry
        r = Registry()
        self.service = r.get_services_from_registry()
        self.startup = r.get_sensitive_registry_key()

        # Load info using the SCManager
        s = GetServices()
        self.service = s.get_services(self.service)

        # Check taskscheduler
        self.t = GetTaskschedulers()
        self.task = self.t.tasks_list()

        self.softwares = Softwares()

    def _check_registry_misconfiguration(self, obj):
        """
        Check registry misconfiguration
        """
        results = []

        # Returns a tab of string
        b = registry_key_with_write_access(obj)
        if b:
            results.append(
                {
                    'Function': 'Registry key with writable access',
                    'Results': b
                }
            )
        return results

    def _check_path_misconfiguration(self, obj):
        """
        Check path misconfiguration
        """
        results = []

        # Returns a tab of dictionary
        b = space_and_no_quotes(obj)
        if b:
            results.append(
                {
                    'Function': 'Path containing spaces without quotes',
                    'Results': b
                }
            )

        # Returns a tab of dictionary
        b = exe_with_writable_directory(obj)
        if b:
            results.append(
                {
                    'Function': 'Binary located on a writable directory',
                    'Results': b
                }
            )

        return results

    # ------------------------------ By category ------------------------------

    # Services
    def get_services_vuln(self, args):
        results = []

        # Returns a boolean
        b = check_services_creation_with_openscmanager()
        if b:
            results.append(
                {
                    'Function': 'Permission to create a service with openscmanager',
                    'Results': b
                }
            )

        # Returns a tab of dictionary
        b = check_service_permissions(self.service)
        if b:
            results.append(
                {
                    'Function': 'Check for services whose configuration could be modified',
                    'Results': b
                }
            )

        results += self._check_path_misconfiguration(self.service)
        results += self._check_registry_misconfiguration(self.service)

        return {
            'Category': 'Service',
            'All': results
        }

    def get_startup_key_vuln(self, args):
        """
        Start up keys
        """
        results = self._check_registry_misconfiguration(self.startup)
        results += self._check_path_misconfiguration(self.startup)

        return {
            'Category': 'Startup Keys',
            'All': results
        }

    def get_msi_configuration(self, args):
        """
        MSI configuration
        """
        results = []
        b = check_msi_misconfiguration()
        if b:
            results.append(
                {
                    'Function': 'All MSI file are launched with SYSTEM privileges',
                    'Results': b
                }
            )
        return {
            'Category': 'MSI misconfiguration',
            'All': results
        }

    def get_tasks_vulns(self, args):
        """
        Taskscheduler
        """
        results = []

        # return a boolean
        b = is_root_dir_writable(self.t.task_directory)
        if b:
            results.append(
                {
                    'Function': 'Permission to write on the task directory: %s' % self.t.task_directory,
                    'Results': b
                }
            )

        results += self._check_path_misconfiguration(self.task)

        return {
            'Category': 'Taskscheduler',
            'All': results
        }

    #
    def get_interesting_files(self, args):
        """
        Interesting files on the file system
        """
        results = []

        # Returns a tab of string
        b = check_unattended_files()
        if b:
            results.append(
                {
                    'Function': 'Unattended file found',
                    'Results': b
                }
            )

        # Returns a tab of string
        b = check_sysprep_files()
        if b:
            results.append(
                {
                    'Function': 'Unattended file found',
                    'Results': b
                }
            )

        return {
            'Category': 'Interesting files',
            'All': results
        }

    def get_installed_softwares(self):
        """
        Useful to find Windows Redistributable version or software vulnerable
        """

        sof_list = []
        for soft in self.softwares.list_softwares:
            sof_list.append('%s %s' % (soft.name, soft.version))

        results = [
            {
                'Function': 'Software installed',
                'Results': sof_list
            },
            {
                'Function': 'AV installed',
                'Results': self.softwares.get_av_software()
            }
        ]

        return {
            'Category': 'Software installed',
            'All': results
        }

    def is_user_an_admin(self, args):
        """
        Check if the user is already an administrator
        """
        results = []

        # Returns boolean
        b = can_get_admin_access()
        if b:
            results.append(
                {
                    'Function': 'Is user in the Administrators group',
                    'Results': b
                }
            )

        return {
            'Category': 'Check user admin',
            'All': results
        }

    def get_well_known_dll_injections(self, args):
        """
        This technique should not work on windows 10
        """
        # From msdn: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
        # 6.0 => Windows Vista  /   Windows Server 2008
        # 6.1 => Windows 7      /   Windows Server 2008 R2
        # 6.2 => Windows 8      /   Windows Server 2012

        results = []
        s = System()
        version = s.get_os_version()
        if version in ['6.0', '6.1', '6.2']:

            # Return a tab of string
            b = checks_writeable_directory_on_path_environment_variable()
            if b:
                results.append(
                    {
                        'Function': 'Writeable path on the path environment variable',
                        'Results': b
                    }
                )

                # Return a tab of dic
                b = check_well_known_dll_injections(self.service)
                if b:
                    results.append(
                        {
                            'Function': 'Check if well known vulnerable services are present',
                            'Results': b
                        }
                    )

        return {
            'Category': 'Check well known dlls hijacking',
            'All': results
        }

def get_sofwares():
    checks = RunChecks()
    yield checks.get_installed_softwares()


def check_all(cmd=None):
    checks = RunChecks()
    found = False

    to_checks = [
        checks.get_msi_configuration,  # Check msi misconfiguration
        checks.get_services_vuln,  # Service checks
        checks.get_startup_key_vuln,  # Startup keys checks
        checks.get_tasks_vulns,  # Taskschedulers checks
        checks.get_interesting_files,  # Interesting files checks
        # checks.get_installed_softwares,           # Softwares checks
        checks.is_user_an_admin,  # System if already admin (uac not bypassed yet)
        checks.get_well_known_dll_injections,  # Well known windows services vulnerable to dll hijacking
    ]

    for c in to_checks:
        try:
            results = c(cmd)
            if results['All']:
                found = True
                yield results
        except Exception:
            yield {
                'Category': 'Error on: %s' % str(c.__name__),
                'All': str(traceback.format_exc())
            }

    if not found:
        yield {
            'Category': 'No Luck',
            'All': '\nNothing found !'
        }


def run(cmd=None):
    results = []
    for r in check_all(cmd):
        results.append(r)
    return results