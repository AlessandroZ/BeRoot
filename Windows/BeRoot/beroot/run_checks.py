# -*- coding: utf-8 -*-
from beroot.modules.checks.path_manipulation_checks import isRootDirectoryWritable, space_and_no_quotes, exe_with_writable_directory
from beroot.modules.checks.services_checks import check_services_creation_with_openscmanager, check_service_permissions
from beroot.modules.checks.filesystem_checks import check_unattended_files, check_sysprep_files, checks_writeable_directory_on_path_environment_variable, check_well_known_dll_injections
from beroot.modules.checks.registry_checks import registry_key_with_write_access, check_msi_misconfiguration
from beroot.modules.checks.system import can_get_admin_access
from beroot.modules.get_info.from_scmanager_services import GetServices
from beroot.modules.get_info.from_registry import Registry
from beroot.modules.get_info.from_taskscheduler import GetTaskschedulers
from beroot.modules.get_info.softwares_list import Softwares
from beroot.modules.get_info.system_info import System
from beroot.modules.checks.webclient.webclient import WebClient
import traceback
import platform

class RunChecks():

	def __init__(self):

		# Load info from registry
		r = Registry()
		self.service = r.get_services_from_registry()
		self.startup = r.get_sensitive_registry_key()

		# Load info using the SCManager
		s = GetServices()
		self.service = s.get_services(self.service)

		# check taskscheduler
		self.t = GetTaskschedulers()
		self.task = self.t.tasksList()

		self.softwares = Softwares()


	# check registry misconfiguration
	def _check_registry_misconfiguration(self, obj):
		results = []

		# returns a tab of string
		b = registry_key_with_write_access(obj)
		if b:
			results.append(
				{
					'Function': 'registry key with writable access',
					'Results' : b
				}
			)
		return results

	# check path misconfiguration
	def _check_path_misconfiguration(self, obj):
		results = []

		# returns a tab of dictionnary
		b = space_and_no_quotes(obj)
		if b:
			results.append(
				{
					'Function': 'path containing spaces without quotes',
					'Results' : b
				}
			)

		# returns a tab of dictionnary
		b = exe_with_writable_directory(obj)
		if b:
			results.append(
				{
					'Function': 'binary located on a writable directory',
					'Results' : b
				}
			)

		return results

	# ------------------------------ By category ------------------------------

	# Services
	def get_services_vuln(self, args):
		results = []

		# return a boolean
		b = check_services_creation_with_openscmanager()
		if b:
			results.append(
				{
					'Function': 'permission to create a service with openscmanager',
					'Results' : b
				}
			)

		# returns a tab of dictionnary
		b = check_service_permissions(self.service)
		if b:
			results.append(
				{
					'Function': 'Check services that could its configuration could be modified',
					'Results' : b
				}
			)

		results += self._check_path_misconfiguration(self.service)
		results += self._check_registry_misconfiguration(self.service)

		return {
			'Category'	: 'Service',
			'All' 		: results
		}

	# Start up keys
	def get_startup_key_vuln(self, args):

		results = self._check_registry_misconfiguration(self.startup)
		results += self._check_path_misconfiguration(self.startup)

		return {
			'Category'	: 'Startup Keys',
			'All' 		: results
		}

	# MSI configuration
	def get_msi_configuration(self, args):
		results = []
		b = check_msi_misconfiguration()
		if b:
			results.append(
				{
					'Function': 'All MSI file are launched with SYSTEM privileges',
					'Results' : b
				}
			)
		return {
			'Category'	: 'MSI misconfiguration',
			'All' 		: results
		}

	# Taskscheduler
	def get_tasks_vulns(self, args):
		results = []

		# return a boolean
		b = isRootDirectoryWritable(self.t.task_directory)
		if b:
			results.append(
				{
					'Function': 'permission to write on the task directory: %s' % self.t.task_directory,
					'Results' : b
				}
			)

		results += self._check_path_misconfiguration(self.task)

		return {
			'Category'	: 'Taskscheduler',
			'All' 		: results
		}

	# interesting files on the file system
	def get_interesting_files(self, args):
		results = []

		# returns a tab of string
		b = check_unattended_files()
		if b:
			results.append(
				{
					'Function': 'Unattend file found',
					'Results' : b
				}
			)

		# returns a tab of string
		b = check_sysprep_files()
		if b:
			results.append(
				{
					'Function': 'Unattend file found',
					'Results' : b
				}
			)


		return {
			'Category'	: 'Interesting files',
			'All' 		: results
		}

	# useful to find Windows Redistributable version or softwares vulnerable
	def get_installed_softwares(self):

		sof_list = []
		for soft in self.softwares.list_softwares:
			sof_list.append('%s %s' % (soft.name, soft.version))

		results = [
			{
				'Function': 'softwares installed',
				'Results' : sof_list
			},
			{
				'Function': 'av installed',
				'Results' : self.softwares.get_av_software()
			}
		]

		return {
			'Category'	: 'Softwares installed',
			'All' 		: results
		}

	# check if the user is on already administrator
	def isUserAnAdmin(self, args):
		results = []

		# returns boolean
		b = can_get_admin_access()
		if b:
			results.append(
				{
					'Function': 'is user in the administrator group',
					'Results' : b
				}
			)

		return {
			'Category'	: 'Check user admin',
			'All' 		: results
		}

	# this technic should not work on windows 10
	def get_well_known_dll_injections(self, args):

		results = []

		# From msdn: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
		# 6.0 	=> 	Windows Vista	/ 	Windows Server 2008
		# 6.1 	=> 	Windows 7 		/ 	Windows Server 2008 R2
		# 6.2 	=> 	Windows 8 		/ 	Windows Server 2012

		s = System()
		version = s.get_os_version()
		if version in ['6.0', '6.1', '6.2']:

			# return a tab of string
			b = checks_writeable_directory_on_path_environment_variable()
			if b:
				results.append(
					{
						'Function': 'Writeable path on the path environment variable',
						'Results' : b
					}
				)

				# return a tab of dic
				b = check_well_known_dll_injections(self.service)
				if b:
					results.append(
						{
							'Function': 'Check if well known vulnerable services are present',
							'Results' : b
						}
					)

		return {
			'Category'	: 'Check well known dlls hijacking',
			'All' 		: results
		}

	# this technic has been patched on June 2016
	def check_webclient(self, cmd='whoami'):
		results = []

		print('-------------- Get System Priv with WebClient --------------\n')

		w = WebClient()
		# returns boolean
		b = w.run(self.service, cmd)
		if b:
			results.append(
				{
					'Function': 'NTLM System token retrieved: ',
					'Results' : b
				}
			)

		return {
			'NotPrint'	: True,
			'Category'	: 'Get System Priv with WebClient',
			'All' 		: results
		}

def get_sofwares():
	checks = RunChecks()
	yield checks.get_installed_softwares()


def check_all(cmd=None):
	checks = RunChecks()
	found = False

	to_cheks = [
		checks.get_msi_configuration,				# check msi misconfiguration
		checks.get_services_vuln, 					# service checks
		checks.get_startup_key_vuln, 				# startup keys checks
		checks.get_tasks_vulns,						# taskschedulers checks
		checks.get_interesting_files, 				# interesting files checks
		# checks.get_installed_softwares, 			# softwares checks
		checks.isUserAnAdmin, 						# system if already admin (uac not bypassed yet)
		checks.get_well_known_dll_injections,		# well known windows services vulnerable to dll hijacking
		checks.check_webclient
	]

	for c in to_cheks:
		try:
			results = c(cmd)
			if results['All']:
				found = True
				yield results
		except:
			yield {
				'Category'	: 'Error on: %s' % str(c.__name__),
				'All'		: str(traceback.format_exc())
			}

	if not found:
		yield {
			'Category'	: 'No Luck',
			'All'		: '\nNothing found !'
		}
