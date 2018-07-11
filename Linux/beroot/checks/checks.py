#!/usr/bin/env python
# -*- coding: utf-8 -*-
from beroot.analyse.binaries import Binaries
from beroot.checks.exploit import Exploit
from beroot.conf.files import FileManager
from beroot.conf.users import Users
import subprocess
import os

class Checks():
	'''
	Retrieve configuration information
	This class does not analyse any information retrieved
	'''
	def __init__(self):
		self.interesting_bin 	= Binaries()
		self.exploit 			= Exploit()

	def get_users(self):
		'''
		Get list of all users with their uid, gid
		''' 
		return Users()

	def get_possible_exploit(self):
		'''
		Execute linux exploit suggester on the system
		'''
		return 'exploit', self.exploit.run()

	def check_suid_bin(self):
		'''
		List all suid binaries
		Using find is much faster than using python to loop through all files looking for suid binaries
		'''
		# For GUID => find / -perm -g=s -type f 2>/dev/null

		cmd 		= 'find / -perm -u=s -type f 2>/dev/null'
		process 	= subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err 	= process.communicate()
		suid 		= []

		for file in out.strip().decode().split('\n'):			
			fm = FileManager(file)
			suid.append(fm)
		
		return 'suid_bin', suid

	def check_files_permissions(self):
		'''
		Check access on write permissions on sensitive files. 
		'''
		result 				= []
		interesting_files 	= [
			# directories
			'/etc/init.d'
			'/etc/cron.d', 
			'/etc/cron.daily',
			'/etc/cron.hourly',
			'/etc/cron.monthly',
			'/etc/cron.weekly',
			
			# files
			'/etc/sudoers',
			'/etc/exports',
			'/etc/at.allow',
			'/etc/at.deny',
			'/etc/crontab',
			'/etc/cron.allow',
			'/etc/cron.deny',
			'/etc/anacrontab',
			'/var/spool/cron/crontabs/root', 
		]

		for path in interesting_files:
			if os.path.isdir(path):
				for root, dirs, files in os.walk(path):
					for file in files:
						fullpath = os.path.join(root, file)
						fm = FileManager(fullpath, check_inside=True)
						result.append(fm)
			else:
				fm = FileManager(path, check_inside=True)
				result.append(fm)

		return 'files_permissions', result

	def check_sudoers(self):
		'''
		Check sudoers file - /etc/sudoers
		'''
		result 	= []
		sfile 	= '/etc/sudoers'
		fm 		= FileManager(sfile)
		
		if fm.file.is_readable:
			result = fm.parse_sudoers(sfile)

		return 'sudoers_file', result

	def check_nfs_root_squashing(self):
		'''
		Check NFS Root Squashing - /etc/exports
		'''
		result 	= []
		sfile 	= '/etc/exports'
		fm 		= FileManager(sfile)

		if fm.file.is_readable:
			result = fm.parse_nfs_conf(sfile)

		return 'nfs_root_squashing', {'file': fm, 'result': result}


	def is_docker_installed(self): 
		'''
		Check if docker service is present
		'''
		module = 'docker'
		return (module, True) if os.path.exists('/etc/init.d/docker') else (module, False)

	def run(self):
		''' 
		Run all functions to retrieve system misconfigurations
		'''
		checks = [
			self.check_files_permissions, 
			self.check_suid_bin,
			self.check_nfs_root_squashing,
			self.is_docker_installed,
			self.check_sudoers,
			self.get_possible_exploit,
		]
		
		for check in checks:
			yield check()
