#!/usr/bin/env python
# -*- coding: utf-8 -*-
from beroot.analyse.binaries import Binaries
from beroot.checks.checks import Checks
import stat
import os

######### ANALYSE RESULTS #########

class Analyse():
	'''
	Analyse results to have an output by module
	'''
	def __init__(self):
		self.checks 			= Checks()
		self.interesting_bin 	= Binaries()
		self.users 				= self.checks.get_users()
		self.nothing_found 	 	= True
		self.sensitive_files 	= None
		self.suid_files			= None

	def is_writable(self, file, user):
		'''
		Check writable access to a file from a wanted user
		https://docs.python.org/3/library/stat.html
		'''
		uid = user.pw_uid
		gid = user.pw_gid
		if file.permissions:
			mode = file.permissions[stat.ST_MODE]
			return (
				((file.permissions[stat.ST_UID] == uid) and (mode & stat.S_IWUSR)) or 		# Owner has write permission.
				((file.permissions[stat.ST_GID] == gid) and (mode & stat.S_IWGRP)) or 		# Group has write permission.
				(mode & stat.S_IWOTH) 														# Others have write permission.
			)

	def get_user(self, user): 
		'''
		Find a user pw object from his name
		- user is a string 
		- u is an object
		'''
		for u in self.users.list: 
			if u.pw_name == user:
				return u

		return False

	def anaylyse_files_permissions(self, files, user, check_wildcards=True):
		
		for fm in files:

			# Check if file has write access
			if self.is_writable(fm.file, user):
				print '[+] Writable file: {file}\n'.format(file=fm.file.path)
				self.nothing_found = False

			# Check path found inside files
			for sub in fm.subfiles:
				ok = False
				for p in sub.paths:
					if self.is_writable(p, user):
						ok = True
						break

				# Something has been found, print a clear output
				if ok:
					print '[!] Inside: {file}'.format(file=fm.file.path)
					print '[!] Line: {line}'.format(line=sub.line)
					for p in sub.paths:
						if self.is_writable(p, user):
							print '[+] Writable path: {file}'.format(file=p.path)
					print
					self.nothing_found = False

				# Check for wildcards
				if '*' in sub.line and check_wildcards:
					for p in sub.paths:
						shell_escape = self.interesting_bin.find_binary(p.basename)
						if shell_escape:

							# IMPROVEMENT: could be interesting to check if write permission on directory => to exploit wildcard, a file should be created.
							# Check from where the script has been called 
							name = p.path if not p.alias else p.alias
							
							# Check that the wildcard is added after the interesting binary
							if sub.line.index(name) < sub.line.index('*'):
								print '[!] Inside: {file}'.format(file=fm.file.path)
								print '[!] Wildcard found on line: {line}'.format(line=sub.line)
								print '[+] Interesting bin: {bin}'.format(bin=name)
								print '[!] Shell escape method: \n{cmd}'.format(cmd=shell_escape)
								print
								self.nothing_found = False
	

	def anaylyse_sudoers(self, sudoers_info, user): 
		
		# Get associated group for the current user
		current_groupname = self.users.groups.getgrgid(user.pw_gid).gr_name

		for sudoers in sudoers_info:
			
			need_password = True
			# NOPASSWD is present, no password will be required to execute the commands
			if 'NOPASSWD' in sudoers['directives']: 
				need_password = False

			# If the sudoers line affects the current user or his group
			if user.pw_name in sudoers['users'] or '%{group}'.format(group=current_groupname) in sudoers['users']: # TO DO => or if match group
				
				for cmd in sudoers['cmds']:
					ok = False 
					msg = ''

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
							msg = '[+] Write permission on {file}'.format(file=c.path)
						
						# Interesting binary found
						shell_escape = self.interesting_bin.find_binary(c.basename)
						if shell_escape:
							args = cmd.line.strip()[cmd.line.strip().index(c.basename) + len(c.basename):].strip()
							ok = True

							# Check if no args but *
							if not args.strip():
								pass # Exploitable (message is printed at the end)

							# Check for wildcards
							elif '*' in args:
								msg = '[!] Should be exploitable using wildcards\n'

							# Print to let the user find if it's still exploitable => but not sure (could be a false positive)
							else: 
								msg = '[!] Could be a false positive\n'
							
							msg += '[+] Interesting bin found: {bin}\n'.format(bin=c.basename)
							msg += '[?] Shell escape method: \n{cmd}'.format(cmd=shell_escape)

						if c.basename == 'su': 
							args = cmd.line.strip()[cmd.line.strip().index(c.basename) + len(c.basename):].strip()

							# Every users could impersonated or at least root
							if args.strip() == '*' or args.strip() == 'root': 
								ok = True
								msg = '[+] Impersonnation can be done on root user'

							else:
								u = self.get_user(user=args.strip())
								if u:
									print '[!] Impersonating user "{user}" using line: {line}'.format(user=args.strip(), line=cmd.line.strip())
									
									# Check all sensitive files for write access using the impersonated user
									self.anaylyse_files_permissions(self.sensitive_files, user=u, check_wildcards=False)

									# Check suid files for write access using the impersonated user
									self.anaylyse_suids(self.suid_files, user=u, only_write_access=True)

									# Realize same check on sudoers file using the impersonated user
									self.anaylyse_sudoers(sudoers_info, u)
								else: 
									ok = True # should be a false positive - however I prefer to prompt the command line to be sure
									msg = '[-] User not found: {user}'.format(user=args.strip())

					if ok: 
						print '[!] Sudoers line: {line}'.format(line=cmd.line.strip())
						if need_password:
							print '[-] Password required'
						else: 
							print '[+] No password required (NOPASSWD used)'
						print '{message}\n'.format(message=msg)
						self.nothing_found = False


	def anaylyse_suids(self, suids, user, only_write_access=False):

		for suid in suids: 
			
			if not only_write_access:
				# Print every suid file (because a manually check should be done on these binaries)
				print '[!] {suid}'.format(suid=suid.file.path)
			
			if self.is_writable(suid.file, user):
				print '[+] Writable suid file'
				self.nothing_found = False
			
			if not only_write_access:
				shell_escape = self.interesting_bin.find_binary(suid.file.basename)
				if shell_escape: 
					print '[+] Interesting bin: {bin}'.format(bin=suid.file.path)
					print '[!] Shell escape method: \n{cmd}'.format(cmd=shell_escape)
					self.nothing_found = False

	def anaylyse_docker(self, is_docker_installed):
		
		if is_docker_installed: 
			print '[+] Docker service found !'
			print '[!] Shell escape method: \n{cmd}'.format(cmd=self.interesting_bin.find_binary('docker'))

	def print_exploit_found(self, output): 
		self.nothing_found = False
		print output

	def anaylyse_result(self, module, result):

		if module == 'files_permissions': 
			# Store data to do tests later
			self.sensitive_files = result
			self.anaylyse_files_permissions(result, user=self.users.current) 	# user is a pwd objet
		elif module == 'sudoers_file':
			self.anaylyse_sudoers(result, user=self.users.current)
		elif module == 'suid_bin': 
			self.suid_files = result
			self.anaylyse_suids(result, user=self.users.current)
		elif module == 'docker':
			self.anaylyse_docker(result)
		elif module == 'exploit':
			self.print_exploit_found(result)

	def run(self):
		'''
		Analyse all results found on the Checks classes 
		'''
		if os.geteuid() == 0:
			print '[!] You are already root.'
			return

		for module, result in self.checks.run():
			
			print '\n################# {module} #################\n'.format(module=module.replace('_', ' ').capitalize())
			
			self.nothing_found = True
			self.anaylyse_result(module, result)
			if self.nothing_found: 
				print '[-] Nothing found !'


