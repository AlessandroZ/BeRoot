from beroot.modules.checks.path_manipulation_checks import get_path_info
from beroot.modules.objects.service import Service
from beroot.modules.objects.registry import Registry_key
from beroot.modules.objects.winstructures import *
import _winreg
import os

class Registry():
			
	# --------------------------------------- StartUp Key functions ---------------------------------------
	
	def definePath(self):
		runkeys_hklm = [
			r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
			r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
			r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
			r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService",
			r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
		]
		return runkeys_hklm
	
	# read all startup key 
	def get_sensitive_registry_key(self):
		keys = []
		runkeys_hklm = self.definePath()
		
		# access either in read only mode, or in write mode
		accessRead = KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
		accessWrite = KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE

		# Loop through all keys to check
		for keyPath in runkeys_hklm:
			is_key_writable = False

			# check if the registry key has writable access
			try:
				hkey = OpenKey(HKEY_LOCAL_MACHINE, keyPath, 0, accessWrite)
				is_key_writable = keyPath
			except:
				try:
					hkey = OpenKey(HKEY_LOCAL_MACHINE, keyPath, 0, accessRead)
				except:
					continue

			# retrieve all value of the registry key
			try:
				num = _winreg.QueryInfoKey(hkey)[1]

				# loop through number of value in the key
				for x in range(0, num):
					k = _winreg.EnumValue(hkey, x)
					
					stk = Registry_key()
					if is_key_writable:
						stk.is_key_writable = is_key_writable

					stk.key = keyPath
					stk.name = k[0]
					stk.full_path = k[1]
					stk.paths = get_path_info(k[1])

					keys.append(stk)
				_winreg.CloseKey(hkey)
			except:
				pass

		return keys

	# --------------------------------------- Service Key functions ---------------------------------------
	
	# read all service information from registry
	def get_services_from_registry(self):
		service_keys = []

		# Open the Base on read only
		accessRead = KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
		accessWrite = KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE

		hkey = OpenKey(HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services', 0, accessRead)
		num = _winreg.QueryInfoKey(hkey)[0]
		
		# loop through all subkeys
		for x in range(0, num):
			sk = Service()
			
			# Name of the service
			svc = _winreg.EnumKey(hkey, x)
			sk.name = svc
			
			# ------ Check Write access of the key ------
			try:
					sk.key = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s" % svc
					skey = OpenKey(hkey, svc, 0, accessWrite)
					sk.is_key_writable = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s" % svc
			except:
				skey = OpenKey(hkey, svc, 0, accessRead)
				pass

			# ------ Check if the key has the Parameters\Application value presents ------
			try:
				# find display name
				display_name = str(_winreg.QueryValueEx(skey, 'DisplayName')[0])
				if display_name:
					sk.display_name = display_name
			except:
				# in case there is no key called DisplayName
				pass

			# ------ Check if the key has his executable with write access and the folder containing it as well ------
			try:
				skey = OpenKey(hkey, svc, 0, accessRead)

				# find ImagePath name
				image_path = str(_winreg.QueryValueEx(skey, 'ImagePath')[0])

				if image_path:
					image_path = os.path.expandvars(image_path)

					if 'drivers' not in image_path.lower():
						sk.full_path = image_path
						sk.paths = get_path_info(image_path)
			except:
				pass
			
			service_keys.append(sk)
		return service_keys
	