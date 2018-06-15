from beroot.modules.objects.winstructures import *
import _winreg

# return the service with write access on his key
def registry_key_with_write_access(keys):
	results = []
	for sk in keys:
		if sk.is_key_writable and sk.is_key_writable not in results:
			if ('HKEY_LOCAL_MACHINE\\%s' % sk.is_key_writable) not in results:
				results.append('HKEY_LOCAL_MACHINE\\%s' % sk.is_key_writable)
	return results

# check if MSI files are always launched with SYSTEM privileges if AlwaysInstallElevated registry key is set
def check_msi_misconfiguration():
	try:
		hklm = OpenKey(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', 0, KEY_READ)
		hkcu = OpenKey(HKEY_CURRENT_USER, 'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', 0, KEY_READ)
		if int(QueryValueEx(hklm, 'AlwaysInstallElevated')[0]) != 0 and int(_winreg.QueryValueEx(hkcu, 'AlwaysInstallElevated')[0]) != 0:
			return True
	except:
		pass
	return False