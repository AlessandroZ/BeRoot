from beroot.modules.checks.path_manipulation_checks import isRootDirectoryWritable
import platform
import os

# Sysprep files could contain inresting data
def check_sysprep_files():
	results = []
	files = [
		"c:\sysprep\sysprep.xml",
		"c:\sysprep\sysprep.inf", 
		"c:\sysprep.inf", 
	]
	for path in files:
		if os.path.exists(path):
			results.append(path)	
	
	return  results	


# Unattend files could contain passwords
def check_unattended_files():
	results = []
	files = [
		"\Panther\Unattend.xml",
		"\Panther\Unattended.xml", 
		"\Panther\Unattend\Unattended.xml", 
		"\Panther\Unattend\Unattend.xml", 
		"\System32\Sysprep\unattend.xml", 
		"\System32\Sysprep\Panther\unattend.xml"
	]
	for file in files:
		path = '%s%s' % (os.path.expandvars('%windir%'), file)
		if os.path.exists(path):
			results.append(path)	
	
	return  results

# if the environment path contains writeable directory, a privilege escalation may be done using dll hijacking
def checks_writeable_directory_on_path_environment_variable():
	results = []
	for p in os.environ['PATH'].split(';'):
		# checks writeable path contained on the path environment
		if isRootDirectoryWritable(p):
			results.append(p)
	return results

# check well known Windows services vulnerable to dll hijacking
def check_well_known_dll_injections(service):
	results = []

	knows_dlls = [
		{ 'service': 'ikeext', 'associate_dll': 'wlbsctrl.dll'}, 
	]

	for s in service:
		for d in knows_dlls:
			if d['service'] in s.name.lower() and not os.path.exists(d['associate_dll']):
				results.append(
						{
							'Service': d['service'], 
							'Associated dll': d['associate_dll']
						}
					)	

	return results