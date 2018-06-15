from beroot.modules.objects.winstructures import *
import ctypes

# Check if a service can be created
def check_services_creation_with_openscmanager():
	isPossible = False
	try:
		# open the SCM with "SC_MANAGER_CREATE_SERVICE" rights 
		createServ = OpenSCManager(None, None, SC_MANAGER_CREATE_SERVICE)
		if ctypes.GetLastError() == 0:
			return True
	except: 
		pass
	
	return False

# returns all services that could be modified
def check_service_permissions(services):
	results = []
	for service in services:
		if 'change_config' in service.permissions:
			if service.permissions['change_config']:
				results.append(
					{
						'Name': str(service.name),
						'Display Name': str(service.display_name),
						'Permissions': 'change config: %s / start: %s / stop: %s' % (service.permissions['change_config'], service.permissions['start'], service.permissions['stop'])
					}
				)
	return results
		
