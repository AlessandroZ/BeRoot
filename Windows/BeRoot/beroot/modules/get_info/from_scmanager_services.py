from beroot.modules.objects.service import Service
from beroot.modules.checks.path_manipulation_checks import get_path_info
import win32service
import re

class GetServices():

	# generate the list of services
	def get_services(self, services_loaded):
		scm = win32service.OpenSCManager(None,None,win32service.SC_MANAGER_ENUMERATE_SERVICE)
		svcs = win32service.EnumServicesStatus(scm)

		for svc in svcs:
			try:
				sh_query_config = win32service.OpenService(scm, svc[0], win32service.SERVICE_QUERY_CONFIG)
				service_info = win32service.QueryServiceConfig(sh_query_config)
				short_name = svc[0]
				full_path = service_info[3]
				sv = self.check_if_service_already_loaded(short_name, full_path, services_loaded)
				
				if sv:
					sv.permissions = self.get_service_permissions(sv)

				if not sv:
					sk = Service()
					sk.name = short_name
					sk.display_name = svc[1]
					sk.full_path = full_path
					sk.paths = get_path_info(full_path)
					sk.permissions = self.get_service_permissions(sv)
					services_loaded.append(sk)
			except:
				pass

		return services_loaded

	# check if the service has already been loaded from registry
	def check_if_service_already_loaded(self, name, full_path, services_loaded):
		for service in services_loaded:
			if service.full_path == full_path and service.name == name:
				return service
		return False

	# Check service permission of a service (if it can be started, stopped or modified)
	def get_service_permissions(self, s):
		hnd = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
		
		start = self.service_start(hnd, s)
		stop = self.service_stop(hnd, s)
		change_config = self.change_sercice_configuration(hnd, s)

		return {'start': start, 'stop': stop, 'change_config': change_config}

	# check if a service can be started
	def service_start(self, hnd, s):
		try: 
			svcH = win32service.OpenService(hnd, s.name, win32service.SERVICE_START)
			return True
		except:
			return False

	# check if a service can be stopped
	def service_stop(self, hnd, s):
		try: 
			svcH = win32service.OpenService(hnd, s.name, win32service.SERVICE_STOP)
			return True
		except:
			return False

	# check if the configuration of a service can be changed
	def change_sercice_configuration(self, hnd, s):
		try: 
			svcH = win32service.OpenService(hnd, s.name, win32service.SERVICE_CHANGE_CONFIG)
			return True
		except:
			return False

	
