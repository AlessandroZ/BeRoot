# -*- coding: utf-8 -*-
import win32service # should be removed => TO DO!
import ctypes

from ..checks.path_manipulation_checks import get_path_info
from ..objects.service import Service
from ..objects.winstructures import SERVICE_START, SERVICE_STOP, SERVICE_CHANGE_CONFIG, SERVICE_QUERY_CONFIG, \
    SERVICE_WIN32, SERVICE_DRIVER, SERVICE_STATE_ALL, \
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, QUERY_SERVICE_CONFIG, ENUM_SERVICE_STATUS, \
    OpenService, OpenSCManager, QueryServiceConfig, EnumServicesStatus


class GetServices(object):

    def get_services(self, services_loaded):
        """
        Generate the list of services
        """
        scm = OpenSCManager(None, None, SC_MANAGER_ENUMERATE_SERVICE)
        svcs = win32service.EnumServicesStatus(scm)

        # bytes_needed = ctypes.c_size_t(0)
        # serv_returned = ctypes.c_size_t(0)
        # res_handle = ctypes.c_size_t(0)
        # pServices = ctypes.POINTER(ENUM_SERVICE_STATUS)
        # dw_bytes = ctypes.sizeof(ENUM_SERVICE_STATUS)
        #
        # ret = EnumServicesStatus(
        #     scm,
        #     SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
        #     pServices,
        #     dw_bytes,
        #     ctypes.byref(bytes_needed),
        #     ctypes.byref(serv_returned),
        #     ctypes.byref(res_handle)
        # )
        # if not ret:
        #     return False

        for svc in svcs:
            try:
                short_name = svc[0]

                hservice = OpenService(scm, svc[0], SERVICE_QUERY_CONFIG)
                if not hservice:
                    continue

                # sc = QUERY_SERVICE_CONFIG()
                # bytes_needed = ctypes.c_size_t(0)
                # ret = QueryServiceConfig(hservice, ctypes.byref(sc), ctypes.sizeof(sc), ctypes.byref(bytes_needed))
                # if not ret:
                #     continue
                #
                # full_path = sc.lpBinaryPathName

                sh_query_config = OpenService(scm, svc[0], SERVICE_QUERY_CONFIG)
                service_info = win32service.QueryServiceConfig(sh_query_config)
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
            except Exception:
                pass

        return services_loaded

    def check_if_service_already_loaded(self, name, full_path, services_loaded):
        """
        Check if the service has already been loaded from registry
        """
        for service in services_loaded:
            if service.full_path == full_path and service.name == name:
                return service
        return False

    def get_service_permissions(self, s):
        """
        Check service permission of a service (if it can be started, stopped or modified)
        """
        hnd = OpenSCManager(None, None, SC_MANAGER_CONNECT)

        start = self.service_start(hnd, s)
        stop = self.service_stop(hnd, s)
        change_config = self.change_sercice_configuration(hnd, s)

        return {'start': start, 'stop': stop, 'change_config': change_config}

    def service_start(self, hnd, s):
        """
        Check if a service can be started
        """
        try:
            sv = OpenService(hnd, s.name, SERVICE_START)
            return True
        except Exception:
            return False

    def service_stop(self, hnd, s):
        """
        Check if a service can be stopped
        """
        try:
            sv = OpenService(hnd, s.name, SERVICE_STOP)
            return True
        except Exception:
            return False

    def change_sercice_configuration(self, hnd, s):
        """
        Check if the configuration of a service can be changed
        """
        try:
            sv = OpenService(hnd, s.name, SERVICE_CHANGE_CONFIG)
            return True
        except Exception:
            return False
