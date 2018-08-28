# -*- coding: utf-8 -*-
from ctypes.wintypes import *
from ctypes import *

try:
    import _winreg as winreg
except ImportError:
    import winreg

from ..get_info.system_info import System

HKEY_LOCAL_MACHINE = -2147483646
HKEY_CURRENT_USER = -2147483647

KEY_READ = 131097
KEY_WRITE = 131078
KEY_ENUMERATE_SUB_KEYS = 8
KEY_QUERY_VALUE = 1

REG_EXPAND_SZ = 2
REG_DWORD = 4

LPCTSTR = LPSTR
LPDWORD = POINTER(DWORD)

SC_MANAGER_CONNECT = 1
SC_MANAGER_CREATE_SERVICE = 2
SC_MANAGER_ENUMERATE_SERVICE = 4

SERVICE_START_PENDING = 2
SERVICE_START = 16
SERVICE_STOP = 32
SERVICE_CONTROL_STOP = 1
SERVICE_RUNNING = 4
SERVICE_QUERY_STATUS = 4
SERVICE_CHANGE_CONFIG = 2
SERVICE_QUERY_CONFIG = 1

SERVICE_KERNEL_DRIVER = 1
SERVICE_FILE_SYSTEM_DRIVER = 2
SERVICE_ADAPTER = 4
SERVICE_RECOGNIZER_DRIVER = 8
SERVICE_WIN32_OWN_PROCESS = 16
SERVICE_WIN32_SHARE_PROCESS = 32
SERVICE_WIN32 = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS
SERVICE_INTERACTIVE_PROCESS = 256
SERVICE_DRIVER = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER
SERVICE_TYPE_ALL = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS

SERVICE_ACTIVE = 1
SERVICE_INACTIVE = 2
SERVICE_STATE_ALL = 3

ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MORE_DATA = 234


class SERVICE_STATUS(Structure):
    _fields_ = [
        ('dwServiceType', DWORD),
        ('dwCurrentState', DWORD),
        ('dwControlsAccepted', DWORD),
        ('dwWin32ExitCode', DWORD),
        ('dwServiceSpecificExitCode', DWORD),
        ('dwCheckPoint', DWORD),
        ('dwWaitHint', DWORD),
    ]
PSERVICE_STATUS = POINTER(SERVICE_STATUS)


class QUERY_SERVICE_CONFIG(Structure):
    _fields_ = [
        ('dwServiceType', DWORD),
        ('dwStartType', DWORD),
        ('dwErrorControl', DWORD),
        ('lpBinaryPathName', LPSTR),
        ('lpLoadOrderGroup', LPSTR),
        ('dwTagId', DWORD),
        ('lpDependencies', LPSTR),
        ('lpServiceStartName', LPSTR),
        ('lpDisplayName', LPSTR),
    ]
LPQUERY_SERVICE_CONFIG = POINTER(QUERY_SERVICE_CONFIG)


class ENUM_SERVICE_STATUSA(Structure):
    _fields_ = [
        ('lpServiceName', LPSTR),
        ('lpDisplayName', LPSTR),
        ('ServiceStatus', SERVICE_STATUS),
    ]
LPENUM_SERVICE_STATUSA = POINTER(ENUM_SERVICE_STATUSA)

class ServiceStatusEntry(object): 
    """ 
    Service status entry returned by L{EnumServicesStatus}. 
    """ 
    def __init__(self, raw): 
        """ 
        @type  raw: L{ENUM_SERVICE_STATUSA} or L{ENUM_SERVICE_STATUSW} 
        @param raw: Raw structure for this service status entry. 
        """ 
        self.ServiceName             = raw.lpServiceName 
        self.DisplayName             = raw.lpDisplayName 
        self.ServiceType             = raw.ServiceStatus.dwServiceType 
        self.CurrentState            = raw.ServiceStatus.dwCurrentState 
        self.ControlsAccepted        = raw.ServiceStatus.dwControlsAccepted 
        self.Win32ExitCode           = raw.ServiceStatus.dwWin32ExitCode 
        self.ServiceSpecificExitCode = raw.ServiceStatus.dwServiceSpecificExitCode 
        self.CheckPoint              = raw.ServiceStatus.dwCheckPoint 
        self.WaitHint                = raw.ServiceStatus.dwWaitHint 


advapi32 = windll.advapi32

OpenSCManager = advapi32.OpenSCManagerA
OpenSCManager.argtypes = [LPCTSTR, LPCTSTR, DWORD]
OpenSCManager.restype = HANDLE

OpenService = advapi32.OpenServiceA
OpenService.argtypes = [HANDLE, LPCTSTR, DWORD]
OpenService.restype = HANDLE

CloseServiceHandle = advapi32.CloseServiceHandle
CloseServiceHandle.argtypes = [HANDLE]
CloseServiceHandle.restype = BOOL

ControlService = advapi32.ControlService
ControlService.argtypes = [HANDLE, DWORD, PSERVICE_STATUS]
ControlService.restype = BOOL

StartService = advapi32.StartServiceA
StartService.argtypes = [HANDLE, DWORD, c_void_p]
StartService.restype = BOOL

GetServiceKeyName = advapi32.GetServiceKeyNameA
GetServiceKeyName.argtypes = [HANDLE, LPCTSTR, LPCTSTR, LPDWORD]
GetServiceKeyName.restype = BOOL

QueryServiceStatus = advapi32.QueryServiceStatus
QueryServiceStatus.argtypes = [HANDLE, PSERVICE_STATUS]
QueryServiceStatus.restype = BOOL

QueryServiceConfig = advapi32.QueryServiceConfigA
QueryServiceConfig.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD]
QueryServiceConfig.restype = BOOL

s = System()


def OpenKey(key, path, index, access):
    if s.isx64:
        return winreg.OpenKey(key, path, index, access | winreg.KEY_WOW64_64KEY)
    else:
        return winreg.OpenKey(key, path, index, access)


def EnumServicesStatus(hSCManager, dwServiceType=SERVICE_DRIVER | SERVICE_WIN32, dwServiceState=SERVICE_STATE_ALL): 
        _EnumServicesStatusA = advapi32.EnumServicesStatusA 
        _EnumServicesStatusA.argtypes = [SC_HANDLE, DWORD, DWORD, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD] 
        _EnumServicesStatusA.restype  = bool 

        cbBytesNeeded    = DWORD(0) 
        services_returned = DWORD(0) 
        ResumeHandle     = DWORD(0) 

        _EnumServicesStatusA(hSCManager, dwServiceType, dwServiceState, None, 0, byref(cbBytesNeeded), byref(services_returned), byref(ResumeHandle)) 

        Services = [] 
        success = False 
        while GetLastError() == ERROR_MORE_DATA: 
                if cbBytesNeeded.value < sizeof(ENUM_SERVICE_STATUSA): 
                        break 
                services_buffer = create_string_buffer("", cbBytesNeeded.value) 
                success = _EnumServicesStatusA(hSCManager, dwServiceType, dwServiceState, byref(services_buffer), sizeof(services_buffer), byref(cbBytesNeeded), byref(services_returned), byref(ResumeHandle)) 
                if sizeof(services_buffer) < (sizeof(ENUM_SERVICE_STATUSA) * services_returned.value): 
                        raise WinError() 
                lpServicesArray = cast(cast(pointer(services_buffer), c_void_p), LPENUM_SERVICE_STATUSA) 
                for index in range(0, services_returned.value):
                        Services.append(ServiceStatusEntry(lpServicesArray[index])) 
                if success: break 
        if not success: 
                raise WinError() 

        return Services 
