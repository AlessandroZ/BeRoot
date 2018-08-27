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
PQUERY_SERVICE_CONFIG = POINTER(QUERY_SERVICE_CONFIG)


class ENUM_SERVICE_STATUS(Structure):
    _fields_ = [
        ('lpServiceName', LPSTR),
        ('lpDisplayName', LPSTR),
        ('ServiceStatus', SERVICE_STATUS),
    ]
PENUM_SERVICE_STATUS = POINTER(ENUM_SERVICE_STATUS)


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
QueryServiceConfig.argtypes = [HANDLE, PQUERY_SERVICE_CONFIG, DWORD, LPDWORD]
QueryServiceConfig.restype = BOOL

EnumServicesStatus = advapi32.EnumServicesStatusA
EnumServicesStatus.argtypes = [HANDLE, DWORD, DWORD, PENUM_SERVICE_STATUS, DWORD, LPDWORD, LPDWORD, LPDWORD]
EnumServicesStatus.restype = BOOL

s = System()


def OpenKey(key, path, index, access):
    if s.isx64:
        return winreg.OpenKey(key, path, index, access | winreg.KEY_WOW64_64KEY)
    else:
        return winreg.OpenKey(key, path, index, access)
