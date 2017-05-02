from beroot.modules.get_info.system_info import System
from ctypes.wintypes import *
from ctypes import *
import platform
import _winreg

HKEY_LOCAL_MACHINE 			= -2147483646
HKEY_CURRENT_USER 			= -2147483647

KEY_READ 					= 131097
KEY_WRITE 					= 131078
KEY_ENUMERATE_SUB_KEYS 		= 8
KEY_QUERY_VALUE 			= 1

REG_EXPAND_SZ 				= 2
REG_DWORD 					= 4
LPCTSTR 					= LPSTR
LPDWORD						= POINTER(DWORD)
SC_MANAGER_CONNECT 			= 1
SC_MANAGER_CREATE_SERVICE 	= 2
SERVICE_START_PENDING 		= 2
SERVICE_RUNNING 			= 4
SERVICE_STOP 				= 32
SERVICE_CONTROL_STOP 		= 1
SERVICE_START 				= 16
SERVICE_QUERY_STATUS 		= 4

class SERVICE_STATUS(Structure):
	_fields_ = [
		('dwServiceType', 				DWORD),
		('dwCurrentState', 				DWORD),
		('dwControlsAccepted', 			DWORD),
		('dwWin32ExitCode',				DWORD),
		('dwServiceSpecificExitCode', 	DWORD),
		('dwCheckPoint', 				DWORD),
		('dwWaitHint', 					DWORD),
	]
PSERVICE_STATUS = POINTER(SERVICE_STATUS)

OpenSCManager 				= windll.advapi32.OpenSCManagerA
OpenSCManager.argtypes 		= [LPCTSTR, LPCTSTR, DWORD]
OpenSCManager.restype  		= HANDLE

OpenService 				= windll.advapi32.OpenServiceA
OpenService.argtypes 		= [HANDLE, LPCTSTR, DWORD]
OpenService.restype  		= HANDLE

CloseServiceHandle 			= windll.advapi32.CloseServiceHandle
CloseServiceHandle.argtypes = [HANDLE]
CloseServiceHandle.restype  = BOOL

ControlService 				= windll.advapi32.ControlService
ControlService.argtypes 	= [HANDLE, DWORD, PSERVICE_STATUS]
ControlService.restype  	= BOOL

StartService 				= windll.advapi32.StartServiceA
StartService.argtypes 		= [HANDLE, DWORD, c_void_p]
StartService.restype  		= BOOL

GetServiceKeyName 			= windll.advapi32.GetServiceKeyNameA
GetServiceKeyName.argtypes 	= [HANDLE, LPCTSTR, LPCTSTR, LPDWORD]
GetServiceKeyName.restype  	= BOOL

QueryServiceStatus			= windll.advapi32.QueryServiceStatus
QueryServiceStatus.argtypes = [HANDLE, PSERVICE_STATUS]
QueryServiceStatus.restype  = BOOL


s = System()
def OpenKey(key, path, index, access):
	if s.isx64:
		return _winreg.OpenKey(key, path, index, access | _winreg.KEY_WOW64_64KEY)
	else:
		return _winreg.OpenKey(key, path, index, access)