import ctypes

class OSVERSIONINFOEXW(ctypes.Structure):
	_fields_ = [('dwOSVersionInfoSize', ctypes.c_ulong),
				('dwMajorVersion', ctypes.c_ulong),
				('dwMinorVersion', ctypes.c_ulong),
				('dwBuildNumber', ctypes.c_ulong),
				('dwPlatformId', ctypes.c_ulong),
				('szCSDVersion', ctypes.c_wchar*128),
				('wServicePackMajor', ctypes.c_ushort),
				('wServicePackMinor', ctypes.c_ushort),
				('wSuiteMask', ctypes.c_ushort),
				('wProductType', ctypes.c_byte),
				('wReserved', ctypes.c_byte)]

class System():

	def get_os_version(self):
		os_version = OSVERSIONINFOEXW()
		os_version.dwOSVersionInfoSize = ctypes.sizeof(os_version)
		retcode = ctypes.windll.Ntdll.RtlGetVersion(ctypes.byref(os_version))
		if retcode != 0:
			return False

		return '%s.%s' % (str(os_version.dwMajorVersion.real), str(os_version.dwMinorVersion.real))
