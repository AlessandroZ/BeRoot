from beroot.modules.objects.software import Software
from beroot.modules.objects.winstructures import *
import _winreg
import re

# Manage all softwares
class Softwares():

	def __init__(self):
		self.list_softwares = self.retrieve_softwares()

	# retrieve all softwares installed on the computer
	def retrieve_softwares(self): 
		results = []

		# Open the Base on read only
		accessRead = KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE

		# check the uninstall key path 
		hkey = _winreg.OpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\\", 0, accessRead)
		num = _winreg.QueryInfoKey(hkey)[0]
		
		# loop through number of subkeys
		for x in range(0, num):
			
			# Name of the software key
			sk = _winreg.EnumKey(hkey, x)
			
			# ------ Check if the key has his executable with write access and the folder containing it as well ------
			try:
				skey = _winreg.OpenKey(hkey, sk, 0, accessRead)
				
				name = str(_winreg.QueryValueEx(skey, "DisplayName")[0])
				if name:
					# regex to not match security patch (KB)
					m = re.match(r".*KB[0-9]{5,7}.*", name, re.IGNORECASE)
					if not m:
						soft = Software()
						soft.name = name
						soft.version = str(_winreg.QueryValueEx(skey, "DisplayVersion")[0])
						soft.key = skey
						results.append(soft)
			except:
				pass
		
		return results
	
	# retrieve the antivirus used 
	def get_av_software(self):
	
		av_list = [
			"Avast",
			"Avira",
			"AVG",
			"avwinsfx",
			"Bit Defender",
			"CAe Trust",
			"Esafe Desktop",
			"Eset",
			"F-secure",
			"G-data",
			"kaspersky",
			"Mcafee",
			"Microsoft Security Essentials", 
			"Nod32",
			"Norton",
			"Panda",
			"Paretologic",
			"Protector Plus",
			"quickhealregfile",
			"Quick Heal",
			"Smart AV",
			"Trend Micro",
			"Vipre",
			"Webroot",
			"ZonAlarm"
		]
		
		results = []
		for i in self.list_softwares:
			for av in av_list: 
				m = re.match(r".*" + av + ".*", i.name, re.IGNORECASE)
				if m:
					antivirus_info = '%s %s ' % (i.name, i.version)
					if antivirus_info not in results:
						results.append(antivirus_info)

		if not results:
			results.append('Antivirus not found')

		return results