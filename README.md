# BeRoot

BeRoot(s) is a post exploitation tool to check common Windows misconfigurations to find a way to escalate our privilege. \
A compiled version is available [here](https://github.com/AlessandroZ/BeRoot/releases). 

It will be added to the [pupy](https://github.com/n1nj4sec/pupy/) project as a post exploitation module (so it will be executed in memory without touching the disk). 

Except one method, this tool is only used to detect and not to exploit. If something is found, [templates](https://github.com/AlessandroZ/BeRoot/tree/master/templates/) could be used to exploit it. To use it, just create a __test.bat__ file located next to the service / DLL used. It should execute it once called. Depending on the Redistributable Packages installed on the target host, these binaries may not work.  

Run it
----
```
|====================================================================|
|                                                                    |
|                    Windows Privilege Escalation                    |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


usage: beRoot.exe [-h] [-l] [-w] [-c CMD]

Windows Privilege Escalation

optional arguments:
  -h, --help         show this help message and exit
  -l, --list         list all softwares installed (not run by default)
  -w, --write        write output
  -c CMD, --cmd CMD  cmd to execute for the webclient check (default: whoami)
```

All detection methods are described on the following document. 


Path containing space without quotes
----

Consider the following file path: 
```
C:\Program Files\Some Test\binary.exe
```

If the path contains spaces and no quotes, Windows would try to locate and execute programs in the following order:
```
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\binary.exe
```

Following this example, if "_C:\\_" folder is writable, it would be possible to create a malicious executable binary called "_Program.exe_". If "_binary.exe_" run with high privilege, it could be a good way to escalate our privilege.

Note: BeRoot realized these checks on every service path, scheduled tasks and startup keys located in HKLM.

__How to exploit__: \
\
The vulnerable path runs as: 
* _a service_: create a malicious service (or compile the service template)
* _a classic executable_: Create your own executable. 

 Writable directory
----

Consider the following file path:
```
C:\Program Files\Some Test\binary.exe
```

If the root directory of "_binary.exe_" is writable (_"C:\Program Files\Some Test\"_) and run with high privilege, it could be used to elevate our privileges. 

__Note__: BeRoot realized these checks on every service path, scheduled tasks and startup keys located in HKLM.

__How to exploit__:
* The service is not running:
	* Replace the legitimate service by our own, restart it or check how it's triggered (at reboot, when another process is started, etc.).

* The service is running and could not be stopped:
	* Most exploitation will be like that, checks for dll hijacking and try to restart the service using previous technics.


Writable directory on %PATH%
----

This technic affects the following Windows version:
```
6.0 	=> 	Windows Vista / Windows Server 2008
6.1 	=> 	Windows 7 / Windows Server 2008 R2
6.2 	=> 	Windows 8 / Windows Server 2012
```

On a classic Windows installation, when DLLs are loaded by a binary, Windows would try to locate it using these following steps:
```
- Directory where the binary is located
- C:\Windows\System32
- C:\Windows\System
- C:\Windows\
- Current directory where the binary has been launched
- Directory present in %PATH% environment variable
```

If a directory on the __%PATH%__ variable is writable, it would be possible to realize DLL hijacking attacks. Then, the goal would be to find a service which loads a DLL not present on each of these path. This is the case of the default "__IKEEXT__" service which loads the inexistant "__wlbsctrl.dll__". 

__How to exploit__: Create a malicious DLL called "_wlbsctrl.dll_" (use the [DLL template](https://github.com/AlessandroZ/BeRoot/tree/master/templates/DLL_Hijacking)) and add it to the writable path listed on the %PATH% variable. Start the service "_IKEEXT_".
To start the IKEEXT service without high privilege, a technic describe on the french magazine MISC 90 explains the following method: 

Create a file as following: 
```
C:\Users\bob\Desktop>type test.txt
[IKEEXTPOC]
MEDIA=rastapi
Port=VPN2-0
Device=Wan Miniport (IKEv2)
DEVICE=vpn
PhoneNumber=127.0.0.1
```

Use the "_rasdial_" binary to start the IKEEXT service. Even if the connection failed, the service should have been started. 
```
C:\Users\bob\Desktop>rasdial IKEEXTPOC test test /PHONEBOOK:test.txt
```

MS16-075
----

For French user, I recommend the article written on the MISC 90 which explain in details how it works. 

This vulnerability has been corrected by Microsoft with MS16-075, however many servers are still vulnerable to this kind of attack. 
I have been inspired from the C++ POC available [here](https://github.com/secruul/SysExec)

Here are some explaination (not in details):

1. Start Webclient service (used to connect to some shares) using some magic tricks (using its UUID)
2. Start an HTTP server locally
3. Find a service which will be used to trigger a _SYSTEM NTLM hash_. 
4. Enable file tracing on this service modifying its registry key to point to our webserver (_\\\\127.0.0.1@port\\tracing_)
5. Start this service
6. Our HTTP Server start a negotiation to get the _SYSTEM NTLM hash_
7. Use of this hash with SMB to execute our custom payload ([SMBrelayx](https://github.com/CoreSecurity/impacket/blob/master/examples/smbrelayx.py) has been modify to realize this action)
8. Clean everything (stop the service, clean the regritry, etc.).


__How to exploit__: BeRoot realize this exploitation, change the "_-c_" option to execute custom command on the vulnerable host.
```
beRoot.exe -c "net user Zapata LaLuchaSigue /add"
beRoot.exe -c "net localgroup Administrators Zapata /add"
```

AlwaysInstallElevated registry key
----

__AlwaysInstallElevated__ is a setting that allows non-privileged users the ability to run Microsoft Windows Installer Package Files (_MSI_) with elevated (_SYSTEM_) permissions. To allow it, two registry entries have to be set to __1__:
```
HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

__How to exploit__: create a malicious msi binary and execute it. 

Unattended Install files
----

This file contains all the configuration settings that were set during the installation process, some of which can include the configuration of local accounts including Administrator accounts.
These files are available on these following path: 
```
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep\unattend.xml 
C:\Windows\System32\Sysprep\Panther\unattend.xml
```

__How to exploit__: open the unattend.xml file to check if passwords are present on it. 
Should looks like: 
```
<UserAccounts>
    <LocalAccounts>
        <LocalAccount>
            <Password>
                <Value>RmFrZVBhc3N3MHJk</Value>
                <PlainText>false</PlainText>
            </Password>
            <Description>Local Administrator</Description>
            <DisplayName>Administrator</DisplayName>
            <Group>Administrators</Group>
            <Name>Administrator</Name>
        </LocalAccount>
    </LocalAccounts>
</UserAccounts>
```

Other possible misconfigurations
----

Other tests are realized to check if it's possible to: 
* Modify an existing service
* Create a new service
* Modify a startup key (on HKLM)
* Modify directory where all scheduled tasks are stored: "_C:\Windows\system32\Tasks_"

Special thanks
----
* Good description of each checks: https://toshellandback.com/2015/11/24/ms-priv-esc/
* C++ POC: https://github.com/secruul/SysExec
* Impacket as always, awesome work: https://github.com/CoreSecurity/impacket/


----
| __Alessandro ZANNI__    |
| ------------- |
| __zanni.alessandro@gmail.com__  |
