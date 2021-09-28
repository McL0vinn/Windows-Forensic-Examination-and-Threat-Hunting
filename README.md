# Windows Forensic Examination and Threat Hunting

1) [Identifying Suspicious Processes](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#Identifying-Suspicious-Processes)
2) [Identifying Suspicious Network Activity](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#Identifying-Suspicious-Network-Activity)
3) [Identifying Suspicious Services](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#identifying-suspicious-services)
4) [Identifying Suspicious Registry ASEPs/Autostart Folders](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#identifying-suspicious-registry-asepsautostart-folders)
5) [Identifying Suspicious Account Activity](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#Identifying-Suspicious-Account-Activity)
6) [Identifying Suspicious Scheduled Tasks](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#identifying-suspicious-scheduled-tasks)
7) [Identifying Suspicious Log Entries](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#identifying-suspicious-log-entries)
8) [Identifying Suspicious SMB Activity](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#identifying-suspicious-smb-activity)
9) [Miscellaneous](https://github.com/McL0vinn/Windows-Forensic-Examination-and-Threat-Hunting/blob/main/README.md#miscellaneous)

Identifying Suspicious Processes
----------------------------------------------------------------------------

1) C:\> taskmgr.exe = invokes the Task Manager GUI.
2) C:\> tasklist = Displays a list of currently running processes on the local computer or on a remote computer.
3) C:\> tasklist /v = Displays verbose task information in the output. ( PID , memory usage status, User name)
4) C:\> tasklist /m = Lists all tasks with PID and DLL modules loaded that match the given pattern name. If the module name is not specified, this option displays all modules loaded by each task.
5) C:\> tasklist /fi = Specifies the types of processes to include in or exclude from the query.examples below
6) C:\> tasklist /v /fi "pid eq 555"
7) C:\> tasklist /m /fi "pid eq 555"
8) C:\> Tasklist /v | findstr Teams.exe
9) C:\> Tasklist /m | findstr Teams.exe

Wmic is even more powerful than Tasklist.

1) C:\> wmic process list brief = brief list of the currently running processes
2) C:\> wmic process list full = full list of the currently running processes
3) C:\> wmic process get Name,Commandline,Description,ProcessID,ParentProcessID = specify only which fields you want to grab
4) C:\> wmic process where processid=600 list full = full info of the process running with pid=600
5) C:\> wmic process where Name=Teams.exe get ProcessID,ParentProcessID = full list of the process running with Name=teams.exe but return only the Pid and Ppid values
6) C:\> wmic process where ProcessID=555

Watch out for:
1) Is this a new or unrecognized process? ( ideally you would want to cross reference your findings with a baseline image -if you have. It will make the whole task of identifying what stands out from "normal activity" easier)
2) Is the name of the Process random-looking ( e.g hJoIuG.exe or whatever)
3) Is it running from a non-standard path ( e.g C:\Temp , C:\Downloads , C:\Music etc)
4) Is the parent suspicious ( child process might be legit but parent process not)
5) Is the Parent-Child relationship suspicious? ( e.g lsass.exe spawning a cmd.exe or IEX spawning a Powershell.exe etc)
6) Is the process tied to suspicious activity? ( e.g a process communicating with well known malicious IP/URL/host/domain etc)
7) Encoded in Base64 ?
8) A process can be used for benign and malicious purposes at the same time. ( e.g PSEXEC ) 
9) Suspicious does not necessarily mean Malicious.


Identifying Suspicious Network Activity
-----------------------------------------

1) C:\> netstat -abno ( this is pretty much all you need)
2) C:\> netstat -abno -n 5 = Automatically refresh the output every 5 seconds.

-n = addresses and port numbers are expressed numerically and no attempt is made to determine names.
-a = Displays all active TCP connections and the TCP and UDP ports on which the computer is listening
-b = shows the EXE using that port and the DLLs that it has loaded to interact with that port.
-o = shows the owner ProcessID associated with the port

You can redirect the outpout into a .txt file if it helps you analyze the results better e.g netstat -abno > C:\Users\McL0vin\Desktop\netstat.txt

Watch out for:
1) Network activity that is abnormal for the associated Process  (e.g Notepad outbound/inbound connections to a Public IP etc)
2) Network activity that is abnormal for your environment/Business Unit/Organization ( e.g lots of traffic during weekends, late hours, holidays etc, long running HTTP/HTTPS sessions etc) ( 2 ways to spot this kind of activity- either have a baseline image of Business as usual activity or know VERY WELL your environment/org/BU)
3) Network activity from/to well known Malicious IPs/Domains/URLs/Hosts  ( leverage Threat Intel & OSINT to identify those IOCs e.g alienvault , abuseipdb , virustotal, hybrid-analysis)


Identifying Suspicious Services
----------------------------------

1) services.msc = spawns the services control panel GUI . shows various services and their Description, Status, Startup Type, Log on as. shows ALL services (running/not running)
2) net start = shows a list of ONLY running services.
3) sc query | more = vast amount of information for each service . can be chaotic.  ONLY running services
4) tasklist /svc = shows which services are running out of each process on your system  along with their PIDs. maps running processes to services ( maps services-to-processes)

Watch out for:
1) New services / Deleted services / Stopped Services (  ideally you would want to cross reference your findings with a baseline image -if you have. Otherwise talk with your Sys Admins. ) 
2) Path to Executable looks abnormal( run services.msc --> right click on a service --> Properties)


Identifying Suspicious Registry ASEPs/Autostart Folders
------------------------------------------------------

Windows has numerous registry and file locations that can be used to start software without a user taking a specific action.These locations are called Autostart Extensibility Points (ASEPs).

The majority of malware manipulates the same registry keys in order to establish persistence and survive a reboot.Those are:

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx

HKEY_CURENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnceEx


1) C:\> regedit = spawns the Registry Editor -GUI to manually browse through the registry hive/keys
2) C:\> reg query HKLM\Software\microsoft\windows\currentversion\run = displays the settings for the specified registry key
3) C:\> taskmgr.exe = Task Manager GUI. go to Startup tab

These registry keys are responsible for executing programs when a system boots up or when a user logs on (Easiest way to establish persistence.Usually attackers map their backdoors there in order to survive reboot)

Autostart folders associated with users.These programs are automatically invoked each time the given user logs on to the system and are sometimes altered by malware

1) C:\> dir \s \b "C:\Users\username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup = lists the contents of a user's autostart folder
2) C:\> start msconfig.exe = spawns a small GUI that displays Startup selection, Boot location/options , startup items
3) C:\> wmic startup list full = displays autostart programs.
4) Right click on Tray bar --> Task Manager --> Startup = displays a GUI with autostart programs and info such as Name, Publisher, Status.



Watch out for:

1)
2)
3)
4)


Identifying Suspicious Account Activity
--------------------------------------

1) c:\> lusrmgr.msc = spawns a GUI which can be used to check the users and groups defined on the machine
2) C:\> net user = displays a list of users
3) C:\> net localgroup administrators = shows who is in the group you specify ( in that case accounts in the administrators group)



Watch out for:

1)
2)
3)
4)


Identifying Suspicious Scheduled Tasks
------------------------------------

1) C:\> schtasks = shows scheduled tasks and details about them such as Folder, Task Name, Next Run Time and Status (can be chaotic depending on your environment . you can export it to a .txt file for easier reading or use | findstr if you know what you are looking for )
2) C:\> taskschd.msc = brings up the Task Scheduler GUI.lots of info such as triggers,actions,conditions etc. much easier to work with
3) PS C:\> Get-ScheduledTask = Powershell commands that lists scheduled taks on the system with info about Taskpath,Taskname,State.
4) PS C:\> Get-ScheduledTask -TaskName "THIS IS SPARTA" if you know the Taskname of the scheduled task you are looking for, use this

Watch out for:

1)Unusual scheduled tasks ( especially those that run as SYSTEM, as a user in administrators group or have a blank username)
2)Scheduled Tasks




Identifying Suspicious Log Entries
-------------------------------

1) Cl\>eventvwr.msc = spawns the GUI Event Viewer ( the most eye-friendly way lol)
2) C:\> wevtutil qe Security /f:text = inspect the Windows EveNt Logs category you specified(in this case Security) . can be chaotic, you can output the content by using > C:\xx\xx\something.txt if you want.
3) PS C:\> Get-EventLog -LogName Security | Format-List -Property * = the equivalent of the above command but in Powershell this time and with a cooler blue background ( lol)


Watch out for:

1) Any indication that event log service was stopped
2) Any indication that Windows File Integrity Checker ( Windows File Protection) was disabled
3) Large number of failed logons about a specific account following a successful logon for that account
4) Small number of failed logons across many accounts ( Password Spray Attack) ( usually between 1-3 password tries per account to avoid account lockout threshold)
5) Large number of failed logons for a specific account ( Brute Force Password Attack)


Identifying Suspicious SMB activity
----------------------------------

*When your machine is acting as a client and want to see the outbound SMB activity*

1) C:\> net use = displays the target machine and the share to which you are connected
2) C:\> net use \\192.168.1.1 /del = drops the SMB session
3) C:\>net use * /del = drops all outbound SMB sessions

*When your machine is acting as a server and want to see the inbound SMB activity*

1) C:\>net session = list the inbound sessions
2) C:\>net session \\192.168.1.1 /del = drops the inbound SMB session

Watch out for:

1)The ability to drop individual SMB sessions (either inbound or outbound) can be useful because this can temporarily stop an attacker from using the SMB session.
This way you can buy some time or interrupt a data exfiltration in progress.
2) Don't expose your TCP/UDP 135,136,137,138,139,445 ports to the internet. Shut them down or if there is a legit business purpose put them behind firewalls with ACLs enforcing access to authorized IPs only.
3)most of them time SMB traffic is between a client and a Server.if you see client-to-client smb activity or excessive server-to-server smb activity without a valid business purpose,then that should be investigated.





Regshot = snapshot tool for Windows.Allows you to record a snapshot of the registry and optionally file system at two points in time and then highlights the differences between the two.
Provides a high level summary of the changes,showing registry keys that were added/deleted/modified as wel as any files that were added/deleted/modified
Super easy to run in 5 steps
1) Start Regshot and configure the options.By default Regshot is not going to record file system.You can specifiy that if you want by checking the Scan dir box and stating the directory you are interested in ( C:\ for example)
2) Once you are done with the configuration of the tool and you got everything ready take the first snapshot
3) Run the malware
4) Use Regshot to take a second snapshot
5) Once finished , click on Compare and Regshot will give you back the results after a few minutes


TaskManager
DeepBlueCLI
Procmon / Process Monitor = shows file system,registry,network and process activity in real-time.Ideal for detonating malicious files/scripts in a sandbox and see live the changes on your system
Procexplorer / Process Explorer = gives in depth information about running processes
Strings = extracts and displays bot ASCII and 16-bit little endian Unicode strings
C:\> strings malfile.exe
TCPView = maps listening TCP/UDP port back to owning processes
SRUMdump
FTK Imager /Volexity / Volatility (Remember . Most volatile FIRST = RAM . then everything else follows)

Miscellaneous
---------------------------------------------------------------------

*Get hashes*
1) C:\> certutil -hashfile malfile.exe MD5 = Calculates the MD5 Hash of a file on Windows.
2) PS C:\> Get-FileHash -Algorithm MD5 malfile.exe - Calculates the MD5 hash of a file on Windows leveraging powershell.

*Detect alternate data streams*
1) C:\> DIR /r = look for alternate data streams.
2) PS :> Get-Item * -Stream * = look for alternate data streams with Powershell.
3) PS:> Get-ChildItem -recurse | ForEach { Get-Item $_.Filename -stream * } | Where stream -ne ':$DATA' = search all subdirectories for ADS.


*Collect Metadata*
1) Use exiftool for Windows.


Watch out for
1) Size.
2) Timestamps ( Access,Creation,Modification).
3) File type and File Type extension.It's pretty common for attackers to change the extension of their scripts into something trivial such as .bmp / .jpg etc in order to avoid detection.
4) File permissions.

*DeepBlueCLI*
DeepBlueCLI - a PowerShell Module for Threat Hunting via Windows Event Logs. It can work with the below Windows event logs:
Windows Security
Windows System
Windows Application
Windows PowerShell
Sysmon
More info below
https://github.com/sans-blue-team/DeepBlueCLI

