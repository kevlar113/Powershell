# Powershell modules
Import-Module ServerManager
Import-Module WebAdministration

# Global variables
$share = "\\mgmt00\share$"
$oldserver = $env:computername.Substring(0,3)
#$oldserver = "\\B1028DC"

# Install the required features for a branch server
Import-Module ServerManager | Out-Null
Add-WindowsFeature RDC | Out-Null
Add-WindowsFeature AS-NET-Framework | Out-Null
Add-WindowsFeature AS-Web-Support | Out-Null
Add-WindowsFeature NET-Framework-Core | Out-Null
Add-WindowsFeature NET-HTTP-Activation | Out-Null
Add-WindowsFeature FS-FileServer | Out-Null
Add-WindowsFeature Print-Server | Out-Null
Add-WindowsFeature FS-Resource-Manager | Out-Null
Add-WindowsFeature SNMP-Service | Out-Null
Add-WindowsFeature SNMP-wmi-provider | Out-Null
Add-WindowsFeature Telnet-Client | Out-Null
Add-WindowsFeature DHCP | Out-Null
Add-WindowsFeature RSAT-DHCP | Out-Null
Add-WindowsFeature RSAT-DNS-Server | Out-Null
Add-WindowsFeature RSAT-Print-Services | Out-Null
Add-WindowsFeature RSAT-FSRM-Mgmt | Out-Null
Add-WindowsFeature RSAT-AD-PowerShell | Out-Null
Add-WindowsFeature Web-Ftp-Service | Out-Null
Add-WindowsFeature Web-Static-Content | Out-Null
Add-WindowsFeature Web-Default-Doc | Out-Null
Add-WindowsFeature Web-Dir-Browsing | Out-Null
Add-WindowsFeature Web-Http-Errors | Out-Null
Add-WindowsFeature Web-Http-Redirect | Out-Null
Add-WindowsFeature Web-Asp-Net | Out-Null
Add-WindowsFeature Web-Net-Ext | Out-Null
Add-WindowsFeature Web-ISAPI-Ext | Out-Null
Add-WindowsFeature Web-ISAPI-Filter | Out-Null
Add-WindowsFeature Web-Http-Logging | Out-Null
Add-WindowsFeature Web-Log-Libraries | Out-Null
Add-WindowsFeature Web-Request-Monitor | Out-Null
Add-WindowsFeature Web-Http-Tracing | Out-Null
Add-WindowsFeature Web-Basic-Auth | Out-Null
Add-WindowsFeature Web-Windows-Auth | Out-Null
Add-WindowsFeature Web-Digest-Auth | Out-Null
Add-WindowsFeature Web-Client-Auth | Out-Null
Add-WindowsFeature Web-Cert-Auth | Out-Null
Add-WindowsFeature Web-Url-Auth | Out-Null
Add-WindowsFeature Web-Filtering | Out-Null
Add-WindowsFeature Web-IP-Security | Out-Null
Add-WindowsFeature Web-Stat-Compression | Out-Null
Add-WindowsFeature Web-Dyn-Compression | Out-Null
Add-WindowsFeature Web-Mgmt-Tools | Out-Null
Add-WindowsFeature Web-Mgmt-Console | Out-Null
Add-WindowsFeature Web-Scripting-Tools | Out-Null
Add-WindowsFeature Web-Mgmt-Service | Out-Null
Add-WindowsFeature WAS-Process-Model | Out-Null
Add-WindowsFeature WAS-NET-Environment | Out-Null
Add-WindowsFeature WAS-Config-APIs | Out-Null
Write-Host "Windows features have been installed." -ForegroundColor Green

# Add accounts for SCCM
net localgroup "administrators" "mhc_#10\SCCM1$" /add
net localgroup "administrators" "mhc_#10\SCCM2$" /add
net localgroup "administrators" "mhc_#10\SCCMDB$" /add

# Set power profile to Max
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# Turn off hibernation
powercfg -h off

# Turn off Windows firewall
netsh advfirewall set allprofiles state off

# Enable Remote Desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Disabled UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f

# Disabled IPv6
reg add "HKLM\SYSTEM\CurrentControlset\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xffffffff /f
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled

# Disable UNC check
reg add 'HKCU\Software\Microsoft\Command Processor' /v DisableUNCCheck /t REG_DWORD /d 1 /f

# Enable WinRM
winrm quickconfig -q

# Install 7zip
if (!(test-path -path "C:\Program Files\7-Zip")){
	msiexec.exe /i $share\software\7z920-x64.msi /q
	}

<# Configure partition layout
if (!(test-path -path E:\)){
	if (!(test-path -path F:\)){
		#diskpart /s $share\branch_diskpart.txt | Out-Null
		Write-Host "Partitions have been configured accordingly." -ForegroundColor Green
		}
	}

#>
# Get the volume label and drive letter for CDROM, C:, D:, E: and P: and change it to OS
(gwmi Win32_cdromdrive).drive | %{$a = mountvol $_ /l;mountvol $_ /d;$a = $a.Trim();mountvol Z: $a} | Out-Null

$DriveLabel = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'C:'"
Set-WmiInstance -input $DriveLabel -Arguments @{Label="OSDisk"} | Out-Null

$DriveLabel = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'D:'"
Set-WmiInstance -input $DriveLabel -Arguments @{Label="VSC"} | Out-Null
$DriveLabel | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null

$DriveLabel = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'E:'"
Set-WmiInstance -input $DriveLabel -Arguments @{Label="Data"} | Out-Null

Write-Host "CDROM drive has been changed to Z: and the drives labels have been updated." -ForegroundColor Green

# Set pagefile
$PageFileSizeMB = [Math]::Truncate(((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory + 200MB) / 1MB)
wmic computersystem set AutomaticManagedPagefile=false | Out-Null
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\" -name "pagingfiles" -type multistring -value "P:\pagefile.sys $PageFileSizeMB $PageFileSizeMB"  | Out-Null

# Disable Internet Explorer ESC for administrators
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 | Out-Null
Stop-Process -Name Explorer | Out-Null
Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

# Configure storage reports
$sreports = "E:\StorageReports"
if (!(test-path $sreports\Incident)){
	New-Item -ItemType Directory -Force -Path $sreports\Incident | Out-Null
	storrept admin defaults /incident:"$sreports\Incident"
	}
if (!(test-path $sreports\Scheduled)){
	New-Item -ItemType Directory -Force -Path $sreports\Scheduled | Out-Null
	storrept admin defaults /scheduled:"$sreports\Scheduled"
	}
if (!(test-path $sreports\Interactive)){
	New-Item -ItemType Directory -Force -Path $sreports\Interactive | Out-Null
	storrept admin defaults /ondemand:"$sreports\Interactive"
	}
Write-Host "Storage reports directories have been created." -ForegroundColor Green
<#
schtasks /create /sc weekly /d WED /tn fsrmreport /tr "storrept reports generate /scheduled /task:fsrmreport" /v1 /st 08:00 /ru system | Out-Null
storrept reports add /task:fsrmreport /scope:"c:\|e:\" /add-report:DuplicateFiles /format:"dhtml" /quiet
storrept reports modify /task:fsrmreport /add-report:FileScreenAudit
storrept reports modify /task:fsrmreport /add-report:FilesByFileGroup
storrept reports modify /task:fsrmreport /add-report:FilesByOwner
storrept reports modify /task:fsrmreport /add-report:LargeFiles
storrept reports modify /task:fsrmreport /add-report:LeastRecentlyAccessed
Write-Host "Storage reports have been created." -ForegroundColor Green
#>

# Set volume shadow copy service for E:\ on F:\
## Still needs to be manually enabled
vssadmin add shadowstorage /for=e: /on=d: /maxsize=80%
Write-Host "Volume Shadow Copies have been enabled for E:\ on F:\ but still needs to be manually enabled from the drive properties!" -ForegroundColor White

# Set DEP to Essential only
bcdedit /set nx OptIn | Out-Null
Write-Host "DEP settings have been changed." -ForegroundColor Green

# Configure the directory for the print spool
New-Item -ItemType Directory -Force -Path E:\Utilities\Spool | Out-Null
Set-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Control\Print\Printers -Name "DefaultSpoolDirectory" -value "E:\Utilities\Spool" | Out-Null
Write-Host "Print spooler location has been updated." -ForegroundColor Green

# Turn off local security policy for passwords
copy $share\turn_off_pass_complex.cfg c:\ | Out-Null
secedit /configure /db C:\Windows\security\new.sdb /cfg c:\turn_off_pass_complex.cfg /areas SECURITYPOLICY | Out-Null
del c:\turn_off_pass_complex.cfg | Out-Null
Write-Host "Local password complexity requirements have been modified." -ForegroundColor Green

# Setup Ftp-Service
net user ftpuser "ftpuser" /add
if (!(test-path -path E:\Shares\FTP)){
	New-Item -ItemType Directory -Force -Path E:\Shares\FTP | Out-Null
	}
if (!(test-path -path E:\Logs\FTP)){
	New-Item -ItemType Directory -Force -Path E:\Logs\FTP | Out-Null
	New-Item -ItemType Directory -Force -Path E:\Logs\IIS | Out-Null
	}

# Disabled IPv4 offloading and auto-tuning
netsh int tcp set global autotuninglevel=disabled | Out-Null
netsh int tcp set global chimney=disabled | Out-Null
Write-Host "IPv4 offloading and auto-tuning have been disabled." -ForegroundColor Green

# Rename network connections
cscript /b $share\rename_network.vbs
Write-Host "Primary NIC has been renamed to Production." -ForegroundColor Green

# Generate system information output on the C:\
systeminfo > c:\$env:computername.log

# Export a list of the printers installed on the old host
write-host "Exporting a list of the current printers from $oldserver." -ForegroundColor Green
Get-WMIObject -class Win32_Printer -computer $oldserver.Substring(2) | Select Name,DeviceID,PortName,Comment,Location,DriverName | Export-CSV -path 'E:\printers.csv'
$cmd = 'copy e:\printers.csv \\mgmt00\share$\printers\' + $oldserver.Substring(2) + '_printers.csv'
cmd /c $cmd | Out-Null
write-host "Exported a list of the current printers from the old host at $share\printers." -ForegroundColor Green

# Enumerate the shares from old server
write-host "Exporting a list of the current shares from $oldserver." -ForegroundColor Green
$cmd = $share + '\tools\srvcheck.exe ' + $oldserver + ' > E:\shares.txt'
cmd /c $cmd | Out-Null
$cmd = 'copy e:\shares.txt \\mgmt00\share$\shares\' + $oldserver.Substring(2) + '_shares.txt' 
cmd /c $cmd | Out-Null
write-host "Exported a list of the current shares from the old host at $share\shares." -ForegroundColor Green

$target = "E:\Shares\FTP"
$logs = "E:\Logs\FTP"
$appPoolName = "ftpapppool"
$ftpSiteTitle = "FTP"
$ftpUserName  = "ftpuser"
$ftpUserPassword  = "ftpuser"
 
if (!(Test-Path IIS:\Sites\$ftpSiteTitle)){
	# ftp site creation
	if (!(Test-Path IIS:\AppPools\$appPoolName)){
		Write-Host "...Creating AppPool: $appPoolName" -ForegroundColor Green
		New-Item IIS:\AppPools\$appPoolName -Verbose:$false -force | Out-Null
		}
	Write-Host "...Creating FTP Site: $ftpSiteTitle" -ForegroundColor Green
	 
	# Create the folder if it doesnt exist.
	if(!(Test-Path "$target")){
		New-Item $target -itemType directory
		}
	New-WebFtpSite -Name FTP -Port 21 -PhysicalPath E:\Shares\FTP -Force | Out-Null
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name applicationPool -Value $appPoolName   
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.security.ssl.controlChannelPolicy -Value 0
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.security.ssl.dataChannelPolicy -Value 0
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.logFile.directory -Value $logs
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.logFile.period -Value 1
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.logFile.enabled -Value $true  
	Set-ItemProperty IIS:\AppPools\$appPoolName managedRuntimeVersion v4.0  

	#Set the permissions...
	Add-WebConfiguration -Filter /System.FtpServer/Security/Authorization -Value (@{AccessType="Allow"; Users="$ftpUserName"; Permissions="Read, Write"}) -PSPath IIS: -Location "$ftpSiteTitle"
	Add-WebConfiguration -Filter /System.FtpServer/Security/Authorization -Value (@{AccessType="Allow"; Users="All Users"; Permissions="Read"}) -PSPath IIS: -Location "$ftpSiteTitle"
	Write-Host "FTP Site $ftpSiteTitle has been created" -ForegroundColor Green
	}
	else {
	Write-Host "FTP Site $ftpSiteTitle already exists" -ForegroundColor Yellow
	}
C:\Windows\System32\inetsrv\appcmd stop site /site.name:"Default Web Site" | Out-Null

# Configure end-user DHCP options and scope
$dhcpserver = $env:computername
$dhcpserver = "\\" + $dhcpserver
$dhcpname = $env:computername.Substring(1,2)
$dhcpname = "Branch " + $dhcpname + " - DHCP Scope"
$getip = Test-Connection -ComputerName $env:computername -Count 1
$ip = $getip.IPV4Address.IPAddressToString
$ip2 = $ip.Split('.')
$ip2[-1] = 0
$scope = $ip2 -join '.'
$ip2[-1] = 1
$gateway = $ip2 -join '.'
$ip2[-1] = 50
$scopestart = $ip2 -join '.'
$ip2[-1] = 150
$scopeend = $ip2 -join '.'
write-host "Configuring computer DHCP scope $scope with IPs ranging from $scopestart to $scopeend." -ForegroundColor Green
Set-Service DHCPServer -startuptype "automatic" | Out-Null
Start-Service DHCPServer | Out-Null
netsh dhcp server $dhcpserver add scope $scope 255.255.255.0 "$dhcpname" "$dhcpname" | Out-Null
netsh dhcp server $dhcpserver scope $scope add iprange $scopestart $scopeend | Out-Null
netsh dhcp server $dhcpserver scope $scope set state 0 | Out-Null
netsh dhcp server $dhcpserver add optiondef 060 PXEClient STRING 0 comment="Option added for PXE Support" | Out-Null
#netsh dhcp server $dhcpserver add optiondef 150 "Cisco TFTP" IPADDRESS 1 comment="Cisco TFTP (VOIP)" | Out-Null
netsh dhcp server $dhcpserver set optionvalue 060 STRING PXEClient | Out-Null
netsh dhcp server $dhcpserver set optionvalue 150 IPADDRESS $gateway 192.168.60.20 192.168.0.20 | Out-Null
netsh dhcp server $dhcpserver set optionvalue 003 IPADDRESS $gateway | Out-Null
netsh dhcp server $dhcpserver set optionvalue 006 IPADDRESS 172.17.100.11 172.17.60.11 | Out-Null
netsh dhcp server $dhcpserver set optionvalue 015 STRING mhc.trk | Out-Null
netsh dhcp server $dhcpserver set optionvalue 044 IPADDRESS 172.17.100.11 172.17.60.11 | Out-Null
netsh dhcp server $dhcpserver set optionvalue 046 BYTE 8 | Out-Null
write-host "Computer DHCP scope $scope has been created." -ForegroundColor Green

# Configure VOIP DHCP options and scope
$getip = Test-Connection -ComputerName $env:computername -Count 1
$ip = $getip.IPV4Address.IPAddressToString
$ip2 = $ip.Split('.')
$ip2[0] = 192
$ip2[1] = 168
$ip2[-1] = 0
$scope = $ip2 -join '.'
$ip2[-1] = 1
$gateway = $ip2 -join '.'
$ip2[-1] = 50
$scopestart = $ip2 -join '.'
$ip2[-1] = 150
$scopeend = $ip2 -join '.'
write-host "Configuring VOIP DHCP scope $scope with IPs ranging from $scopestart to $scopeend." -ForegroundColor Green
netsh dhcp server $dhcpserver add scope $scope 255.255.255.0 "$dhcpname" "$dhcpname" | Out-Null
netsh dhcp server $dhcpserver scope $scope add iprange $scopestart $scopeend | Out-Null
netsh dhcp server $dhcpserver scope $scope set state 0 | Out-Null
netsh dhcp server $dhcpserver scope $scope set optionvalue 150 IPADDRESS $gateway 192.168.60.20 192.168.0.20 | Out-Null
netsh dhcp server $dhcpserver scope $scope set optionvalue 003 IPADDRESS $gateway | Out-Null
write-host "VOIP DHCP scope $scope has been created." -ForegroundColor Green

if (test-path C:\Drv) { remove-item C:\Drv -recurse }
if (test-path C:\Drivers) { remove-item C:\Drivers -recurse }
if (test-path C:\Temp) { remove-item C:\Temp -recurse }
if (test-path C:\Sysprep) { remove-item C:\Sysprep -recurse }
