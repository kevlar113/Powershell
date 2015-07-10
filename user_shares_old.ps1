# Create variable for the computer names
#$OldServer = $env:computername.Substring(0,3)
$OldServer = $env:computername + "-OLD"
$NewServer = $env:computername

# Create shares and assign permissions
$Names = get-WmiObject -class Win32_Share -computer $OldServer | Select-Object Name
$Paths = get-WmiObject -class Win32_Share -computer $OldServer | Select-Object Path
$i = 0
foreach ($Name in $Names -split('\r')){
	
	# Share path
	[string]$PathName = $Paths[$i]
	[string]$PathName = $PathName.substring(7)
	[string]$PathName = $PathName.trimend("}")
	[string]$PathName = $PathName.trimend(":")
	$PathName = $PathName
	
	# Share name
	[string]$ShareName = $Name
	[string]$ShareName = $ShareName.substring(7)
	[string]$ShareName = $ShareName.trimend("}")
	$ShareName = $ShareName
	
	# Setup share creation method
	$Shares=[WMICLASS]'WIN32_Share'
	
	$i++
	
	$trustee = ([wmiclass]'Win32_trustee').psbase.CreateInstance()
	$trustee.Domain = "NT Authority"
	$trustee.Name = "Authenticated Users"

	$ace = ([wmiclass]'Win32_ACE').psbase.CreateInstance()
	$ace.AccessMask = 1245631
	$ace.AceFlags = 3
	$ace.AceType = 0
	$ace.Trustee = $trustee

	$trustee2 = ([wmiclass]'Win32_trustee').psbase.CreateInstance()
	$trustee2.Domain = "."  #Or domain name
	$trustee2.Name = "Everyone"

	$ace2 = ([wmiclass]'Win32_ACE').psbase.CreateInstance()
	$ace2.AccessMask = 2032127
	$ace2.AceFlags = 3
	$ace2.AceType = 0
	$ace2.Trustee = $trustee2

	$sd = ([wmiclass]'Win32_SecurityDescriptor').psbase.CreateInstance()
	$sd.ControlFlags = 4
	$sd.DACL = $ace.psObject.baseobject, $ace2.psObject.baseobject
	$sd.group = $trustee2
	$sd.owner = $trustee2
		
	
	# Check for unnecessary shares and then create the share and assign the user and NTFS permissions
	#if (!(test-path "\\$NewServer\$ShareName") -and ($ShareName -ne $Null) -and ($PathName -ne $Null) -and ($PathName -ne "C:\") -and ($PathName -ne "E:\")`
	#	-and ($PathName -ne "F:\") -and ($PathName -ne "D:\") -and ($PathName -ne "C:\Windows") -and ($ShareName -ne "IPC$") -and ($PathName -ne "")`
	#	-and ($PathName -ne ":") -and !(test-path .) -and ($PathName -ne "Z:\String") -and ($PathName -ne "Z:\") -and ($PathName -ne "G:\")){
		
		if (($PathName -ne "") -and !(test-path $PathName) ){
			New-Item -type directory -Path $PathName
			}
		# Create the share and assign Everyone full control
		$Shares.create($PathName, $ShareName, 0, 100, "", "", $sd) | Out-Null
		
		# Assign the NTFS permissions
		$Acl = Get-Acl $PathName
		$Acl.SetAccessRuleProtection($True, $False)
		$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit, ObjectInherit', 'None', 'Allow')
		$Acl.AddAccessRule($rule)
		$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Domain Admins','FullControl','ContainerInherit, ObjectInherit', 'None', 'Allow')
		$Acl.AddAccessRule($rule)
		$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Network Security','FullControl','ContainerInherit, ObjectInherit', 'None', 'Allow')
		$Acl.AddAccessRule($rule)
		$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Network Analyst','FullControl','ContainerInherit, ObjectInherit', 'None', 'Allow')
		$Acl.AddAccessRule($rule)
		$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('scan-smb','Write','ContainerInherit, ObjectInherit', 'None', 'Allow')
		$Acl.AddAccessRule($rule)
		
		# Check that the user exists in active directory
		$UserCheck = [ADSISearcher]"(sAMAccountName=$ShareName)"
		$UserCheck = $UserCheck.FindOne()
		if (!($UserCheck -eq $Null)){
			write-host "$ShareName found in Active Directory, adding to $ShareName share." -ForegroundColor Green
			$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ShareName,'FullControl','ContainerInherit, ObjectInherit', 'None', 'Allow')
			$Acl.AddAccessRule($rule)
			}
			else {
			write-host "$ShareName not found in Active Directory!" -ForegroundColor Yellow
			}
		# Check for a department share and user exists in active directory
		$DeptName = $env:computername.substring(0,3) + $ShareName + "Dept"
		$DeptCheck = [ADSISearcher]"(sAMAccountName=$DeptName)"
		$DeptCheck = $DeptCheck.FindOne()
		if (!($DeptCheck -eq $Null)){
		write-host "$DeptName found in Active Directory, adding to $ShareName share." -ForegroundColor Green
			$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($DeptName,'FullControl','ContainerInherit, ObjectInherit', 'None', 'Allow')
			$Acl.AddAccessRule($rule)
			}
			else {
			write-host "$DeptName not found in Active Directory!" -ForegroundColor Yellow
			}
		Set-Acl $PathName $Acl | Out-Null
		write-host "New share $ShareName created at $PathName and granted user $ShareName full control."  -ForegroundColor Green
		#}
		#else {
		#	write-host "The $ShareName share already exists at $PathName!" -ForegroundColor Yellow
		#}
		#write-host $ShareName
		#write-host $PathName
		if ($PathName -eq "E:\Shares\Public"){
			write-host "Found $ShareName share, adding permissions for all users." -ForegroundColor Green
			cacls $PathName /e /t /g Users:f | Out-Null
		}
		elseif ($PathName -eq "E:\Shares\FTP"){
			write-host "Found $ShareName share, adding permissions for all users." -ForegroundColor Green
			cacls $PathName /e /t /g Users:f | Out-Null
			cacls $PathName /e /t /g ftpuser:f | Out-Null
		}
	}
