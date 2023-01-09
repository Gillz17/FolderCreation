#Created by: Zach McGill
#9/2/2021
#Grabs all active users from AD and creates a folder
#and then gives them permission to that folder.

#Apply permissions to the folder
function applyPerm{
	param(
		[Parameter(Mandatory=$true)] [String] $folder,
		[Parameter(Mandatory=$true)] [String] $username
	)
	#Grant user permission to their folder
	$acl = Get-Acl $folderPath
	$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($username,
		"FullControl","ContainerInherit,ObjectInherit", "None", "Allow")
	$acl.SetAccessRule($AccessRule)
	$acl | Set-Acl -Path $folderPath
	Write-Host "`tGranted $username permission to their folder" -ForegroundColor Red
}

#Gets the active users from AD
$nycUser = Get-ADUser -Filter 'enabled -eq $true'  -SearchBase 'OU=NYC Users,DC=TEST,DC=COM' 
$adminUser = Get-ADUser -Filter 'enabled -eq $true' -SearchBase 'OU=NYC Admin Users, DC=TEST, DC=COM'
$sfoUser = Get-ADUser -Filter 'enabled -eq $true' -SearchBase 'OU=SFO Users,DC=TEST, DC=COM'

#Loops through the NYC Users
foreach($username in $nycUser){
	$folderPath = "C:\Documents\" + $username.SamAccountName
	#See if the folder already exists
	if(Test-Path $folderPath){
		Write-Host "The folder already exists, $folderPath" -ForegroundColor Green
		#Check that the permissions are applied correctly
		$checkPerm = (Get-Acl -Path $folderPath).Access | ?{$_.IdentityReference -match $username.SamAccountName} |
			Select IdentityReference, FileSystemRights
		if($checkPerm){
			Write-Host "`tThe correct permissions were already applied" -ForegroundColor Yellow
		}else{
			#Call apply permissions function to grant permissions again
			applyPerm $folderPath $username.SamAccountName
		}
	}else{
		#Create a new folder
		New-Item -ItemType Directory -Force -Path $folderPath
		#Apply permissions to the folder
		applyPerm $folderPath $username.SamAccountName	
	}
}	
#Loops through Admin Users
foreach($username in $adminUser){
	$folderPath = "C:\Documents\" + $username.SamAccountName
	#See if the folder already exists
	if(Test-Path $folderPath){
		Write-Host "The folder already exists" -ForegroundColor Red
		#Check that the permissions are applied correctly
		$checkPerm = (Get-Acl -Path $folderPath).Access | ?{$_.IdentityReference -match $username.SamAccountName} |
			Select IdentityReference, FileSystemRights
		if($checkPerm){
			Write-Host "The correct permissions were applied" -ForegroundColor Green
		}else{
			#Call apply permissions function to grant permissions again
			applyPerm $folderPath $username.SamAccountName
		}
	}else{
		#Create a new folder
		New-Item -ItemType Directory -Force -Path $folderPath
		#Apply permissions to the folder
		applyPerm $folderPath $username.SamAccountName	
	}
}
#Loops through SFO Users
foreach($username in $sfoUser){
	$folderPath = "C:\Documents\" + $username.SamAccountName
	#See if the folder already exists
	if(Test-Path $folderPath){
		Write-Host "The folder already exists" -ForegroundColor Red
		#Check that the permissions are applied correctly
		$checkPerm = (Get-Acl -Path $folderPath).Access | ?{$_.IdentityReference -match $username.SamAccountName} |
			Select IdentityReference, FileSystemRights
		if($checkPerm){
			Write-Host "The correct permissions were applied" -ForegroundColor Green
		}else{
			#Call apply permissions function to grant permissions again
			applyPerm $folderPath $username.SamAccountName
		}
	}else{
		#Create a new folder
		New-Item -ItemType Directory -Force -Path $folderPath
		#Apply permissions to the folder
		applyPerm $folderPath $username.SamAccountName	
	}
}	