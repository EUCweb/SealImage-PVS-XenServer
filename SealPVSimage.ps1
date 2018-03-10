[CmdletBinding(SupportsShouldProcess = $true)]
PARAM(
		[parameter(Mandatory=$false)][string]$XSHost,
		[parameter(Mandatory=$True)][string]$VMName,
		[parameter(Mandatory=$True)][string]$PVSCollection,
		[parameter(Mandatory=$false)][string]$PVSDiskName,
        [parameter(Mandatory=$false)][string]$PVSDiskSize,
        [parameter(Mandatory=$false)][string]$PVSDiskRAMSize,
        [parameter(Mandatory=$True)][string]$PVSDiskStore
		
	)

clear-host
$script_path = $MyInvocation.MyCommand.Path
$script_dir = Split-Path -Parent $script_path

##### ---- Start custom specified entries ---- ####

#defines the Company that shown in the vDisk
$company = "company name"

#define the username, wich connect to your hypervisor (Xenserver currently supported only)
$host_username = "root"

#defines the file where you stored the maintenance VM's [format: Host,VM)
$ServerList = "$script_dir\Maintenance_Servers.txt"

#defines the PVS Server to connect 
$PVSServer = "Hostname PVS-Server"

#Sync script for vDisk, local path on the connected PVS Server
$SyncScript = "F:\Sync_vDisks\Sync_vDisks_v5.ps1"

#defines the PVS standard vDisk Size in MB (vdisk is dynamic VHDX), if not specified with the parameter from the calling script 
IF (!($PVSDiskSizee))
{
    $PVSDiskSize = "204800"
}

#defines the PVS standard vDisk RAM Size in MB (Cache in Device RAM with Overflow on Disk), if not specified with the parameter from the calling script 
IF (!($PVSDiskRAMSize))
{
    $PVSDiskRAMSize = "4096"
}

# E-mail report details
$emailFrom     = "SealMasterImage@NOREPLY.company.net"
$emailTo		= @("YourMailAddress")
$smtpServer    = "smtp.company.net"

##### ---- End custom specified entries ---- ####

$timestamp = Get-Date -Format yyyyMMdd-HHmmss
$computer = $Env:COMPUTERNAME
$cu = $env:username
$Global:SumData=@()
$LogFolder = "Logs"
$Global:LogFilePath = "$script_dir\$LogFolder\$VMName"
$Global:LogFileName = "SealPVSImage_$($computer)_$($VMName)_$timestamp.log"
$Global:LOGFile="$LogFilePath\$LogFileName"
$Global:Domain = (Get-WmiObject -Class Win32_ComputerSystem).domain
$Global:OutFile = "$script_dir\tmp\SealPVSImage_$($VMName).html"
$ModulePath = "$script_dir\module"
$Wait = "60"

[string]$credential_filepath = "$script_dir\PWD\credential_$cu.pwd"

#load Modules
    try {
        $Modules = @(Get-ChildItem -path $ModulePath -filter "*.psm1" -Force -Recurse)
        ForEach ($module in $Modules) {
            
            Write-Host " --- --- Importing Module $module PSM1--- --- " -ForegroundColor Green -BackgroundColor DarkGray
            Import-Module -Name "$ModulePath\$module" -Force
        }
    }
    catch {
        Throw "An error occured while loading modules. The error is: $_"
        Exit 1
    }

Set-LogFilePath -LFP $LogFilePath
Write-Log -Msg "Checking Prerequisites" -ShowConsole -Color Cyan
Write-Log -Msg "Logfile would be set to $LOGFile" -ShowConsole -Color DarkCyan -SubMsg
Invoke-LogRotate -Versions 5 -Directory $LogFilePath
Write-Log -Msg "Connect to your hypervisor with encrypted credentials in $credential_filepath" -ShowConsole -Color DarkCyan -SubMsg
 

# Check if the file exists; if not, create it (should be used once)
if ((Test-Path -Path $credential_filepath ) -eq $False) {
 (Get-Credential).Password | ConvertFrom-SecureString | Out-File $credential_filepath
}
 
# Read the password
$my_stored_password = cat $credential_filepath | ConvertTo-SecureString

# Add it back to a credential object
$cred = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $host_username, $my_stored_password



if ( (Get-PSSnapIn -Name "Citrix.PVS.SnapIn" -ErrorAction SilentlyContinue) -eq $Null ) 
{
	Write-Log -Msg "Load Citrix Provisioning Server Powershell SnapIn " -ShowConsole -Color DarkCyan -SubMsg
	Add-PSSnapin Citrix*
	
} ELSE {
	Write-Log -Msg "Citrix Provisioning Server Powershell SnapIn already loaded" -ShowConsole -Color DarkCyan -SubMsg
}


IF (Test-Path $Outfile -PathType Leaf)				
{
	Write-Log "HTML file $Outfile for e-Mail report already exist, deleting now !" -ShowConsole -SubMsg -Type W
    remove-item $Outfile -force | out-null
}
Write-Log "creating HTML file $Outfile for e-Mail report" -ShowConsole -Color DarkCyan -SubMsg
ConvertTo-Html -head $a -body "<H2> IT Automation - Citrix Sealing Process Overview for $VMName  </H2>" | Out-File $Outfile
Write-Log "Sync vDisk across PVS Servers is not available in this script, please sync your vDisks with your prefered method !" -ShowConsole -Type W -SubMsg -ToHTML

Write-Log -Msg "---------------------------------- Performing Actions for $VMName ----------------------------------" -ShowConsole -Color White
####### --- XenServer Operations
Write-Log -Msg "XenServer Operations" -ShowConsole -Color Green -ToHTML
$Listentry = Get-Content $ServerList
$detectVM = $false
ForEach ($entry in $Listentry)
{
	$splitentry = ($entry -split ",")
	$searchHost = $($splitentry[0])
	#$SearchVM = $($splitentry[1])  
    Write-Log -Msg "Connect to Server $($splitentry[0]) and searching for Maintenance VM $VMName" -ShowConsole -Color DarkGreen -SubMsg
	Connect-XenServer -Server $($splitentry[0]) -Creds $cred -SetDefaultSession -NoWarnCertificates -NoWarnNewCertificates
	$ListOfVM = @()
	$ListOfVM = Get-XenVM | ? {$_.is_a_snapshot -eq $false -and $_.is_a_template -eq $false -and $_.is_control_domain -eq $false } | % {$_.name_label}
	Write-Log -Msg "VMs on Host: $ListOfVM"
	$detectVM = $false
	ForEach ($VM in $ListOfVM)
	{
		IF ($VM -eq $VMName)
		{
			$detectVM = $true
			$XSHost = $splitentry[0]
            Write-Log -Msg "$VM is hosting on $XSHost" -ShowConsole -Color DarkGreen -SubMsg -ToHTML            
			break
		}
	}
	IF ($detectVM -eq $false) {
        Write-Log -Msg "VM $VMName not detected on Host $searchHost " -ShowConsole -type W -SubMsg
    } ELSE {
        break
    }
}

	


IF ($detectVM -eq $false)
{
   Write-Log -Msg "VM $VMName could not detected on any Host based on $ServerList " -Type E -ToHTML

}


Invoke-HTML

####### --- Power Operations
Write-Log -Msg "Power Operations" -ShowConsole -Color Green -ToHTML
$VMpowerstate = Get-XenVM | ? {$_.is_a_snapshot -eq $false -and $_.is_a_template -eq $false -and $_.is_control_domain -eq $false -and $_.name_label -eq $VMname} | % {$_.power_state}
Write-Log -Msg "$VMName is in current $VMpowerstate Power State" -ShowConsole -Color DarkGreen -SubMsg -ToHTML	
	
	IF ($VMpowerstate -ne "Halted")
	{
		$XenVM = Get-XenVM -Name $VMName
		Write-Log "Shutdown VM $VMName" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
		Invoke-XenVM -VM $XenVM -XenAction CleanShutdown -Async
        Write-Log -Msg "Waiting $Wait seconds to proceed" -ShowConsole -Color DarkGreen -SubMsg
        start-sleep $Wait
}


Invoke-HTML


####### --- Storage operations
Write-Log -Msg "Storage Operations" -ShowConsole -Color Green -ToHTML
Write-Log -Msg "Switch Device ID 0 -> 9" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Get-XenVM -Name $VMName | select -ExpandProperty VBDs | Get-XenVBD  | ? {$_.userdevice -eq '0'} | Set-XenVBD -Userdevice 9

Write-Log -Msg "Switch Device ID 1 -> 0" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Get-XenVM -Name $VMName | select -ExpandProperty VBDs | Get-XenVBD  | ? {$_.userdevice -eq '1'} | Set-XenVBD -Userdevice 0

Write-Log -Msg "Switch Device ID 9 -> 1" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Get-XenVM -Name $VMName | select -ExpandProperty VBDs | Get-XenVBD  | ? {$_.userdevice -eq '9'} | Set-XenVBD -Userdevice 1

$VMMacXS = Get-XenVM -Name $VMName | select -ExpandProperty VIFs | Get-XenVIF | % {$_.MAC}
$VMMacXS = $VMMacXS.ToUpper() -replace (":","-")
Write-Log "MAC Address on XenServer for $VMname is $VMMacXS" -ShowConsole -Color DarkGreen -SubMsg -ToHTML

Invoke-HTML

####### --- Optical Drive Operations
Write-Log -Msg "Optical Drive Operations" -ShowConsole -Color Green -ToHTML

#get datacenter D1 or D2 from XS Host
#$DCid = $XSHost.Substring(8,1)  # 09.05.2017 -  M .Schlimm: not possible to use the XSHost to get the right datacenter, sometimes the Vm could not boot and does not found the attached vdisk
$DCid = $PVSServer.Substring(9,1) # 09.05.2017 -  M. Schlimm: using connect PVS Server to get the DataCenter ID (e.g. TSW041PVS101  :  string 9, length 1)

$BootIsoName = "PVS-DHCP-D" + $DCid + ".iso"

$cdeject = Get-XenVM -Name $VMName | select -ExpandProperty VBDs | Get-XenVBD | where {$_.type -eq "CD"} | ? {$_.allowed_operations -contains 'eject'}
IF (!($cdeject -eq $null))
{
    Write-Log -Msg "CD Drive not empty, eject CD" -ShowConsole -Type W -SubMsg -ToHTML
    Get-XenVM -Name $VMName | select -ExpandProperty VBDs | Get-XenVBD | where {$_.type -eq "CD"} | Invoke-XenVBD -XenAction Eject

} ELSE {
    Write-Log -Msg "CD Drive is empty" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
}

Write-Log -Msg "Mount CD $BootIsoName (calculating from $PVSServer in Datacenter $DCid)" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Get-XenVM -Name $VMName | select -ExpandProperty VBDs | Get-XenVBD | where {$_.type -eq "CD"} | Invoke-XenVBD -XenAction Insert -VDI (Get-XenVDI -Name "$BootISOName" | select -ExpandProperty opaque_ref)

Invoke-HTML

####### --- PVS Operations
Write-Log -Msg "PVS Operations" -ShowConsole -Color Green -ToHTML
Write-Log -Msg "Connect to Provisioning Server $PVSServer" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Set-PVSConnection -Server $PVSServer
				
$PVSSiteName = Get-PvsSite | % {$_.SiteName}
$PVSStores = Get-PVSStore | % {$_.StoreName}
Write-Log "Get Informations from PVS Site $PVSSiteName" -ShowConsole -Color DarkGreen -SubMsg 
$TestPVSDevice=@()
try 
{
    $ErrorActionPreference = "Stop"
    $TestPVSDevice = Get-PvsDevice -DeviceName "$VMName"
}
catch 
{
    Write-Log -Msg "Device $VMName not exists" -ShowConsole -SubMsg -Type W -ToHTML
    Write-Log "Creating Device $VMname in PVS Collection $PVSCollection" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
    New-PvsDevice -Name $VMname -DeviceMac $VMMacXS -SiteName $PVSSiteName -CollectionName $PVSCollection -Description "$cu - PVS Maintenance Device, creating from powershell automation script ($timestamp)" -BootFrom 2 -Type 2 | Out-Null
}


 Finally 
{ 
    $ErrorActionPreference = "Continue" 
    $VMMacPVS = Get-PvsDevice -name $VMname | % {$_.DeviceMAC}
    Write-Log "MAC Address on PVS for $VMname is $VMMacPVS" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
    }




####### --- Existing PVS Device

####### --- Compare MAC-Addess from PVS and XenServer Host
Write-Log "Compare MAC-Address from PVS and XenServer Host" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
IF ($VMMacPVS -eq $VMMacXS)
{
    Write-Log "MAC-Address for $VMName on PVS $VMMacPVS is equal on XenServer $VMMacXS" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
} ELSE {
    Write-Log "MAC-Address for $VMName on PVS $VMMacPVS is NOT equal on XenServer $VMMacXS" -ShowConsole -SubMsg -Type W -ToHTML
    $PVSDeviceMAC = Get-PvsDevice -Name $VMName -Fields DeviceMac
    $PVSDeviceMAC.DeviceMac = $VMMacXS
    Set-PvsDevice $PVSDeviceMAC
    Write-Log "Change MAC-Address for $VMName on PVS to $VMMacXS" -ShowConsole -Type W -SubMsg -ToHTML
}



####### --- Set Boot from HardDisk
$PVSDeviceBootFromNbr = Get-PvsDevice -Name $VMName | % {$_.BootFrom}
$PVSDeviceBootFrom = convertToBootFrom($PVSDeviceBootFromNbr)
Write-Log "Device is booting up from $PVSDeviceBootFrom" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
IF ($PVSDeviceBootFrom -ne "Hard Disk")
{
    Write-Log "Change Device Boot Mode to Hard Disk" -ShowConsole -SubMsg -Type W -ToHTML
    $PVSDeviceBootMode = Get-PvsDevice -Name $VMName -Fields BootFrom
    $PVSDeviceBootMode.BootFrom = "2"
    Set-PvsDevice $PVSDeviceBootMode
} 

Invoke-HTML

####### --- Set Type Maintenance
$PVSDeviceTypeNbr = Get-PvsDevice -Name $VMName | % {$_.Type}
$PVSDeviceType = convertToDeviceType($PVSDeviceTypeNbr)
Write-Log "Device type is $PVSDeviceType" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
IF ($PVSDeviceType -ne "Maintenance")
{
    Write-Log "Change Device type to Maintenance" -ShowConsole -SubMsg -Type W -ToHTML
    $PVSDeviceType = Get-PvsDevice -Name $VMName -Fields type
    $PVSDeviceType.type = "2"
    Set-PvsDevice $PVSDeviceType
} 

Invoke-HTML

####### --- vDisk Operations
Write-Log -Msg "vDisk Operations" -ShowConsole -Color Green -ToHTML
$ListDisksInStore=Get-PvsDiskInfo -StoreName $PVSDiskStore -SiteName $PVSSiteName | % {$_.DiskLocatorName}
$NewDisk=$False
IF (!($PVSDiskName))
{
    $PVSDiskName = $VMName
    Write-Log "vDiskName not specified, using VMName $PVSDiskName " -ShowConsole -SubMsg -Type W -ToHTML
}

for ($i=1; $i -lt 100; $i++)
{
    $vDiskNbr = $i.ToString("0#")
    $vDiskName = $PVSDiskName + "-V" +$vDiskNbr
    ForEach ($vDisk in $ListDisksInStore)
    {
        IF ($vDisk -eq $vDiskName)
        {
                Write-Log "PVS Disk $vDiskName already exists in Store $PVSDiskStore" -ShowConsole -SubMsg -Type W -ToHTML
            $Nbr=$i + 1
            $NewDisk = $PVSDiskName + "-V" +$Nbr.ToString("0#")
        }
    }
}
IF ($NewDisk -eq $False) {$vDiskName = $PVSDiskName + "-V01"} ELSE {$vDiskName = $NewDisk}

Write-Log -Msg "Create vDisk $vDiskName, Size $PVSDiskSize in Store $PVSDiskStore" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Start-PvsCreateDisk -Name $vDiskName -Size $PVSDiskSize -StoreName $PVSDiskStore -SiteName $PVSSiteName -VHDX -Dynamic -Description "$cu - Base Disk on $VMName creating from powershell automation script ($timestamp)"
#Start-PvsCreateDisk -Name $vDiskName -Size $PVSDiskSize -StoreName $PVSDiskStore -SiteName $PVSSiteName -VHDX -Dynamic -ServerName $PVSServer -Description "Base Disk from installation on $VMName - $timestamp"

Write-Log -Msg "Set LoadBalancing on vDisk $vDiskName to BestEffort" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Set-PvsDiskLocator -DiskLocatorName $vDiskName -SiteName $PVSSiteName -StoreName $PVSDiskStore -SubnetAffinity 1

Write-Log -Msg "Set personal informations on vDisk $vDiskName" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Set-PvsDisk -Author $cu -Company $company -DiskLocatorName $vDiskName -SiteName $PVSSiteName -StoreName $PVSDiskStore 


$disklocator = Get-PvsDeviceInfo -DeviceName $VMName | % {$_.DiskLocatorName}
IF (!($disklocator))
{
    Write-Log -Msg "Device $VMName is free from any vDisk" -ShowConsole -Color DarkGreen -SubMsg -ToHTML

} ELSE {
    $DevicevDiskStore = $disklocator.split("\")[0]
    $DevicevDiskName = $disklocator.split("\")[1]
    Write-Log "Device $VMName has vDisk $DevicevDiskName from Store $DevicevDiskStore attached" -ShowConsole -SubMsg -Type W -ToHTML
    Write-Log -Msg "remove vDisk $DevicevDiskName from Device $VMName" -ShowConsole -SubMsg -Type W -ToHTML
    Remove-PvsDiskLocatorFromDevice -DeviceName $VMName -DiskLocatorName $DevicevDiskName -SiteName $PVSSiteName -StoreName $DevicevDiskStore
}

Write-Log -Msg "Add vDisk $vDiskName to Device $VMName" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Get-PvsDiskLocator -Name $vDiskName -SiteName $PVSSiteName -StoreName $PVSDiskStore -Fields Guid | Add-PvsDiskLocatorToDevice -DeviceName $VMName
Write-Log -Msg "Update PVS Inventory Table" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Update-PvsInventory

Invoke-HTML

####### --- Power Operations
Write-Log -Msg "Power Operations" -ShowConsole -Color Green -ToHTML
$VMpowerstate = Get-XenVM | ? {$_.is_a_snapshot -eq $false -and $_.is_a_template -eq $false -and $_.is_control_domain -eq $false -and $_.name_label -eq $VMname} | % {$_.power_state}
Write-Log "VM $VMname is in $VMpowerstate Power State" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
$startVM = Get-XenVM -Name $VMname
IF ($VMpowerstate -eq "Halted")
{
	Write-Log "Power on virtual machine $VMname" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
	Invoke-XenVM -VM $startVM -XenAction Start
	$TestVM = Test-VMConnectivity -VMName $($VMname) 
} ELSE {
	Write-Log "Restart virtual machine $VMname" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
	Invoke-XenVM -VM $startVM -XenAction CleanReboot
	$TestVM = Test-VMConnectivity -VMName $($VMname) 
}

Invoke-HTML

####### --- Sealing Operations

$MsgCommand = { Msg * "This VM is running sealing process. Please do nothing or check the logfile on Management Server who strating this job !!"}
Invoke-Command  -Computername $VMName -Scriptblock $MsgCommand

Write-Log -Msg "Sealing Operations" -ShowConsole -Color Green -ToHTML

Write-Log "Base Image Script Framework (BIS-F) Operations" -ShowConsole -Color DarkGreen -SubMsg -ToHTML

$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $VMName)
$RegKey= $Reg.OpenSubKey("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{A59AF8D7-4374-46DC-A0CD-8B9B50AFC32E}_is1")
$BISF_InstallLocation = $RegKey.GetValue("InstallLocation") 
$BISF_RemoteInstallLocation = $BISF_InstallLocation -replace (":","$")
Write-Log "BIS-F is installed in $BISF_InstallLocation on $VMName" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
              
$BIS_Start = "PrepareBaseImage_$($VMName).cmd"
$BIS_GlobalPath = "Framework\SubCall\Global"
$BISF_Module = "BISF.psd1"

$mainmodulename = import-module "\\$VMName\$($BISF_RemoteInstallLocation)$($BIS_GlobalPath)\$BISF_Module"
$ver= (Get-Module BISF).Version.ToString()
Remove-Module BISF
IF ($ver -ge "6.0.0") 
{
    Write-Log "BIS-F is Version $ver" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
} ELSE {
    Write-Log "BIS-F Verison is not supported !!" -ShowConsole -Type E -SubMsg -ToHTML

}

$regkey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $VMName) 
$ref = $regKey.OpenSubKey("SOFTWARE\Policies\Login Consultants\BISF");

if (!$ref) {Write-Log -Msg "BISF not configured with ADMX, fully automation cannot performed !" -SubMsg -Type E -ToHTML}
else {Write-Log "BIS-F is configured with ADMX" -ShowConsole -Color DarkGreen -SubMsg -ToHTML}


$RunPrepare = "$BISF_InstallLocation" + "Framework\PrepBISF_Start.ps1"
"Powershell.exe -command ""set-executionpolicy RemoteSigned"" >NUL" | Out-file $BIS_Start -Encoding ASCII
"Powershell.exe -file ""$RunPrepare" | Out-file $BIS_Start -append -Encoding ASCII
"del /F /Q ""%0""" | Out-file $BIS_Start -Append -Encoding ASCII
Copy-Item -Path ".\$BIS_Start" -Destination "\\$VMname\c$" -Force 
Remove-Item -Path ".\$BIS_Start" -Force

Write-Log "Starting BIS-F on remote Machine $VMName" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Invoke-WmiMethod -ComputerName $VMNAME -class win32_process -Name create -ArgumentList "cmd /c c:\$BIS_Start" | Out-null 
Start-Sleep 30
Show-ProgressBar -Computername $VMname -CheckProcess "powershell" -ActivityText "running Base Image Script Framework (BIS-F) on $VMname"
for ($i=0; $i -lt 10; $i++)
{
												
	$vDiskDeviceCount= Get-PVSDiskInfo -DiskLocatorName $vDiskName -SiteName $PVSSiteName -StoreName $PVSDiskStore | % {$_.Devicecount}
												 
	IF ($vDiskDeviceCount -eq "0") 
	{
		Write-Log "vDisk Version is free from any devices, devicecount is currently $vDiskDeviceCount" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
		$PromoteDisk = $true
		break
	} ELSE {
		Write-Log "Retry $i/10: Waiting if the vDisk Version is free from any devices, devicecount is currently $vDiskDeviceCount" -Type W -SubMsg -ToHTML
		Start-Sleep -Seconds 60
		$PromoteDisk = $false
												
	}
}

Invoke-HTML

####### --- vDisk Operations
Write-Log -Msg "vDisk Operations" -ShowConsole -Color Green -ToHTML
IF ($PromoteDisk -eq $true)
{
    Write-Log "Change vDisk $vDiskName Access Mode: Shared Image Mode " -ShowConsole -Color DarkGreen -SubMsg -ToHTML
    Write-Log "Change vDisk $vDiskName Cache Type: Cache in Device RAM with Overflow on Disk - RAM Size $PVSDiskRAMSize" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
    Set-PvsDisk -Author $cu -Company $company -DiskLocatorName $vDiskName -SiteName $PVSSiteName -StoreName $PVSDiskStore -WriteCacheSize $PVSDiskRAMSize -WriteCacheType 9


    Write-Log "Sync vDisk across PVS Servers is not available in this script, please sync your vDisks with your prefered method !" -ShowConsole -Type W -SubMsg -ToHTML

    <#
    ForEach ($AllPVSServer in $AllPVSServers)
    {
        IF ($AllPVSServer -ne $PVSServer)
        {
            Write-Log "Processing PVS Server $AllPVSServer" -ShowConsole -Color DarkGreen -SubMsg
            ## copy vhdx and pvp
            
            
            $PVSDiskSrc = "$PVSLocalStore\$vDiskName.vhdx" 
            $PVSDiskDest = "\\$AllPVSServer\$PVSRemoteStore"
            
            


        } ELSE {
            Write-Log "Skip connected PVS Server $AllPVSServer" -ShowConsole -Type W -SubMsg

        }

    }
    #>

} ELSE {
    Write-Log "vDisk $vDiskName cannot changed to shared image mode, because it's not free from any devices ! Check previous actions if it run without any issues !" -ShowConsole -Type W -SubMsg -ToHTML
}

Invoke-HTML

####### --- Set Boot from vDisk
$PVSDeviceBootFromNbr = Get-PvsDevice -Name $VMName | % {$_.BootFrom}
$PVSDeviceBootFrom = convertToBootFrom($PVSDeviceBootFromNbr)
Write-Log "Device is booting up from $PVSDeviceBootFrom" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
IF ($PVSDeviceBootFrom -ne "vDisk")
{
    Write-Log "Change Device Boot Mode to vDisk" -ShowConsole -SubMsg -Type W -ToHTML
    $PVSDeviceBootMode = Get-PvsDevice -Name $VMName -Fields BootFrom
    $PVSDeviceBootMode.BootFrom = "1"
    Set-PvsDevice $PVSDeviceBootMode
} 

Write-Log "Reset Machine Account Password for VM $VMName" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
Reset-PvsDeviceForDomain -devicename $VMName

Invoke-HTML

####### --- Power Operations
Write-Log -Msg "Power Operations" -ShowConsole -Color Green -ToHTML
$VMpowerstate = Get-XenVM | ? {$_.is_a_snapshot -eq $false -and $_.is_a_template -eq $false -and $_.is_control_domain -eq $false -and $_.name_label -eq $VMname} | % {$_.power_state}
Write-Log "VM $VMname is in $VMpowerstate Power State" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
$startVM = Get-XenVM -Name $VMname
IF ($VMpowerstate -eq "Halted")
{
	Write-Log "Power on virtual machine $VMname to" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
	Invoke-XenVM -VM $startVM -XenAction Start
	$TestVM = Test-VMConnectivity -VMName $($VMname) 
} ELSE {
	Write-Log "Restart virtual machine $VMname" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
	Invoke-XenVM -VM $startVM -XenAction CleanReboot
	$TestVM = Test-VMConnectivity -VMName $($VMname) 
}

IF ($TestVM -eq $true)
{
    Write-Log "$VMName is sucessfull booted from vDisk in shared mode.." -ShowConsole -Color DarkGreen -SubMsg -ToHTML
    $VMpowerstate = Get-XenVM | ? {$_.is_a_snapshot -eq $false -and $_.is_a_template -eq $false -and $_.is_control_domain -eq $false -and $_.name_label -eq $VMname} | % {$_.power_state}
    Write-Log -Msg "$VMName is in current $VMpowerstate Power State" -ShowConsole -Color DarkGreen -SubMsg -ToHTML	 
	
	IF ($VMpowerstate -ne "Halted")
	{
		$XenVM = Get-XenVM -Name $VMName
		Write-Log "Shutdown VM $VMName" -ShowConsole -Color DarkGreen -SubMsg -ToHTML
		Invoke-XenVM -VM $XenVM -XenAction CleanShutdown -Async
        Write-Log -Msg "Waiting $Wait seconds to proceed" -ShowConsole -Color DarkGreen -SubMsg
        start-sleep $Wait
        Write-Log -Msg "Sucessfull build the vDisk $vDiskName ... all tests passed..." -ShowConsole -Color Green -ToHTML  
    } 


} ELSE {
     Write-Log "$VMName could not booting up from previous created vDisk, please check it manualy" -ShowConsole -Type W -SubMsg -ToHTML
}

Invoke-HTML

ConvertTo-Html -head $a -body "<br> Script: $script_path | Computer: $computer | User: $cu | Date / Time: $(Get-Date) </br>" | Out-File $outfile -append


$sendEmail = $true
$emailSubject  = ("$PVSSiteName - Citrix Image Sealing Report for $VMName " + (Get-Date -format R))

IF ($sendEmail -eq $true)
{
    $mailMessageParameters = @{
	    From       = $emailFrom
	    To         = $emailTo
	    Subject    = $emailSubject
	    SmtpServer = $smtpServer
	    Body       = (gc $outfile) | Out-String
	    Attachment = $logfile
    }
    Write-Log -Msg "E-Mail would be send now to the following recipients: $emailTo" -ShowConsole -Color DarkCyan -SubMsg
    Send-MailMessage @mailMessageParameters -BodyAsHtml
} ELSE {
    Write-Log -Msg "No E-Mail would be send" -ShowConsole -Color DarkCyan -SubMsg
}


Write-Log -Msg "---------------------------------- Finalize Actions for $VMName ----------------------------------" -ShowConsole -Color White

####### --- Cleanup Operations
Write-Log -Msg "Cleanup Operations" -ShowConsole -Color Cyan
remove-item $Outfile -force | out-null

Write-Log "Remove Citrix Provisioning Server Powershell SnapIn" -ShowConsole -Color DarkCyan -SubMsg
Remove-PSSnapin Citrix*
add-FinishLine
Remove-Module Module
#Remove-Module XenServerPSModule