# Script Name: TriggerEvent.ps1
# Usage Example (use a valid ID found via Event Viewer XML view of an event): powershell .\TriggerEvent.ps1 -eventRecordID 1 -eventChannel Application
#
# Create a fake event or testing with the following command (from an elevated command prompt):
#   eventcreate /T INFORMATION /SO BuildMasterImage /ID 1000 /L APPLICATION /D “<Params><VMName>MasterImageComputerName</VMName><PVSCollection>XA7_Maintenance</PVSCollection><PVSDiskStore>XenApp 76</PVSDiskStore><PVSDiskName>vDisk-XA7-STD</PVSDiskName></Params>”

# Collects all named paramters (all others end up in $Args)
param($eventRecordID,$eventChannel)
$ScriptPath = Split-Path $MyInvocation.InvocationName
$timestamp = Get-Date -Format yyyyMMdd-HHmm
$args = @()
$event = get-winevent -LogName $eventChannel -FilterXPath "<QueryList><Query Id='1000' Path='$eventChannel'><Select Path='$eventChannel'>*[System[(EventRecordID=$eventRecordID)]]</Select></Query></QueryList>"

[xml]$eventParams = $event.Message
if ($eventParams.Params.VMName) {
    $eventVMName = $eventParams.Params.VMName
    $args="-VMName ""$eventVMName"""
	
	IF ($eventParams.Params.PVSCollection) {
		$eventPVSCollection = $eventParams.Params.PVSCollection
		$args = $args +" -PVSCollection ""$eventPVSCollection"""
	}
	
	IF ($eventParams.Params.PVSDiskStore) {
		$eventPVSDiskStore = $eventParams.Params.PVSDiskStore
		$args = $args +" -PVSDiskStore ""$eventPVSDiskStore"""
	}
	
	IF ($eventParams.Params.PVSDiskName) {
		$eventPVSDiskName = $eventParams.Params.PVSDiskName
		$args = $args +" -PVSDiskName ""$eventPVSDiskName"""
	}
    
	IF ($eventParams.Params.PVSDiskRAMSize) {
		$eventPVSDiskRAMSize = $eventParams.Params.PVSDiskRAMSize
		$args = $args +" -PVSDiskRAMSize ""$eventPVSDiskRAMSize"""
	}
	
	IF ($eventParams.Params.PVSDiskSize) {
		$eventPVSDiskSize = $eventParams.Params.PVSDiskSize
		$args = $args +" -PVSDiskSize ""$eventPVSDiskSize"""
	}
	
    $File= "E:\SCRIPTS\SealImage\Logs\TriggerEvent_$eventVMName.log"
    "$timestamp - Sealing Image from eventRecordID: $eventRecordID, EventChannel: $eventChannel, Arguments: $args" | Out-File $File -append
	Invoke-Expression "$ScriptPath\SealPVSimage.ps1 $args"
} ELSE {

	$File= "E:\SCRIPTS\SealImage\Logs\TriggerEvent.log"
	"$timestamp - ERROR - Sealing Image from eventRecordID: $eventRecordID, EventChannel: $eventChannel, VMName: $eventVMName not specified !!" | Out-File $File -append
    
}