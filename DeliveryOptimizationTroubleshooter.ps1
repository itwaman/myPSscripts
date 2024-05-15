
<#PSScriptInfo

.VERSION 1.1.0

.GUID 9516d007-5e02-4bfd-84a4-436ea6778687

.AUTHOR carmenf

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<#
.DESCRIPTION 
 Troubleshoot Delivery Optimization by performing device health checks and peer-to-peer configuration of the device. This PowerShell script is officially signed by Microsoft. 
#> 
# DeliveryOptimizationTroubleshooter.ps1
#
# Copyright Microsoft Corporation.
#

<#
    .SYNOPSIS
        Script for:
        - Checking Device, Network, DO, P2P and MCC Settings.

    .PARAMETER HealthCheck
        A Health Checker script that displays settings to help the user to validate if there are any wrong settings in the user device, network, DO.

    .PARAMETER P2P
        Show to user the P2P efficiency of the device, errors found and Policy settings.

    .PARAMETER MCC
        Show MCC settings to allow customers to ensure the Windows device can correctly connect to the CacheHost server on the network, for supported content downloads. 

    .EXAMPLE
        To run all script verifications 

            DeliveryOptimizationTroubleshooter.ps1

    .EXAMPLE
        To run only Healthcheck 

            DeliveryOptimizationTroubleshooter.ps1 -HealthCheck

    .EXAMPLE
        To run only P2P validation 

            DeliveryOptimizationTroubleshooter.ps1 -P2P
            
    .EXAMPLE
        To run only MCC validation 

            DeliveryOptimizationTroubleshooter.ps1 -MCC
#>

[CmdLetBinding()]
Param(
    [switch] $HealthCheck,
    [switch] $P2P,
    [switch] $MCC
)

#----------------------------------------------------------------------------------#
# Enums
Add-Type -TypeDefinition @"
    public enum TestResult
    {
        Unset,
        Fail,
        Pass,
        Disabled,
        Warn,
    }
"@

#----------------------------------------------------------------------------------#
# Get Custom Objects
function Get-DOErrorsTable(){
    $errorsObj = @'
[
    { 
        "ErrorCode": "0x80D01001", 
        "Description": "Delivery Optimization was unable to provide the service." 
    },
    {         
        "ErrorCode": "0x80D02002", 
        "Description": "Download of a file saw no progress within the defined period." 
    },
    {         
        "ErrorCode": "0x80D02003", 
        "Description": "Job was not found." 
    },
    {         
        "ErrorCode": "0x80D02004", 
        "Description": "There were no files in the job." 
    },
    {         
        "ErrorCode": "0x80D02005", 
        "Description": "No downloads currently exist." 
    },
    {         
        "ErrorCode": "0x80D0200B", 
        "Description": "Memory stream transfer is not supported." 
    },
    {         
        "ErrorCode": "0x80D0200C", 
        "Description": "Job has neither completed nor has it been cancelled prior to reaching the max age threshold." 
    },
    {         
        "ErrorCode": "0x80D0200D", 
        "Description": "There is no local file path specified for this download." 
    },
    {          
        "ErrorCode": "0x80D02010", 
        "Description": "No file is available because no URL generated an error." 
    },
    {          
        "ErrorCode": "0x80D02011", 
        "Description": "SetProperty() or GetProperty() called with an unknown property ID." 
    },
    {          
        "ErrorCode": "0x80D02012", 
        "Description": "Unable to call SetProperty() on a read-only property." 
    },
    {          
        "ErrorCode": "0x80D02013", 
        "Description": "The requested action is not allowed in the current job state." 
    },
    {          
        "ErrorCode": "0x80D02015", 
        "Description": "Unable to call GetProperty() on a write-only property." 
    },
    {         
        "ErrorCode": "0x80D02016", 
        "Description": "Download job is marked as requiring integrity checking but integrity checking info was not specified." 
    },
    {         
        "ErrorCode": "0x80D02017", 
        "Description": "Download job is marked as requiring integrity checking but integrity checking info could not be retrieved." 
    },
    {         
        "ErrorCode": "0x80D02018", 
        "Description": "Unable to start a download because no download sink (either local file or stream interface) was specified." 
    },
    {
        "ErrorCode": "0x80D02019", 
        "Description": "An attempt to set a download sink failed because another type of sink is already set." 
    },
    {
        "ErrorCode": "0x80D0201A", 
        "Description": "Unable to determine file size from HTTP 200 status code." 
    },
    {
        "ErrorCode": "0x80D0201B", 
        "Description": "Decryption key was provided but file on CDN does not appear to be encrypted." 
    },
    {
        "ErrorCode": "0x80D0201C", 
        "Description": "Unable to determine file size from HTTP 206 status code." 
    },
    {
        "ErrorCode": "0x80D0201D", 
        "Description": "Unable to determine file size from an unexpected HTTP 2xx status code." 
    },
    {
        "ErrorCode": "0x80D0201E", 
        "Description": "User consent to access the network is required to proceed." 
    },
    {
        "ErrorCode": "0x80D02200", 
        "Description": "The download was started without providing a URI." 
    },
    {
        "ErrorCode": "0x80D02201", 
        "Description": "The download was started without providing a content ID." 
    },
    {
        "ErrorCode": "0x80D02202", 
        "Description": "The specified content ID is invalid." 
    },
    {
        "ErrorCode": "0x80D02203", 
        "Description": "Ranges are unexpected for the current download." 
    },
    {
        "ErrorCode": "0x80D02204", 
        "Description": "Ranges are expected for the current download." 
    },
    {
        "ErrorCode": "0x80D03001", 
        "Description": "Download job not allowed due to participation throttling." 
    },
    {
        "ErrorCode": "0x80D03002", 
        "Description": "Download job not allowed due to user/admin settings."  
    },
    {
        "ErrorCode": "0x80D03801", 
        "Description": "DO core paused the job due to cost policy restrictions." 
    },
    {
        "ErrorCode": "0x80D03802",  
        "Description": "DO job download mode restricted by content policy." 
    },
    {
        "ErrorCode": "0x80D03803", 
        "Description": "DO core paused the job due to detection of cellular network and policy restrictions." 
    },
    {
        "ErrorCode": "0x80D03804",
        "Description": "DO core paused the job due to detection of power state change into non-AC mode.",
        "RelatedPolicyName": "DOMinBatteryPercentageAllowedToUpload",
        "SuggestedRemedy": "Please check your Battery level is enough to P2P."
    },
    {
        "ErrorCode": "0x80D03805", 
        "Description": "DO core paused the job due to loss of network connectivity." 
    },
    {
        "ErrorCode": "0x80D03806", 
        "Description": "DO job download mode restricted by policy." 
    },
    {
        "ErrorCode": "0x80D03807",
        "Description": "DO core paused the completed job due to detection of VPN network.",
        "RelatedPolicyName": "DOAllowVPNPeerCaching",
        "SuggestedRemedy": "Check you are connected to any VPN when you are doing P2P."
    },
    {
        "ErrorCode": "0x80D03808", 
        "Description": "DO core paused the completed job due to detection of critical memory usage on the system." 
    },
    {
        "ErrorCode": "0x80D03809", 
        "Description": "DO job download mode restricted due to absence of the cache folder." 
    },
    {
        "ErrorCode": "0x80D0380A", 
        "Description": "Unable to contact one or more DO cloud services." 
    },
    {
        "ErrorCode": "0x80D0380B", 
        "Description": "DO job download mode restricted for unregistered caller." 
    },
    {
        "ErrorCode": "0x80D0380C", 
        "Description": "DO job is using the simple ranges download in simple mode." 
    },
    {
        "ErrorCode": "0x80D0380D", 
        "Description": "DO job paused due to unexpected HTTP response codes (e.g. 204)." 
    },
    {
        "ErrorCode": "0x80D05001", 
        "Description": "HTTP server returned a response with data size not equal to what was requested." 
    },
    {
        "ErrorCode": "0x80D05002", 
        "Description": "The Http server certificate validation has failed." 
    },
    {
        "ErrorCode": "0x80D05010", 
        "Description": "The specified byte range is invalid." 
    },
    {
        "ErrorCode": "0x80D05011", 
        "Description": "The server does not support the necessary HTTP protocol. Delivery Optimization (DO) requires that the server support the Range protocol header." 
    },
    {
        "ErrorCode": "0x80D05012", 
        "Description": "The list of byte ranges contains some overlapping ranges, which are not supported." 
    },
    {
        "ErrorCode": "0x80D06800", 
        "Description": "Too many bad pieces found during upload." 
    },
    {
        "ErrorCode": "0x80D06802",
        "Description": "Fatal error encountered in core." 
    },
    {
        "ErrorCode": "0x80D06803", 
        "Description": "Services response was an empty JSON content." 
    },
    {
        "ErrorCode": "0x80D06804", 
        "Description": "Received bad or incomplete data for a content piece." 
    },
    {
        "ErrorCode": "0x80D06805", 
        "Description": "Content piece hash check failed." 
    },
    { 
        "ErrorCode": "0x80D06806", 
        "Description": "Content piece hash check failed but source is not banned yet." 
    },
    {
        "ErrorCode": "0x80D06807",
        "Description": "The piece was rejected because it already exists in the cache." 
    },
    {
        "ErrorCode": "0x80D06808", 
        "Description": "The piece requested is no longer available in the cache." 
    },
    {
        "ErrorCode": "0x80D06809", 
        "Description": "Invalid metainfo content." 
    },
    {
        "ErrorCode": "0x80D0680A", 
        "Description": "Invalid metainfo version." 
    },
    {
        "ErrorCode": "0x80D0680B", 
        "Description": "The swarm isn't running." 
    },
    {
        "ErrorCode": "0x80D0680C", 
        "Description": "The peer was not recognized by the connection manager." 
    },
    {
        "ErrorCode": "0x80D0680D", 
        "Description": "The peer is banned." 
    },
    {
        "ErrorCode": "0x80D0680E", 
        "Description": "The client is trying to connect to itself." 
    },
    {
        "ErrorCode": "0x80D0680F", 
        "Description": "The socket or peer is already connected." 
    },
    {
        "ErrorCode": "0x80D06810", 
        "Description": "The maximum number of connections has been reached." 
    },
    {
        "ErrorCode": "0x80D06811", 
        "Description": "The connection was lost." 
    },
    {
        "ErrorCode": "0x80D06812", 
        "Description": "The swarm ID is not recognized." 
    },
    {
        "ErrorCode": "0x80D06813", 
        "Description": "The handshake length is invalid." 
    },
    {
        "ErrorCode": "0x80D06814", 
        "Description": "The socket has been closed." 
    },
    {
        "ErrorCode": "0x80D06815",  
        "Description": "The message is too long." 
    },
    {
        "ErrorCode": "0x80D06816", 
        "Description": "The message is invalid." 
    },
    {
        "ErrorCode": "0x80D06817", 
        "Description": "The peer is an upload." 
    },
    {
        "ErrorCode": "0x80D06818", 
        "Description": "Cannot pin a swarm because it's not in peering mode." 
    },
    {
        "ErrorCode": "0x80D06819", 
        "Description": "Cannot delete a pinned swarm without using the 'force' flag."
    }
]
'@ | ConvertFrom-Json

    foreach ($obj in $errorsObj)
    {
        $intValue = [Convert]::ToInt32($obj.ErrorCode, 16)
        $obj.ErrorCode = $intValue
    }
    
    return $errorsObj
}
        
function Get-DOPolicyTable(){
    $linkBase = "https://learn.microsoft.com/windows/deployment/do/waas-delivery-optimization-reference"

@"
    [
        { 
            "PolicyCode": "DODownloadMode", 
            "PolicyName": "Download Mode Configured", 
            "Description": "The download method that DO can use in downloads.", 
            "Link": "$linkBase#download-mode"
        },
        { 
            "PolicyCode": "DOGroupId", 
            "PolicyName": "Group ID", 
            "Description": "Unique GUID group id to create a custom group.", 
            "Link": "$linkBase#group-id"
        },
        { 
            "PolicyCode": "DOGroupIdSource", 
            "PolicyName": "Group ID Source", 
            "Description": "Restrict peer selection to a specific source.", 
            "Link": "$linkBase#select-the-source-of-group-ids"
        },
        { 
            "PolicyCode": "DORestrictPeerSelectionBy", 
            "PolicyName": "Restrict Peer Selection", 
            "Description": "Restriction to set peering boundary.", 
            "Link": "$linkBase#select-a-method-to-restrict-peer-selection"
        },
        { 
            "PolicyCode": "DODelayForegroundDownloadFromHttp", 
            "PolicyName": "Delay Foreground from Http", 
            "Description": "Control the time to wait for peering (foreground).", 
            "Link": "$linkBase#delay-foreground-download-from-http-in-secs"
        },
        { 
            "PolicyCode": "DODelayBackgroundDownloadFromHttp", 
            "PolicyName": "Delay Background from Http", 
            "Description": "Control the time to wait for peering (background).", 
            "Link": "$linkBase#delay-background-download-from-http-in-secs"
        },
        { 
            "PolicyCode": "DOAllowVPNPeerCaching", 
            "PolicyName": "Enable Peering on VPN", 
            "Description": "Allow device to use peering while connected to a VPN.", 
            "Link": "$linkBase#enable-peer-caching-while-the-device-connects-via-vpn"
        },
        { 
            "PolicyCode": "DOMaxCacheAge", 
            "PolicyName": "Max Cache Age", 
            "PolicyUnit": "(secs)", 
            "Description": "Max number of seconds a file can be held in DO cache.", 
            "Link": "$linkBase#max-cache-age"
        },
        { 
            "PolicyCode": "DOMaxCacheSize", 
            "PolicyName": "Max Cache Size", 
            "PolicyUnit": "%", 
            "Description": "Percentage of available disk drive space allowed​.", 
            "Link": "$linkBase#max-cache-size"
        },
        { 
            "PolicyCode": "DOAbsoluteMaxCacheSize", 
            "PolicyName": "Absolute Max Cache Size", 
            "PolicyUnit": "GB", 
            "Description": "Max number of gigabytes the DO cache can use.", 
            "Link": "$linkBase#absolute-max-cache-size"
        },
        { 
            "PolicyCode": "DOMinBatteryPercentageAllowedToUpload", 
            "PolicyName": "Allow P2P on Battery", 
            "PolicyUnit": "%", 
            "Description": "Specifies battery level to allow upload data.", 
            "Link": "$linkBase#allow-uploads-while-the-device-is-on-battery-while-under-set-battery-level"
        },
        { 
            "PolicyCode": "DOMinDiskSizeAllowedToPeer", 
            "PolicyName": "Minimum Free Disk Size", 
            "PolicyUnit": "GB", 
            "Description": "Required minimum disk size to allow peer caching.", 
            "Link": "$linkBase#minimum-disk-size-allowed-to-use-peer-caching"
        },
        { 
            "PolicyCode": "DOMinFileSizeToCache", 
            "PolicyName": "Minimum Peer File Size", 
            "PolicyUnit": "MB", 
            "Description": "Minimum content file size to use peer caching.", 
            "Link": "$linkBase#minimum-peer-caching-content-file-size"
        },
        { 
            "PolicyCode": "DOMinRAMAllowedToPeer", 
            "PolicyName": "Minimum RAM size", 
            "PolicyUnit": "GB", 
            "Description": "Minimum RAM size to use peer caching.", 
            "Link": "$linkBase#minimum-ram-inclusive-allowed-to-use-peer-caching"
        },
        { 
            "PolicyCode": "DOMinBackgroundQoS", 
            "PolicyName": "Minimum Background QoS", 
            "PolicyUnit": "KB/s", 
            "Description": "Specifies the minimum download speed guarantee.", 
            "Link": "$linkBase#minimum-background-qos"
        }
    ]
"@ | ConvertFrom-Json

}

#----------------------------------------------------------------------------------#
# Print Functions
function Print-OSInfo()
{
    # Check OS Version
    $os = Get-WmiObject -Class Win32_OperatingSystem

    Write-Host "`nWindows" $os.Version -NoNewline

    switch ($os.BuildNumber)
    {
        "10240" { Write-Host " - TH1" }
        "10586" { Write-Host " - TH2" }
        "14393" { Write-Host " - RS1" }
        "15063" { Write-Host " - RS2" }
        "16299" { Write-Host " - RS3" }
        "17134" { Write-Host " - RS4" }
        "17763" { Write-Host " - RS5" }
        "18362" { Write-Host " - Titanium 19H1" }
        "18363" { Write-Host " - Vanadium 19H2" }
        "19041" { Write-Host " - Vibranium 20H1" }
        "19042" { Write-Host " - Vibranium (v2) 20H2" }
        "19645" { Write-Host " - Manganese" }
        "19043" { Write-Host " - Vibranium (v3) 21H1" }
        "19044" { Write-Host " - Vibranium (v4) 21H2" }
        "20348" { Write-Host " - Iron" }
        "22000" { Write-Host " - Cobalt" }
        "22621" { Write-Host " - Nickel" }
        default { Write-Host "" }
    }

    # Check UUS Version
    $uusVerPath = "$env:ProgramData\Microsoft\Windows\UUS\State\_active.uusver"
    if (Test-Path $uusVerPath)
    {
        $uusVersion = Get-Content $uusVerPath
        Write-Host "UUS" $uusVersion
    }
    
    $PSVersion = "PS Version " + $PSVersionTable.PSVersion
    Write-Verbose $PSVersion
}

function Print-Title([string] $TextTitle, [int] $TitleLineSize, [string] $BgColor, [string] $FgColor)
{
    $textLine  = AddSpace -Text $TextTitle -SizeSpace $TitleLineSize
    $emptyLine = AddSpace -Text " " -SizeSpace $TitleLineSize
    $bColor = [Enum]::GetValues([System.ConsoleColor]) | Where-Object {$_.ToString() -eq $BgColor}

    Write-Host ""
    Write-host $emptyLine -b $bColor -n; Write-host ([char]0xA0) # ([char]0xA0) is necessary to solve print color bug

    if ($FgColor)
    {
        $fColor = [Enum]::GetValues([System.ConsoleColor]) | Where-Object {$_.ToString() -eq $FgColor}
        Write-host $textLine -f $fColor -b $bColor -n;   Write-host ([char]0xA0)
    }
    else 
    {
        Write-host $textLine -b $bColor -n; Write-host ([char]0xA0)
    }
    
    Write-host $emptyLine -b $bColor -n; Write-host ([char]0xA0)
}

function Format-ResultObject([pscustomobject] $Object)
{
    $Object | Format-Table -Wrap -Property  @{ Label = "Name"; Expression={ $_.Name }; Align='left'; Width = 30; },
                                            @{ Label = "Result"; Expression={ switch ($_.Result) 
                                                                                {
                                                                                    "Fail" { $color = "91"; $text = "FAIL"; break }
                                                                                    "Pass" { $color = "92"; $text = "PASS"; break }
                                                                                    "Warn" { $color = "93"; $text = "WARN"; break }
                                                                                    "Disabled" { $color = "37"; $text = "DISABLED"; break }
                                                                                    default { $color = "91"; $text = "ERROR" }
                                                                                } 
                                                                                ; $e = [char]27
                                                                                ;"$e[${color}m$($text)${e}[0m"
                                                                            }; Width = 10;}, 
                                            @{ Label = "Details"; Expression={ $_.Details }; Align='left'; }       
} 

#----------------------------------------------------------------------------------#
# Device Check

function Check-AdminPrivileges([string] $InvocationLine)
{
    if (IsElevated)
    {
        return $true;
    }
    
    $ScriptPath = $MyInvocation.PSCommandPath

    # The new process can't resolve working dir when script is launched like .\dolog.ps1, so we have to parse
    # and rebuild the full script path and param list.
    $scriptParams = ""
    $firstParam = $InvocationLine.IndexOf('-')

    if($firstParam -gt 0)
    {
        $scriptParams = $InvocationLine.Substring($firstParam-1)
    }

    $scriptCmd = "$ScriptPath $scriptParams"

    $arg = "-NoExit -Command `"$scriptCmd`""

    #Check Powershell version to use the right path
    if ($PSVersionTable.PSVersion.Major -lt 7)
    {
        $PSPath = "powershell.exe" 
    }
    else
    {
        $PSPath = "pwsh.exe"
    }
    
    $proc = Start-Process $PSPath -ArgumentList $arg -Verb Runas -ErrorAction Stop

    return $false
}

function IsElevated
{
    $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp = new-object System.Security.Principal.WindowsPrincipal($wid)
    $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $isElevated = $prp.IsInRole($adm)
    return $isElevated
}

function Check-NetInterface()
{
    $outputName = "Network Interface"
    $result = [TestResult]::Unset
    $description = " "

    try
    {
        $query = "SELECT * FROM Win32_NetworkAdapter WHERE NOT PNPDeviceID LIKE 'ROOT\\%'"
        $interfaces = Get-WmiObject -Query $query | Sort index
        $networkInterface = @()
        
        #Save in a string all the interfaces found
        foreach ($interface in $interfaces)
        {
            $name = $interface.NetConnectionID
            $description = $interface.Name

            if ($name)
            {
               $networkInterface += "($name) $description "
            }
        }

        if ($networkInterface)
        {
            $result = [TestResult]::Pass
            $description = $networkInterface -join " - "
        }
        else
        {
            $result = [TestResult]::Fail
            $description = "No network"
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
}

function Check-CacheFolder()
{
    $outputName = "Cache Folder Access"
    $result = [TestResult]::Unset
    $description = ""

    try
    {
        $dosvcWorkingDir = $doConfig.WorkingDirectory
        if (!(Test-Path $dosvcWorkingDir)) { throw "Cache folder not found: $dosvcWorkingDir" }

        $acl = Get-Acl $dosvcWorkingDir

        $IdentityReferenceDO = "NT SERVICE\DoSvc"
        $IdentityReferenceNS = "NT AUTHORITY\NETWORK SERVICE"
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit)

        # Filter to DO/NS permissions
        $permissionEntries = $acl.Access | where { @($IdentityReferenceDO, $IdentityReferenceNS) -contains $_.IdentityReference.Value }
        # This might be interesting here: Write-Verbose $permissionEntries

        # Look for Allow/FullControl/Full inheritance
        $permissionEntries = $permissionEntries | where { ($_.AccessControlType -eq "Allow") -and ($_.FileSystemRights -eq "FullControl") -and ($_.InheritanceFlags -eq $inheritanceFlags) }

        if ($permissionEntries)
        {
            $result = [TestResult]::Pass
        }
        else
        {
            $description = "Required permissions missing"
            $result = [TestResult]::Fail
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
}

function Check-Service([string] $ServiceName)
{
    $outputName = "Service Status"
    $result = [TestResult]::Unset
    $description = ""

    try
    {
        $service = Get-Service -Name $ServiceName
        if ($service -and ($service.StartType -ne "Disabled"))
        {
            if ($service.Status -eq "Running")
            {
                $description = "$ServiceName running"
                $result = [TestResult]::Pass
            }
            else
            {
                $description = "$ServiceName stopped"
                $result = [TestResult]::Warn
            }
        }
        else
        {
            $description = "$ServiceName disabled"
            $result = [TestResult]::Fail
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
}

function Check-KeyAccess()
{
    $outputName = "Registry Key Access"
    $result = [TestResult]::Unset
    $description = ""

    try
    {
        Remove-PSDrive HKU -ErrorAction SilentlyContinue

        $drive = New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
        $testPath = Test-Path -Path HKU:\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization
        if (!$testPath) { throw "Registry Key not found" }
        # TODO: Check permissions on key

        # $doConfig.WorkingDirectory is the cache path, which may be redirected elsewhere. The state directory doesn't follow that redirection.
        $path = "$env:windir\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\dosvcState.dat"

        $testPath = Test-Path -Path $path -PathType Leaf
        if (!$testPath)
        {
            $description = "Registry file not found"
            $result = [TestResult]::Fail
        }
        else
        {
            # TODO: Check permissions on file
            $result = [TestResult]::Pass
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
    finally
    {
        Remove-PSDrive HKU -ErrorAction SilentlyContinue
    }
}

function Check-RAMRequired()
{
    $outputName = "RAM"
    $result = [TestResult]::Unset
    $description = ""

    try
    {
        $totalRAM = (Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | Select-Object -ExpandProperty Sum)/1GB
        
        if ($totalRAM -ge $doConfig.MinTotalRAM)
        {
            $description = "$totalRAM GB"
            $result = [TestResult]::Pass
        }
        else
        {
            $description = "Local RAM: $ramTotal GB | RAM Requirements: $minTotalRAM GB."
            $result = [TestResult]::Fail
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
}

function Check-DiskRequired()
{
    $outputName = "Disk"
    $result = [TestResult]::Unset
    $description = ""

    try
    {
        $diskSize = Get-WmiObject -Class win32_logicaldisk | Where-Object DeviceId -eq $env:SystemDrive | Select-Object @{N='Disk'; E={$_.DeviceId}}, @{N='Size'; E={[math]::Round($_.Size/1GB,2)}}, @{N='FreeSpace'; E={[math]::Round($_.FreeSpace/1GB,2)}}

        if ($diskSize.FreeSpace -ge $doConfig.MinTotalDiskSize)
        {
            $result = [TestResult]::Pass
            $description = $diskSize.Disk + " | Total Size: " + $diskSize.Size + "GB | Free Space: " + $diskSize.FreeSpace + "GB"
        }
        else
        {
            $result = [TestResult]::Fail            
            $description = "Free Space Requirements: $minDiskSize GB. | Local Free Space: $diskSize.FreeSpace GB"
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
}

function Check-Vpn()
{
    $outputName = "VPN"
    $result = [TestResult]::Unset
    $description = ""

    try
    {
        $vpn = Get-VpnConnection
        if (!$vpn)
        {
            $result = [TestResult]::Pass
        }
        else
        {
            $activeVPN = $vpn | Where-Object ConnectionStatus -eq "Connected"  | Select-Object -ExpandProperty Name
            if ($activeVPN)
            {
                $result = [TestResult]::Warn
                $description = "Connected: $activeVPN"
            }
            else
            {
                $AllVPN = (($vpn | Select-Object -ExpandProperty Name) -join " - ")
                $result = [TestResult]::Pass
                $description = "Not connected: $AllVPN"
            }
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
}

function Check-PowerBattery()
{
    $outputName = "Power"
    $result = [TestResult]::Unset
    $description = ""

    try
    {
        $battery = Get-WmiObject -Class win32_battery

        #PC:
        if (!$battery)
        {
            $result = [TestResult]::Pass
            $plan = Get-WmiObject -Class win32_powerplan -Namespace "root\cimv2\power" | Where-Object IsActive -eq true | Select-Object -ExpandProperty ElementName
            $description = "A/C: $plan"
        }
        #Notebook:
        else
        {
            $batteryPercentage = $battery.EstimatedChargeRemaining
            $batteryStatus = Get-WmiObject -Class BatteryStatus -Namespace root\wmi -ComputerName "localhost" -ErrorAction SilentlyContinue -ErrorVariable ProcessError
            
            if ($ProcessError)
            {
                $result = [TestResult]::Fail
                $description = "WMI Error ( Check https://learn.microsoft.com/en-us/previous-versions/tn-archive/ff406382(v=msdn.10) ) | Error: " + $ProcessError.Exception
            }
            elseif ($batteryStatus.PowerOnline)
            {
                $result = [TestResult]::Pass
                $description = "A/C: $batteryPercentage% (charging)"
            }
            else
            {
                $batteryLevelForSeeding = $doConfig.BatteryPctToSeed
                if ($batteryPercentage -ge $batteryLevelForSeeding)
                {
                    $result = [TestResult]::Pass
                }
                else
                {
                    $result = [TestResult]::Fail
                }
                $description = "Battery: $batteryPercentage% ($batteryLevelForSeeding% required to upload)"
            }
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
}

#----------------------------------------------------------------------------------#
# Connection Check

function Test-Port([int] $Port, [switch] $Optional)
{
    $outputName = "Check Port"
    $oldPreference = $Global:ProgressPreference
    $result = [TestResult]::Unset
    $description = "$Port"

    try
    {
        $Global:ProgressPreference = 'SilentlyContinue'
        $resultTest = Test-NetConnection -Computer localhost -Port $Port -WarningAction SilentlyContinue -InformationLevel 'Quiet'

        if ($resultTest)
        {
            $result = [TestResult]::Pass
        }
        else
        {
            if ($Optional -or ((Check-DownloadMode).Result -ne [TestResult]::Pass))
            {
                $result = [TestResult]::Warn
            }
            else
            {
                $result = [TestResult]::Fail
            }
        }

        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }
    finally
    {
        $Global:ProgressPreference = $oldPreference
    }
}

function Check-DownloadMode()
{
    $outputName = "Download Mode" 
    $result = [TestResult]::Fail
    $downloadMode = $doConfig.DownloadMode

    if (@("Lan", "Group", "Internet") -contains $downloadMode)
    {
        $result = [TestResult]::Pass
    }

    [pscustomobject] @{ Name = $outputName; Result = $result; Details = $downloadMode }
}

function Test-Hostname([string] $HostName)
{
    $outputName = "Host Connection" 
    $description = $HostName
    $result = [TestResult]::Unset

    try
    {
        $dnsHostnames = Resolve-DnsName $HostName | Select-Object -Unique -Property NameHost | % {[string]$_.NameHost}
        $dnsHostnames = $dnsHostnames | Where {!$_.Equals("")}

        $result = [TestResult]::Fail

        # Check if the list of hostnames is empty
        if ($dnsHostnames -eq $null)
        {
            $description = "Failed to resolve DNS: $HostName"
        }
        else
        {
            foreach($dnsHostname in $dnsHostnames)
            {
                $test = Test-Connection $dnsHostname -Quiet
                if ($test)
                {
                    $result = [TestResult]::Pass
                    break
                }
            }
        }
        
        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }     
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }  
    }
}

function Test-InternetInfo()
{
    # Check Request Timeout
    # Check if the Request comes back with a StatusCode error
    # Check if the Request comes back with a StatusCode 200 (success)
    # Check if the WebRequest comes back with Content-Type "text/json" (DO services all return json). Captive portal falls under here.
    # Check if the Json misses some information.

    $resultInt = [TestResult]::Fail
    $outputNameInt = "Internet Access" 
    $msgInt = ""

    $resultIp = [TestResult]::Fail
    $outputNameIp = "External IP"  
    $msgIp = "Unable to get External IP. "

    $url = "https://geo.prod.do.dsp.mp.microsoft.com/geo/"
    $testResults = @()

    try
    {
        $httpResponse = Invoke-WebRequest -UseBasicParsing -Uri $url
        if ($httpResponse.StatusCode -eq 200)
        {
            Write-Verbose $httpResponse.RawContent
            if ($httpResponse.Headers["Content-Type"] -eq "text/json")
            {
                $contentJson = ConvertFrom-Json $httpResponse.Content

                if (($contentJson.KeyValue_EndpointFullUri.Length -gt 0) -and ($contentJson.ExternalIpAddress.Length -gt 4))
                {
                    $resultInt = [TestResult]::Pass
                    $resultIp  = [TestResult]::Pass

                    $msgIp = $contentJson.ExternalIpAddress
                }
                else
                {
                    $msgInt = "Invalid GEO response!"   
                    $msgIp += "Invalid GEO response!"
                }
            }
            elseif ($httpResponse.Headers["Content-Type"] -eq "text/html")
            {
                $resultInt = [TestResult]::Warn
                $msgInt = "Possible captive portal detected!"
            }
            else
            {
                $contentType = $httpResponse.Headers["Content-Type"]
                $msgInt = "Invalid GEO response!" 
                $msgIp += "Unexpected Content-Type in GEO response '$contentType'"
            }
        }
        else
        {
            $msgInt = "Unable to reach DO's GEO service. Status Code: $httpResponse.StatusCode - $httpResponse.StatusDescription"
        }

        $testResults += [pscustomobject] @{ Name = $outputNameInt; Result = $resultInt; Details = $msgInt; Connection = ($resultInt -eq [TestResult]::Pass) }
        $testResults += [pscustomobject] @{ Name = $outputNameIp;  Result = $resultIp;  Details = $msgIp }
    }
    catch [System.Net.WebException] 
    {
        $msgInt = "Unable to reach DO's GEO service. Exception:" + $_.Exception 

        $testResults += [pscustomobject] @{ Name = $outputNameInt; Result = $null    ; Details = $msgInt; Connection = $false }
        $testResults += [pscustomobject] @{ Name = $outputNameIp;  Result = $resultIp; Details = $msgIp }
    }
    catch
    {
        $testResults += [pscustomobject] @{ Name = $outputNameInt; Result = $null; Details = $_.Exception; Connection = $false }
        $testResults += [pscustomobject] @{ Name = $outputNameIp;  Result = $resultIp;  Details = $msgIp }
    }

    return $testResults
}

function Check-ByteRange()
{
    $outputName = "HTTP Byte-Range Support"   
    $result = [TestResult]::Unset
    $description = ""

    try
    {
        $uri = "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/52fa8751-747d-479d-8f22-e32730cc0eb1"
        $request = [System.Net.WebRequest]::Create($uri)
        
        # Set request
        $request.Method = "GET"
        $request.AddRange("bytes", 0, 9)
        
        $return = $request.GetResponse()
        $statusCode = [int]$return.StatusCode
        $contentRange = $return.GetResponseHeader("Content-Range")
        $description = "$statusCode - " + $return.StatusCode + ", Content-Range: $contentRange"
        
        if(($statusCode -eq 206) -and ($contentRange -eq "bytes 0-9/25006511"))
        {
            $result = [TestResult]::Pass
        }
        else
        {
            $result = [TestResult]::Fail
        }

        Write-Verbose $return.Headers.ToString()    
        [pscustomobject] @{ Name = $outputName; Result = $result; Details = $description }
    }
    catch
    {
        [pscustomobject] @{ Name = $outputName; Result = $null; Details = $_.Exception }
    }

}

#----------------------------------------------------------------------------------#
# P2P Check

function Check-Winrt([ref] [bool] $BurntToastWasPreInstalled)
{   
    # Adding this Start-Sleep to Write-Progress works in Powershell 7 
    if ($PSVersionTable.PSVersion.Major -gt 6)
    {
        Start-Sleep -Seconds 1
    }

    Write-Progress -Activity "Checking Winrt" -Status "Checking Powershell Version" -PercentComplete 50

    try
    {
        if ($PSVersionTable.PSVersion.Major -lt 6)
        {
            $null = [Windows.Management.Policies.NamedPolicy,Windows.Management.Policies,ContentType=WindowsRuntime]
        }
        else
        {
            $BurntToastWasPreInstalled.Value = Load-Module -Module "BurntToast" 
                
            $DllsPath = Get-ChildItem -Path $env:userprofile\Documents\PowerShell\Modules\BurntToast\*\lib\Microsoft.Windows.SDK.NET\ -Filter *.dll -Recurse | %{$_.FullName}
            Add-Type -AssemblyName $DllsPath
        }
    }
    catch
    {
        Write-Error $_.Exception
    }

    Write-Progress -Activity "Checking Winrt" -Status "Checking Powershell Version" -Completed
}

function Load-Module ([string] $Module) {
    $oldProgressPreference = $Global:ProgressPreference
    $Global:ProgressPreference = "SilentlyContinue"

    try
    {
        # If module is imported in the session
        $checkModuleSession = Get-Module | Where-Object {$_.Name -eq $Module}

        # If module is not imported, but available on disk (PS 5)
        $checkModuleAvailableDisk = Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module}

        if ($checkModuleSession -or $checkModuleAvailableDisk) 
        {
            return $true
        }
        else 
        {
            Install-Module -Name $Module -Force -WarningAction SilentlyContinue -Scope CurrentUser
            return $false
        }
    }
    catch
    {
        Write-Error $_.Exception
    }
    finally
    {
        $Global:ProgressPreference = $oldProgressPreference
    }
}

function Get-PolicyData([string] $PolicyCode)
{
    $policy = [Windows.Management.Policies.NamedPolicy]::GetPolicyFromPath("DeliveryOptimization", $PolicyCode)
    
    if (!$policy.IsManaged){ return $null }

    switch ($policy.Kind.ToString())
    {
        "Int32" { return $policy.GetInt32().ToString() }
        "Int64" { return $policy.GetInt64().ToString() }
        default { return $policy.GetString() }
    }
}

function Check-PeerEfficiency()
{
    Write-Progress -Activity "Checking Peer Efficiency" -Status "Gathering data to determine P2P efficiency (it can take a few minutes)" -PercentComplete 10
    $logInfo = "Peer to Peer Efficiency:  "

    try
    {
        $peerEfficiency = (Get-DeliveryOptimizationLogAnalysis).EfficiencyInPeeringFiles
        
        Write-Progress -Activity "Checking Peer Efficiency" -Status "Checking return" -PercentComplete 80

        if($peerEfficiency -ne $null)
        {
            $description = $peerEfficiency.ToString() + " %"
        }
        else 
        {
            $description = "Failure in Get-DeliveryOptimizationLogAnalysis. Unable to determine P2P efficiency!"
        }
    }
    catch
    {
        Write-Error $_.Exception
        $description = "Failure in Get-DeliveryOptimizationLogAnalysis."
    }
    finally 
    {
        Write-Progress -Activity "Checking Peer Efficiency" -Status "Returning data" -Completed
    }

    
    [pscustomobject] @{ Peer_Info = $logInfo; Description = $description} 
}

function Get-PeerLogErrors()
{
    Print-Title -TextTitle " Errors Found (excluding transient errors):" -TitleLineSize 50 -BgColor "White" -FgColor "Black"
   
    # Adding this Start-Sleep to Write-Progress works in Powershell 7 
    if ($PSVersionTable.PSVersion.Major -gt 6)
    {
        Start-Sleep -Seconds 1
    }
    
    Write-Progress -Activity "Finding errors in DO logs" -Status "Parsing logs (it can take a couple of minutes)" -PercentComplete 10

    $startDate = (Get-Date).AddDays(-15)
    $hrRegistered = (Get-DeliveryOptimizationLog -LevelFilter 3) | Where-Object {($_.TimeCreated -gt $startDate) -and ($_.ErrorCode -ne $null)} | Sort-Object -Property ErrorCode -Unique
    Write-Progress -Activity "Finding errors in DO logs" -Status "Filtering errors" -PercentComplete 40
    
    if($hrRegistered)
    {
        Write-Progress -Activity "Finding errors in DO logs" -Status "Returning errors" -PercentComplete 80
        Get-DOErrorsTable | Where-Object {$hrRegistered.ErrorCode -contains $_.ErrorCode} 
    }

    Write-Progress -Activity "Finding errors in DO logs" -Status "Returning errors" -Completed
}

function Get-DOPolicies([pscustomobject] $ErrorsFound)
{   
    $policyTable = Get-DOPolicyTable
    $policyOutputs = @()
    $percentComp = 0

    # Adding this Start-Sleep to Write-Progress works in Powershell 7 
    if ($PSVersionTable.PSVersion.Major -gt 6)
    {
        Start-Sleep -Seconds 1
    }

    Write-Progress -Activity "Checking DO Policies" -Status "Getting policy data" -PercentComplete $percentComp

    try
    {
        foreach($policy in $policyTable)
        {
            $policyRelatedError = $false
            $policyValue = $null

            Write-Progress -Activity "Checking DO Policies" -Status "Getting $($policy.PolicyCode) data" -PercentComplete $percentComp
            $percentComp += 100/$policyTable.Count  

            #Policy Setup adjustments.
            $policyValue = Get-PolicyData -PolicyCode $policy.PolicyCode

            if($policyValue)
            {                 
                if($policy.PolicyUnit)
                { 
                    $policyValue += " " + $policy.PolicyUnit
                }
             
                if($policy.PolicyCode -eq "DODownloadMode")
                { 
                    $policyValue = switch ( $policyValue)
                    {
                        0 { "CdnOnly - 0" }
                        1 { "LAN - 1" }
                        2 { "Group - 2" }
                        3 { "Internet - 3" }
                        99 { "Simple - 99" }
                        100 { "Bypass - 100" }
                        default {  $policyValue }
                    }
                }
            }
            
            $policyError = $ErrorsFound | Where-Object {$_.RelatedPolicyName -eq $policy.PolicyCode}

            if ($policyError) 
            {
                $description = $policyError.SuggestedRemedy
                $policyRelatedError = $true
            }
            else 
            {
                $description = $policy.Description
            }
            
            $description += "`r`nMORE INFO: " + $policy.Link + "`r`n"
            $policyOutputs += [pscustomobject] @{ Name = $policy.PolicyName; Configuration = $policyValue; MoreInfo = $description; PolicySuggestion = $policyRelatedError }
        }
    }
    catch
    {
        Write-Error $_.Exception
    }
        
    Write-Progress -Activity "Checking DO Policies" -Status "Returning data" -Completed
    return $policyOutputs
}

#----------------------------------------------------------------------------------#
# Aux Functions
function AddSpace([string] $Text, [int] $SizeSpace)
{
    return $Text + (" " * ([math]::max(0, $sizeSpace - $text.Length)))
}

#----------------------------------------------------------------------------------#
# MAIN FUNCTIONS:
# Heath Checker:
function Invoke-HealthChecker()
{
    Print-Title -TextTitle " Device Health Check:" -TitleLineSize 100 -BgColor "Yellow" -FgColor "Black"
    
    Write-Host -ForegroundColor Green "-------------------------------------------------"
    Write-Host -ForegroundColor Green "-> Device Settings"
    Write-Host -ForegroundColor Green "-------------------------------------------------" -NoNewline
    
    $deviceSettings = @()
    $deviceSettings += Check-DownloadMode   
    $deviceSettings += Check-Service -ServiceName "dosvc"  
    $deviceSettings += Check-CacheFolder
    $deviceSettings += Check-KeyAccess 
    $deviceSettings += Check-Vpn
    
    Format-ResultObject $deviceSettings
    
    Write-Host -ForegroundColor Green "-------------------------------------------------"
    Write-Host -ForegroundColor Green "-> Hardware Settings"
    Write-Host -ForegroundColor Green "-------------------------------------------------" -NoNewline
    
    $hardwareCheck = @()
    $hardwareCheck += Check-RAMRequired
    $hardwareCheck += Check-DiskRequired
    $hardwareCheck += Check-PowerBattery
    
    Format-ResultObject $hardwareCheck
    
    Write-Host -ForegroundColor Green "-------------------------------------------------"
    Write-Host -ForegroundColor Green "-> Connection Check"
    Write-Host -ForegroundColor Green "-------------------------------------------------" -NoNewline
    
    Write-Progress -Activity "Connection Check" -Status "Checking net interface" -PercentComplete 0
    $connectionCheck = @()
    $connectionCheck += Check-NetInterface
    Write-Progress -Activity "Connection Check" -Status "Testing port 7680" -PercentComplete 15
    $connectionCheck += Test-Port -Port 7680           # 7680 - DO port
    Write-Progress -Activity "Connection Check" -Status "Testing port 7680" -PercentComplete 30
    $connectionCheck += Test-Port -Port 3544 -Optional # 3544 - Teredo port
    
    Write-Progress -Activity "Connection Check" -Status "Testing internet connection" -PercentComplete 45
    $connInformation = Test-InternetInfo
    $connectionCheck += $connInformation
    
    $hostNames = @( "dl.delivery.mp.microsoft.com", "download.windowsupdate.com" )
    if ($connInformation.Connection -eq $true)
    {
        Write-Progress -Activity "Connection Check" -Status "Checking HTTP ByteRange" -PercentComplete 60
        $connectionCheck += Check-ByteRange
    
        Write-Progress -Activity "Connection Check" -Status "Checking hostnames" -PercentComplete 75
        foreach($hostName in $hostNames)
        {
            $connectionCheck += Test-Hostname -HostName $hostName
        } 
    }
    else 
    {
        $result = [TestResult]::Fail
        $description = "Internet check failed. Unable to check "
    
        #Check-ByteRange:
        $connectionCheck += [pscustomobject] @{ Name = "HTTP Byte-Range Support"; Result = $result; Details = ($description + "HTTP Byte-Range Support") }
    
        #Test-Hostname:
        foreach($hostName in $hostNames)
        {
            $connectionCheck += [pscustomobject] @{ Name = "Host Connection"; Result = $result; Details = ($description + $hostName) }
        }
    } 
    
    Write-Progress -Activity "Connection Check" -Status "Showing results" -Completed
    
    Format-ResultObject $connectionCheck
}

# P2P Check:
function Invoke-P2PHealthChecker()
{
    Print-Title -TextTitle " P2P Health, Errors, Configuration:" -TitleLineSize 100 -BgColor "Green"
    
    Check-PeerEfficiency | Format-Table -Wrap -Autosize Peer_Info, Description
    
    #***** Check Errors Found  *****#
    $errorsFound = Get-PeerLogErrors
    if($errorsFound) 
    { 
        $errorsFound | Format-Table -Wrap -Autosize -Property @{Label='Error Code'; e={"0x{0:X}" -f $_.ErrorCode}}, Description 
    }
    else
    {
        Write-Host "  No errors Found!"
    }
    
    #***** Get DOPolicies *****# 
    Print-Title -TextTitle " Policy Settings:" -TitleLineSize 50 -BgColor "White" -FgColor "Black"
    
    # WinRT API (PS5 and PS7)
    $BurntToastWasPreInstalled = $false
    
    Check-Winrt ([ref]$BurntToastWasPreInstalled)
    
    Get-DOPolicies -ErrorsFound $errorsFound | Format-Table -Wrap -Property @{e='Name'; Width = 30; },
    @{Label='Configuration'; e={ if ($_.Configuration) { $_.Configuration } else { "Not Set" } } ; Width = 15; },
    @{Label='More Info'; e={ if ($_.PolicySuggestion) { $color = "93"; $e = [char]27; "$e[${color}m$($_.MoreInfo)${e}[0m" } else { $_.MoreInfo } } ; }
    
    #***** Remove Burnt Toast if it wasn't installed before in PS7 *****# 
    if (!$BurntToastWasPreInstalled -and $PSVersionTable.PSVersion.Major -gt 6)
    {
        Remove-Module -Name "BurntToast" -Force -WarningAction SilentlyContinue
    }
}

# MCC Check:
function Invoke-MCCHealthChecker()
{
    Print-Title -TextTitle " MCC Check:" -TitleLineSize 100 -BgColor "Blue" -FgColor "Black"
    
    Write-Host "`n"
}

#----------------------------------------------------------------------------------#
# MAIN SCRIPT:

$admin = Check-AdminPrivileges($MyInvocation.Line)
if (!$admin) { return }

$doConfig = Get-DOConfig -Verbose

Print-OSInfo

if (!$HealthCheck -and !$P2P -and !$MCC) 
{ 
    Invoke-HealthChecker 
    Invoke-P2PHealthChecker 
    Invoke-MCCHealthChecker 
}
else 
{
    if ($HealthCheck) { Invoke-HealthChecker } 
    if ($P2P){ Invoke-P2PHealthChecker } 
    if ($MCC){ Invoke-MCCHealthChecker } 
}
# SIG # Begin signature block
# MIInxAYJKoZIhvcNAQcCoIIntTCCJ7ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCuqBQd4BYjPYGC
# mFNLD/CTilhokGVy7uJ2scvdPwq0baCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGaQwghmgAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIYqRX9NaJgD8ex8mzZ1ZhUg
# dQp5Ey7BOkQhBtEXgrIOMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBnOGuJEo24rFb0ZP1ea5e5bAIhmayfhdnRbJ67dwRaZJ6qWG8lhkGE
# nqtbEODv1Yw04l4LOnr0VIutk5moO2xSmB2RO1NP0KGez3h3RlEtJI45jymUk/zJ
# /CgP+cMtIQButFX5mmMuhN42etooNUZPvHeBHJqEb0SKtI03CsR+xeF6BANHOa43
# W88jYOYp600K1zSlMNLXHyziAMu/x15O+ZCxvLABBKF0vQATJ+GW3PWG+0TGa3u+
# LG0nlYwfHgzQ1gCtWD/Boy+JrwiZDnJ7XPUv/GepnCxPH62MZHjwTYBsvs2Fpq1P
# +6TdTCtQaftk5a5ppaOPhzBalv492ZAuoYIXLDCCFygGCisGAQQBgjcDAwExghcY
# MIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHEGDVxlTH1cEHJqbUgkKyAHoHrDm963CX3PZvDuvBx2AgZlL+C+
# vncYEzIwMjMxMDMxMTc1MDUwLjc4NFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF7MIIHJzCCBQ+gAwIBAgITMwAAAbP+Jc4pGxuKHAABAAABszAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMDNaFw0yMzEyMTQyMDIyMDNaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEt
# NEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHwPuuYYgK4ssGCCsr2N
# 7eElKlz0JPButr/gpvZ67kNlHqgKAW0JuKAy4xxjfVCUev/eS5aEcnTmfj63fvs8
# eid0MNvP91T6r819dIqvWnBTY4vKVjSzDnfVVnWxYB3IPYRAITNN0sPgolsLrCYA
# KieIkECq+EPJfEnQ26+WTvit1US+uJuwNnHMKVYRri/rYQ2P8fKIJRfcxkadj8CE
# PJrN+lyENag/pwmA0JJeYdX1ewmBcniX4BgCBqoC83w34Sk37RMSsKAU5/BlXbVy
# Du+B6c5XjyCYb8Qx/Qu9EB6KvE9S76M0HclIVtbVZTxnnGwsSg2V7fmJx0RP4bfA
# M2ZxJeVBizi33ghZHnjX4+xROSrSSZ0/j/U7gYPnhmwnl5SctprBc7HFPV+BtZv1
# VGDVnhqylam4vmAXAdrxQ0xHGwp9+ivqqtdVVDU50k5LUmV6+GlmWyxIJUOh0xzf
# Qjd9Z7OfLq006h+l9o+u3AnS6RdwsPXJP7z27i5AH+upQronsemQ27R9HkznEa05
# yH2fKdw71qWivEN+IR1vrN6q0J9xujjq77+t+yyVwZK4kXOXAQ2dT69D4knqMlFS
# sH6avnXNZQyJZMsNWaEt3rr/8Nr9gGMDQGLSFxi479Zy19aT/fHzsAtu2ocBuTqL
# VwnxrZyiJ66P70EBJKO5eQECAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTQGl3CUWdS
# DBiLOEgh/14F3J/DjTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAWoa7N86wCbjA
# Al8RGYmBZbS00ss+TpViPnf6EGZQgKyoaCP2hc01q2AKr6Me3TcSJPNWHG14pY4u
# hMzHf1wJxQmAM5Agf4aO7KNhVV04Jr0XHqUjr3T84FkWXPYMO4ulQG6j/+/d7gqe
# zjXaY7cDqYNCSd3F4lKx0FJuQqpxwHtML+a4U6HODf2Z+KMYgJzWRnOIkT/od0oI
# Xyn36+zXIZRHm7OQij7ryr+fmQ23feF1pDbfhUSHTA9IT50KCkpGp/GBiwFP/m1d
# rd7xNfImVWgb2PBcGsqdJBvj6TX2MdUHfBVR+We4A0lEj1rNbCpgUoNtlaR9Dy2k
# 2gV8ooVEdtaiZyh0/VtWfuQpZQJMDxgbZGVMG2+uzcKpjeYANMlSKDhyQ38wboAi
# vxD4AKYoESbg4Wk5xkxfRzFqyil2DEz1pJ0G6xol9nci2Xe8LkLdET3u5RGxUHam
# 8L4KeMW238+RjvWX1RMfNQI774ziFIZLOR+77IGFcwZ4FmoteX1x9+Bg9ydEWNBP
# 3sZv9uDiywsgW40k00Am5v4i/GGiZGu1a4HhI33fmgx+8blwR5nt7JikFngNuS83
# jhm8RHQQdFqQvbFvWuuyPtzwj5q4SpjO1SkOe6roHGkEhQCUXdQMnRIwbnGpb/2E
# sxadokK8h6sRZMWbriO2ECLQEMzCcLAwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBxi0Tolt0eEqXCQl4qgJXUkiQOYaCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6OuAnTAiGA8yMDIzMTAzMTIxMzMxN1oYDzIwMjMxMTAxMjEzMzE3WjB3MD0G
# CisGAQQBhFkKBAExLzAtMAoCBQDo64CdAgEAMAoCAQACAgthAgH/MAcCAQACAhJ+
# MAoCBQDo7NIdAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAma6BRwvpgqZk
# h19NNf8roYajb4OecGuYJBUy9PpPeF6JYLLbfqLH1H8/fEN4zvKN9tgq+KCHD2vE
# 5o1KeLwtNiurY37HQfab2oPznVKioi4ZZXdjAe9gMtrsR7B0Uyn7syhXvvbSD+5A
# TqoETeNT+XhzUFVn4Zwv1g9jBgK0814xggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbP+Jc4pGxuKHAABAAABszANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCCsKHlyjQ95aeyOG4AXmrKOMcMXWoG5CjKD1mrYEo21bDCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIIahM9UqENIHtkbTMlBlQzaOT+WXXMkaHoo6
# GfvqT79CMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGz/iXOKRsbihwAAQAAAbMwIgQgpASDg6KBsZ3vdAk4PxC6Q+vJqkvSsOMJREzh
# n5rWH54wDQYJKoZIhvcNAQELBQAEggIACbOgmtlFEKtmh8K/Tas++Y3D17U3E9Ck
# px/SV1v9WHo+Ipu90NspK1HR2s0tSn/yfjKmFfiPqljqcFZ43OlCq5W6cpQwG4Da
# mK+wjasWti4ddiA/ECC0HN2nSSNiQwkb6a4K0FIMtQI5VdXtxdEFDmYwThl2j/RF
# rtIh1gSYd0hpD0P0flE1+vjzPCW5VmP7bTnm5pXXWYgwcDmViL0FEzjZNIepiWtn
# ePPODdJYNMVZ0MX0Dc9x5Pm5xj4anayxUlFAcsgfjsHeoHObLFB9zxJhF7KaSTH5
# nV+aqXc8wp8XcoOfEl9Ofx5JIqtHq2sfYo8fJSKSFOsvoCqpKw1R57U5szkM2mXB
# GdtTlnZLUMIlVHaGYhFlJhykTBQOHJUihIj83tRCHCjbza4sjljvYoA6lDVwGcCK
# jXj6WnkhWGvJRM+lF6iWFh0Z6y54ovHUkR6dJ8CtiG+ey5Ba3+uM6cm1qEt0HOAn
# kqhjjgKYZQmm3WIznqBueKWk5GQL2bsc68AudIJlljWIgDs03WP+WZs6adA6nMhw
# hu1fh4CJJCo9GtzvVNl0zzQ8SUpzuuphXFBfdVj6Vn9EH3h5iofnS79Iqqz0nC+C
# tKk+1yYR6bmUs06dy6Vt6j7E/qAhGGWH6Spsupill7yLW407btjiYZ3TLqAaSugW
# qB3YcEcK0bQ=
# SIG # End signature block
