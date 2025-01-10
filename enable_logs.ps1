<#PSScriptInfo
.VERSION 
    1.4
.AUTHOR
    bobby-tablez (Tim Peck)
    lukas-holas
.GUID
    a5d40ad0-297b-4269-80f9-934f6341367c
.SYNOPSIS
    Enables detailed logging telemetry for a host. 
.DESCRIPTION 
    This module provides a large amount of logging telemetry. This includes Sysinternals Sysmon, PowerShell module and scriptblock logging, and audit policies for key event IDs. This script can be modified to suit organizational needs, however it should be tested first as it can generate a huge amount of log data depending on the host.
.NOTES 
    Use at your own risk.
.LINK 
    https://raw.githubusercontent.com/bobby-tablez/Invoke-XORfuscation/main/Invoke-XORfuscation.ps1
    https://www.securonix.com/blog/improving-blue-team-threat-detection-with-enhanced-siem-telemetry/
.PARAMETER -sysmononly 
    This will ONLY download and install sysmon. If sysmon is already present, it will perform a reinstall using the provided XML import config file.    
.EXAMPLE 
    enable_logs.ps1 -sysmononly (-so)
.PARAMETER -y 
    This will skip the "are you sure?" prompt upon initial execution.
.EXAMPLE 
    enable_logs.ps1 -y (-yes)
    enable_logs.ps1 -y -sysmononly
.PARAMETER -config
    Bring your own XML config file. When the -config argument is passed, supply a direct URL to a Sysmon config import file. When no argument is supplied it will download: "https://raw.githubusercontent.com/bobby-tablez/FT-Sysmon-Config/master/ft-sysmonconfig-export.xml"
.EXAMPLE 
    enable_logs.ps1 -y
    enable_logs.ps1 -y -sysmononly
    enable_logs.ps1 -yes -sysmononly -config https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
.PARAMETER -driver (-d)
    Modify the Sysmon driver name. Limited to 8 characters.
.EXAMPLE 
    enable_logs.ps1 -y -driver "sccm"
.PARAMETER -name (-n)
    Modify the Sysmon binary file's name. The binary name will effectively become the service name. https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon
.EXAMPLE 
    enable_logs.ps1 -y -d "sccm" -name "sccm_service.exe"
.PARAMETER -auditpolonly
    This will ONLY configure advanced audit policies.
.EXAMPLE
    enable_logs.ps1 -auditpolonly (-apo)
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

#>

Param(
    [Alias("so")]
    [switch]$sysmononly,

    [Alias("y")]
    [switch]$yes,

    [Alias("c")]
    [string]$config = "https://raw.githubusercontent.com/bobby-tablez/FT-Sysmon-Config/master/ft-sysmonconfig-export.xml",

    [Alias("d")]
    [string]$driver,

    [Alias("n")]
    [string]$name,

    [Alias("apo")]
    [switch]$auditpolonly
)

# Check for administrator privs
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host -ForegroundColor Red "Enable All The Logs! requires Administrator privileges. Please rerun in an admin PowerShell console."
    exit
}

# Bypass the warning prompt when -y arguement is supplied
If (-Not $yes){
    If ($sysmononly){
        $confirmation = $(Write-Host -f Yellow -NoNewLine "CAUTION: This script will download and install Sysmon. Do you want to continue? (y/n): "; Read-Host)
    } ElseIf ($auditpolonly) {
        $confirmation = $(Write-Host -f Yellow -NoNewLine "CAUTION: This script will configure advanced audit policies. Do you want to continue? (y/n): "; Read-Host)
    } Else {
        $confirmation = $(Write-Host -f Yellow -NoNewLine "CAUTION: This script will download and install Sysmon, configure advanced audit policies and make registry changes that will increase log volume. Continue? (y/n): "; Read-Host)
    }

    If (-not($confirmation -eq 'y')) {
        Write-Host "`nBye!"
        exit
    }
}

# checkmark characters green/red
$cm = [char]0x2713
$ex = [char]0x274C


# SYSMON RELATED #
##################

$sysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonOut = "$env:temp\Sysmon.zip"
$sysmonConfOut = "$env:temp\sysmon-config.xml"
$sysmonConf = $config


Function ValidateDriverName {
    If ( -not $driver ) {
        return
    }
    If ($driver.Length -gt 8) {
        Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host "Error: Driver string must be 8 characters or less."
        exit 1
    }
    $driver = "-d $driver"
}

Function DownloadSysmon {
    Try { 
        Invoke-WebRequest -URI $sysmonURL -OutFile $sysmonOut
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " Sysmon downloaded"
    } Catch {
        $errorSysmon = $_.Exception.Message
        Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " Error occurred while downloading Sysmon: $errorSysmon"
        exit 1
    }
}

Function DownloadSysmonConfig {
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Downloading Sysmon config import file"
    Try { 
        Invoke-WebRequest -URI $sysmonConf -OutFile $sysmonConfOut
        # Attempt to load the file as an XML to validate its content
        [xml]$xmlContent = Get-Content -Path $sysmonConfOut
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Import config file downloaded and validated as XML"
    } Catch {
        $errorXML = $_.Exception.Message
        If ($_ -is [System.Xml.XmlException]) {
            Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] The downloaded config import file is not valid XML: $errorXML"
            exit 1 
        } Else {
            Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] Error occurred while downloading the config import file: $errorXML"
            exit 1
        }
    }
}

Function ExtractSysmon {
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Extracting Sysmon archive"
    Try { 
        Expand-Archive $sysmonOut -Destination $env:temp -ErrorAction Stop -Force
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Sysmon archive extracted"
    } Catch {
        $errorZIP = $_.Exception.Message
        Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] Error occurred while extracting the Sysmon archive: $errorZIP"
        exit 1
    }
}

Function Rename-Sysmon {
    Param (
        [string]$sourcePath,
        [string]$destinationPath
    )
    
    If (Test-Path $sourcePath) {
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Renaming binary to $destinationPath"
        Rename-Item -Path $sourcePath -NewName $destinationPath
    } Else {
        Write-Host "[ " -nonewline; Write-Host "ERROR" -f red -nonewline; Write-Host " ] Source binary not found: $sourcePath"
        exit 1
    }
}

# Used to uninstall sysmon prior to (re)installation
Function Uninstall-Sysmon {
    Param (
        [string]$serviceName,
        [string]$exePath
    )

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service.Length -gt 0) {
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Uninstalling Existing version of $serviceName"
        Start-Process -FilePath $exePath -ArgumentList "-u force" -Wait
        Sleep 3
    }
}

# Get CPU arch
Function b64{
    $b64test = [Environment]::Is64BitOperatingSystem #Used to install x86/x64 Sysmon per OS architecture
    return $b64test
}

Function SetupSysmon {
    ValidateDriverName
    DownloadSysmon
    DownloadSysmonConfig
    ExtractSysmon

    # Set variables of service and file names based on cpu arch
    If (b64) {
        $originalExePath = "$env:temp\Sysmon64.exe"
        $ServiceName = "Sysmon64"
    } Else {
        $originalExePath = "$env:temp\Sysmon.exe"
        $ServiceName = "Sysmon"
    }

    If ($name) {
        $SysmonExt = "$name.exe"
        $newExePath = "$env:temp\$SysmonExt"
        Rename-Sysmon -sourcePath $originalExePath -destinationPath $newExePath
        $sysmonExe = $newExePath
    } Else {
        $sysmonExe = $originalExePath
    }

    # Uninstall Sysmon if present (consideration for original and/or renamed binaries)
    Uninstall-Sysmon -serviceName $ServiceName -exePath $originalExePath
    If ($name) {
        Uninstall-Sysmon -serviceName $ServiceName -exePath $sysmonExe
    }

    # Install Sysmon
    If ($sysmononly) {
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Installing Sysmon64"
    } Else {
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Installing Sysmon"
    }
    Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i $sysmonConfOut $driver" -Wait

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Sysmon successfully installed"
    Write-Host ""

    # Clean Up
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Cleaning up"
    Remove-Item $sysmonOut,$sysmonConfOut,$sysmonExe,$env:temp\sysmon64.exe,$env:temp\sysmon64a.exe -ErrorAction SilentlyContinue | Out-Null
}

# AUDIT POLICY RELATED #
########################

# Policy settings
$auditSettings = @{

    # Account Logon
    "Credential Validation" =                    @{ Success="enable"; Failure="enable" }
    "Kerberos Authentication Service" =          @{ Success="enable"; Failure="enable" }
    "Kerberos Service Ticket Operations" =       @{ Success="enable"; Failure="enable" }
    "Other Account Logon Events" =               @{ Success="enable"; Failure="enable" }

    # Account Management
    "Application Group Management" =             @{ Success="enable"; Failure="enable" }
    "Computer Account Management" =              @{ Success="enable"; Failure="enable" }
    "Distribution Group Management" =            @{ Success="enable"; Failure="enable" }
    "Other Account Management Events" =          @{ Success="enable"; Failure="enable" }
    "Security Group Management" =                @{ Success="enable"; Failure="enable" }
    "User Account Management" =                  @{ Success="enable"; Failure="enable" }

    # Detailed Tracking
    "DPAPI Activity" =                           @{ Success="enable"; Failure="enable" }
    "Plug and Play Events" =                     @{ Success="enable"; Failure="disable" }
    "Process Creation" =                         @{ Success="enable"; Failure="enable" }
    "Process Termination" =                      @{ Success="enable"; Failure="enable" }
    "RPC Events" =                               @{ Success="enable"; Failure="enable" }
    "Token Right Adjusted Events" =              @{ Success="enable"; Failure="enable" }

    # DS Access
    "Detailed Directory Service Replication" =   @{ Success="disable"; Failure="disable" }
    "Directory Service Access" =                 @{ Success="enable"; Failure="enable" }
    "Directory Service Changes" =                @{ Success="enable"; Failure="enable" }
    "Directory Service Replication" =            @{ Success="enable"; Failure="enable" }

    # Logon/Logoff
    "Account Lockout" =                          @{ Success="enable"; Failure="enable" }
    "User / Device Claims" =                     @{ Success="enable"; Failure="enable" }
    "Group Membership" =                         @{ Success="enable"; Failure="enable" }
    "IPsec Extended Mode" =                      @{ Success="disable"; Failure="disable" }
    "IPsec Main Mode" =                          @{ Success="disable"; Failure="disable" }
    "IPsec Quick Mode" =                         @{ Success="disable"; Failure="disable" }
    "Logoff" =                                   @{ Success="enable"; Failure="enable" }
    "Logon" =                                    @{ Success="enable"; Failure="enable" }
    "Network Policy Server" =                    @{ Success="enable"; Failure="enable" }
    "Other Logon/Logoff Events" =                @{ Success="enable"; Failure="enable" }
    "Special Logon" =                            @{ Success="enable"; Failure="enable" }

    # Object Access
    "Application Generated" =                    @{ Success="enable"; Failure="enable" }
    "Certification Services" =                   @{ Success="enable"; Failure="enable" }
    "Detailed File Share" =                      @{ Success="enable"; Failure="enable" }
    "File Share" =                               @{ Success="enable"; Failure="enable" }
    "File System" =                              @{ Success="enable"; Failure="enable" }
    "Filtering Platform Connection" =            @{ Success="enable"; Failure="enable" }
    "Filtering Platform Packet Drop" =           @{ Success="enable"; Failure="enable" }
    "Handle Manipulation" =                      @{ Success="enable"; Failure="enable" }
    "Kernel Object" =                            @{ Success="enable"; Failure="enable" }
    "Other Object Access Events" =               @{ Success="enable"; Failure="enable" }
    "Removable Storage" =                        @{ Success="enable"; Failure="enable" }
    "Registry" =                                 @{ Success="enable"; Failure="enable" }
    "SAM" =                                      @{ Success="enable"; Failure="disable" }
    "Central Policy Staging" =                   @{ Success="disable"; Failure="disable" }

    # Policy Change
    "Audit Policy Change" =                      @{ Success="enable"; Failure="enable" }
    "Authentication Policy Change" =             @{ Success="enable"; Failure="enable" }
    "Authorization Policy Change" =              @{ Success="enable"; Failure="enable" }
    "Filtering Platform Policy Change" =         @{ Success="enable"; Failure="enable" }
    "MPSSVC Rule-Level Policy Change" =          @{ Success="disable"; Failure="disable" }
    "Other Policy Change Events" =               @{ Success="disable"; Failure="disable" }

    # Privilege Use
    "Non Sensitive Privilege Use" =              @{ Success="disable"; Failure="disable" }
    "Other Privilege Use Events" =               @{ Success="disable"; Failure="disable" }
    "Sensitive Privilege Use" =                  @{ Success="enable"; Failure="enable" }

    # System
    "IPsec Driver" =                             @{ Success="enable"; Failure="disable" }
    "Other System Events" =                      @{ Success="disable"; Failure="enable" }
    "Security State Change" =                    @{ Success="enable"; Failure="enable" }
    "Security System Extension" =                @{ Success="enable"; Failure="enable" }
    "System Integrity" =                         @{ Success="enable"; Failure="enable" }
}

Function ApplyPolicy {
    Param (
        [Parameter(Mandatory)]
        [string]$subcategory,

        [Parameter(Mandatory)]
        [string]$success,

        [Parameter(Mandatory)]
        [string]$failure
    )
    
    $invokeAudit = "auditpol /set /subcategory:`"$subcategory`" /success:$success /failure:$failure"
    Invoke-Expression -Command $invokeAudit | Out-Null
}

Function ConfigureAuditPolicy {
        
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Configuring Audit Policies"

    # Force audit policy subcategories
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $ValueName = "SCENoApplyLegacyAuditPolicy"
    $ValueData = 1
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData
    Get-ItemProperty -Path $RegistryPath -Name $ValueName
    
    # Apply each policy
    Foreach ($policy in $auditSettings.Keys) {
        $settings = $auditSettings[$policy]
        ApplyPolicy -subcategory $policy -success $settings.Success -failure $settings.Failure
    }

    Invoke-Expression -Command 'auditpol /get /category:*'

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Audit Policies Configured"
}

# OTHER CONFIGURATIONS #
########################

Function SetRegistryDword {
    Param (
        [Parameter(Mandatory)]
        [string]$regPath,

        [Parameter(Mandatory)]
        [string]$regValName,

        [Parameter(Mandatory)]
        [int]$regValDat
    )

    If (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -ItemType Directory -Force
    }
    Set-ItemProperty -Path $regPath -Name $regValName -Value $regValDat -Type DWord
    Get-ItemProperty -Path $regPath -Name $regValName
}

Function EnablePSLogging {
    
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling PowerShell scriptblock logging"
    $PSregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $PSregValName = "EnableScriptBlockLogging"
    $PSregValDat = 1
    SetRegistryDword -regPath $PSregPath -regValName $PSregValName -regValDat $PSregValDat
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] PowerShell Script Block Logging enabled"

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling PowerShell module logging"
    $PSMregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $PSMregValName = "EnableModuleLogging"
    $PSMregValDat = 1
    SetRegistryDword -regPath $PSMregPath -regValName $PSMregValName -regValDat $PSMregValDat
    # Necessary for module logging to work
    $PSMregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    if (-not (Test-Path $PSMregPath)) {
        New-Item -Path $PSMregPath -Force
    }
    Set-ItemProperty -Path $PSMregPath -Name "*" -Value "*"
    Get-ItemProperty -Path $PSMregPath
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] PowerShell Module Logging enabled"
}

# Enable command line field in process creation event 4688
Function EnableCmdLineField {

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling command line logging w/ EVID: 4688"
    $cmdRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $cmdRegValue = "ProcessCreationIncludeCmdLine_Enabled"
    $cmdRegData = 1
    SetRegistryDword -regPath $cmdRegPath -regValName $cmdRegValue -regValDat $cmdRegData
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Event ID 4688 enabled with commandline"
}

# MAIN LOGIC #
##############

if ($sysmononly) {
    SetupSysmon
    exit
}

if ($auditpolonly) {
    ConfigureAuditPolicy
    exit
}

# Setup everything
SetupSysmon
ConfigureAuditPolicy
EnablePSLogging
EnableCmdLineField
