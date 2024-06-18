<#
.SYNOPSIS
===========================================================================
Created on:         February 29, 2024
Last Updated on:    May 6, 2024  
Created by:         Joe Wetmore
Organization:       Comtech
Filename:           AD_setup STEP04 for all DCs
File Version:       1.0.1.0
Package Version     1.4
===========================================================================

.DESCRIPTION
! PLEASE RUN AS ADMIN to be sure commands complete properly
- this script configures local domain controller settings
- this script should be run on all domain controllers

.LINK


.NOTES
- 1.0.0.0 - Initial Commit
- 1.0.0.1 - Revision
- 1.0.1.0 - Check for pending reboot

#>

# Verify administrator
if ( -not (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) ) {
    throw 'Run as an administrator'
}


#Set the Log File Location
$LogFile = "C:\AD_setup\logs\AD_setup.log"

#Function to Create a Log File
Function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string] $message,
        [Parameter(Mandatory = $false)] [ValidateSet("INFO","WARNING","ERROR")] [string] $level = "INFO"
    )
    $Timestamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    Add-Content -Path $LogFile -Value "$timestamp [$level] - $message"
}
#Call the Function to Log a Message
#Write-Log -level ERROR -message "String failed to be a string"

#Function to check if this script has already been run
Function Check-alreadyrun {
$alreadyrun = Select-String -Path $logfile -pattern "step04a.ps1 script complete"
if ($alreadyrun -ne $null)
{
    Write-Host "This script has already been run on this host. Stopping."
    Exit
}
else
{
    Write-Host "This script is being run for the first time on this host. Continuing. "
}}
Check-alreadyrun

#Function to check for pending reboot
Function Get-PendingRebootStatus {
<#
.Synopsis
    This will check to see if a server or computer has a reboot pending.
    For updated help and examples refer to -Online version.
  
.NOTES
    Name: Get-PendingRebootStatus
    Author: theSysadminChannel
    Version: 1.2
    DateCreated: 2018-Jun-6
  
.LINK
    https://thesysadminchannel.com/remotely-check-pending-reboot-status-powershell -
  
  
.PARAMETER ComputerName
    By default it will check the local computer.
  
.EXAMPLE
    Get-PendingRebootStatus -ComputerName PAC-DC01, PAC-WIN1001
  
    Description:
    Check the computers PAC-DC01 and PAC-WIN1001 if there are any pending reboots.
#>
  
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position=0
        )]
  
    [string[]]  $ComputerName = $env:COMPUTERNAME
    )
  
  
    BEGIN {}
  
    PROCESS {
        Foreach ($Computer in $ComputerName) {
            Try {
                $PendingReboot = $false
  
                $HKLM = [UInt32] "0x80000002"
                $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
  
                if ($WMI_Reg) {
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') {$PendingReboot = $true}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true}
  
                    #Checking for SCCM namespace
                    $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore
                    if ($SCCM_Namespace) {
                        if (([WmiClass]"\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq $true) {$PendingReboot = $true}
                    }
  
                    [PSCustomObject]@{
                        ComputerName  = $Computer.ToUpper()
                        PendingReboot = $PendingReboot
                    }
                }
            } catch {
                Write-Error $_.Exception.Message
  
            } finally {
                #Clearing Variables
                $null = $WMI_Reg
                $null = $SCCM_Namespace
            }
        }
    }
  
    END {}
}

Get-PendingRebootStatus

$pendingReboot = Get-PendingRebootStatus
if ($pendingReboot) {
    Write-Host "`nSystem does not require a reboot. Continuing...`n"
}
else {
    Write-Host "`nSystem requires a reboot. Exiting...`n"
    Exit
}

Write-Log "Beginning STEP04a of AD_Setup"

# Get the domain definition from step02
$domain = Get-Content C:\AD_setup\Domain.txt
$domainname = Get-Content C:\AD_setup\DomainName.txt
$tld = Get-Content C:\AD_setup\tld.txt
$hostname = hostname

Clear-Host

# Configure DNS1 and DNS2 on the network interface "
Write-Host "-----------------------------------------------" -ForegroundColor Green
Write-Host "-----Configuring DNS---------------------------" -ForegroundColor Green
Write-Host "-----------------------------------------------" -ForegroundColor Green
Write-Host " "
# Configure forwarders
Add-DnsServerForwarder -IPAddress 8.8.8.8 -PassThru
Add-DnsServerForwarder -IPAddress 1.1.1.1 -PassThru
Get-DnsServerForwarder
Write-Log "Configure DNS1 and DNS2 on the network interface"

<# Security hardening
    - Disable the AllowNT4Crypto setting on all the affected domain controllers (TB-202 page 13)
    - Spectre and Meltdown (TB-230 page 31, TB-127)
    - CVE-2021-34527 Print spooler (TB-230 page 32, TB-217)
    - Kerberos insecure encryption (TB-230 page 32, TB-220)
    - SMB signing no required (TB-230 page 32)
    - Windows speculative execution configuration check (TB-230 page 32)
    - Configure schannel to remove obsolete cyphers (TB-230 page 33, TB-198)
    - Windows Firewall (TB-230 page 33, TB-1)
    - Update OS (WSUS) (TB-230 page 33)
    - 3rd party updates (TB-230 page 33)
    - Configure a logon banner (TB-230 page 34)
    - Harden local account passwords (TB-230 page 35)
#>
Write-Host "-----------------------------------------------" -ForegroundColor Green
Write-Host "-----Applying security hardening---------------" -ForegroundColor Green
Write-Host "-----------------------------------------------" -ForegroundColor Green

# TB-230 Security Hardening Notes and Procedures, SECTION 9.1.1, Spectre and Meltdown
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -PropertyType "DWORD" -Value 0
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -PropertyType "DWORD" -Value 3

# TB-230 Security Hardening Notes and Procedures, SECTION 9.1.2, Mitigate CVE-2021-34527 Print Spooler
# Addressed in step03a, New-GPLink -Name "Global - Printers: Print Spooler - Disable"

# TB-230 Security Hardening Notes and Procedures, SECTION 9.1.3, Fix Kerberos Insecure Encryption
# Note, this GPO should have been included in the /AD_setup/gpoimport directory. Foldername is {6C410133-6E56-43F5-B0E5-9F8AFEB4E1E8}
# Addressed in step03a, New-GPLink -Name "Core - Windows System: Kerberos Encryption"

# TB-230 Security Hardening Notes and Procedures, SECTION 9.1.4, SMB Signing not required
# Addressed in step03a, New-GPLink -Name "Global - Windows System: SMBv1 - Disable"

# TB-230 Security Hardening Notes and Procedures, SECTION 9.1.5, Windows Speculative Execution Configuration Check
# NEED THE GPO FOR THIS

# TB-230 Security Hardening Notes and Procedures, SECTION 9.1.6, Configure SCHANNEL to remove obsolete Ciphers
# Addressed in step03a, New-GPLink -Name "Global - Security: SCHANNEL -Disable Insecure TLS1.1 and older and Cipher Suites"

# TB-230 Security Hardening Notes and Procedures, SECTION 9.1.7, Windows Firewall
# Addressed in step03a, in the following lines
# New-GPLink -Name "Global - Windows Firewall: Base Rules" -Target "DC=$domain,DC=$tld" -LinkEnabled Yes
# New-GPLink -Name "Global - Windows Firewall: Configuration" -Target "DC=$domain,DC=$tld" -LinkEnabled Yes
# New-GPLink -Name "Global - Windows Firewall: Radmin" -Target "DC=$domain,DC=$tld" -LinkEnabled Yes
# New-GPLink -Name "Global - Windows Firewall: Remove Local FW Rules" -Target "DC=$domain,DC=$tld" -LinkEnabled Yes
# New-GPLink -Name "Core - Windows Firewall: Configure Network Connection Profile" -Target "OU=Datacenters,DC=$domain,DC=$tld" -LinkEnabled Yes
# New-GPLink -Name "Core - Windows Firewall: Enable WinRM" -Target "OU=Datacenters,DC=$domain,DC=$tld" -LinkEnabled Yes
# New-GPLink -Name "Core - Windows Firewall: Domain Controllers" -Target "OU=Domain Controllers,DC=$domain,DC=$tld" -LinkEnabled Yes
# New-GPLink -Name "PSAP - Windows Firewall: Workstation" -Target "OU=PSAPs,DC=$domain,DC=$tld" -LinkEnabled Yes

# Enable GPO Links that were created but not enabled in Step03a
Set-GPLink -Name "Global - Security: Local Users and Groups - Local Administrator Account - Disable" -Target "DC=$domain,DC=$tld" -LinkEnabled Yes
Set-GPLink -Name "Global - Security: Local Users and Groups - Rename Built-In Guest and Administrator Accounts" -Target "DC=$domain,DC=$tld" -LinkEnabled Yes
Set-GPLink -Name "Global - Security: User Rights - Built-In and Special Accounts - Deny Logon" -Target "DC=$domain,DC=$tld" -LinkEnabled Yes
Set-GPLink -Name "Global - Windows System: Powershell - Disabled PSv2 Activate Constrained" -Target "DC=$domain,DC=$tld" -LinkEnabled Yes
Set-GPLink -Name "Core - Security: Local Users and Groups - Local Adminstrators" -Target "OU=Datacenters,DC=$domain,DC=$tld" -LinkEnabled Yes
Set-GPLink -Name "Core - Windows System: Powershell - Execution Policy to Allow Running Unsigned Scripts" -Target "OU=Domain Controllers,DC=$domain,DC=$tld" -LinkEnabled Yes


Write-Log "Configured security hardening steps from TB-230"

Write-Log "step04a.ps1 script complete"

exit
