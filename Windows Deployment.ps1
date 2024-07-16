<#
This script will install programs and make couple tweaks without user interaction

Before running this script I would HIGHLY RECOMMEND to check the contents of this script and
apps.json file and modify it to your needs

Parts of the code have been copied from https://github.com/ChrisTitusTech/winutil
#>

# Relaunch the script with administrator privileges
function relaunchAsAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-Output "This script requires administrator acces"
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}

function checkWingetInstallStatus {
    Write-Host "Checking if Winget is Installed..."
    if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe) {
        #Checks if winget executable exists and if the Windows Version is 1809 or higher
        Write-Host "Winget Already Installed"
    }
    else {
        if (((((Get-ComputerInfo).OSName.IndexOf("LTSC")) -ne -1) -or ((Get-ComputerInfo).OSName.IndexOf("Server") -ne -1)) -and (((Get-ComputerInfo).WindowsVersion) -ge "1809")) {
            #Checks if Windows edition is LTSC/Server 2019+
            #Manually Installing Winget
            Write-Host "Running Alternative Installer for LTSC/Server Editions"

            #Download Needed Files
            Write-Host "Downloading Needed Files..."
            Start-BitsTransfer -Source "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -Destination "./Microsoft.VCLibs.x64.14.00.Desktop.appx"
            Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.2.10271/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination "./Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.2.10271/b0a0692da1034339b76dce1c298a1e42_License1.xml" -Destination "./b0a0692da1034339b76dce1c298a1e42_License1.xml"

            #Installing Packages
            Write-Host "Installing Packages..."
            Add-AppxProvisionedPackage -Online -PackagePath ".\Microsoft.VCLibs.x64.14.00.Desktop.appx" -SkipLicense
            Add-AppxProvisionedPackage -Online -PackagePath ".\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -LicensePath ".\b0a0692da1034339b76dce1c298a1e42_License1.xml"
            Write-Host "winget Installed (Reboot might be required before winget will work)"

            #Sleep for 5 seconds to maximize chance that winget will work without reboot
            Write-Host "Pausing for 5 seconds to maximize chance that winget will work without reboot"
            Start-Sleep -s 5

            #Removing no longer needed Files
            Write-Host "Removing no longer needed Files..."
            Remove-Item -Path ".\Microsoft.VCLibs.x64.14.00.Desktop.appx" -Force
            Remove-Item -Path ".\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Force
            Remove-Item -Path ".\b0a0692da1034339b76dce1c298a1e42_License1.xml" -Force
            Write-Host "Removed Files that are no longer needed"
        }
        elseif (((Get-ComputerInfo).WindowsVersion) -lt "1809") {
            #Checks if Windows Version is too old for winget
            Write-Host "Winget is not supported on this version of Windows (Pre-1809)"
        }
        else {
            #Installing Winget from the Microsoft Store
            Write-Host "Winget not found, installing it now."
            Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
            $nid = (Get-Process AppInstaller).Id
            Wait-Process -Id $nid
            Write-Host "Winget Installed"
        }
    }
}

function InstallLinuxSubsystem {
    # Installing Linux subsystem for Windows
    Write-Output "Installing Linux Subsystem..."
        If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
            # 1607 needs developer mode to be enabled
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
        }
        Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Installing software
    Write-Output "Starting to install software. This might take a while"
    Write-Output " "

# Applications that will be installed can be modified from apps.json file
# Modify apps.json for your needs
    winget import $PSScriptRoot/apps.json
    #winget import $PSScriptRoot/apps.json  # You can also add other app lists here

# Windows tweaks
    winget uninstall "windows web experience pack" # Removing windows web experience pack aka. widgets

# Pinning apps that I don't want to update automatically
    winget pin add Microsoft.PowerToys --blocking --force  # This blocks PowerToys from updating. This prevents features from breaking.
    winget pin add Oracle.VirtualBox --blocking --force  # This blocks VirtualBox from updating. This prevents features from breaking.

# Actually running the script
    relaunchAsAdmin
    checkWingetInstallStatus
    InstallLinuxSubsystem

    Write-Output " "
    Write-Output "Software installation is done. Please check if everything is installed correctly"
    Write-Output "`nPress any key to continue..."
	[Console]::ReadKey($true) | Out-Null