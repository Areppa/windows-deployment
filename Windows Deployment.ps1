<#
This script will install programs and make couple tweaks without user interaction

Before running this script I would HIGHLY RECOMMEND to check the contents of this script and
apps.json file and modify it to your needs

Parts of the code have been copied from https://github.com/ChrisTitusTech/winutil
#>

function relaunchAsAdmin {
    # Relaunching script as admin if it's not already running as admin
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-Output "This script requires administrator access"
        Start-Process wt -ArgumentList "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}

function createRestorePoint {
    # Creating restore point
    Write-Output "`nCreating restorepoint incase something bad happens"
        Enable-ComputerRestore -Drive "C:\"
        Checkpoint-Computer -Description "Windows Deployment Script" -RestorePointType "MODIFY_SETTINGS"
}

function checkWingetInstallStatus {
    # Checking if winget is installed and installing it if it's not

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

function installLinuxSubsystem {
    # Installing Linux subsystem for Windows
    Write-Output "Installing Linux Subsystem..."
        If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
            # 1607 needs developer mode to be enabled
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
        }
        Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

function installSoftware {
    # Installing software
        Write-Output "`nStarting to install software. This might take a while"
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

    Write-Output " "
    Write-Output "Software installation is done. Please check if everything is installed correctly"
}

function runOOSU {
    # Running O&O ShutUp10 with specific settings
    Import-Module BitsTransfer
    
    Write-Output "`nDownloading O&O ShutUp10 configuration file"
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/Areppa/windows-deployment/dev/ooshutup10.cfg" -Destination ooshutup10.cfg
    Write-Output "Downloading O&O ShutUp10"
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
    
    Write-Output "Running O&O ShutUp10 with custom settings"
    ./OOSU10.exe ooshutup10.cfg /quiet
}

function disableTelemetry {

	# GENERAL TELEMETRY
	Write-Output "`nDisabling Telemetry..."
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

	# APPLICATION TELEMETRY
	Write-Output "Disabling Activity History..." # Disable Activity History feed in Task View
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

	# CLOUD CONTENT
	Write-Output "Disabling Cloud Content..."
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

	# TAILORED EXPERIENCES
	Write-Output "Disabling Tailored Experiences..."
		If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
			New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

	# LOCATION & MAPS
	Write-Output "Disabling Location Tracking..."
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

	Write-Output "Disabling automatic Maps updates..."
		Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

	# FEEDBACK
	Write-Output "Disabling Feedback..."
		If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
			New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

	# ADVERITISING
	Write-Output "Disabling Advertising ID..."
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

	# ERROR REPORTING
	Write-Output "Disabling Error reporting..."
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
		Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null


	# REMOVE ONLINE RESULTS FROM SEARCH
	Write-Output "Removing online results from search..."
		If (!(Test-Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer')) {
			New-Item -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer' -Force | Out-Null
		}
		New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer' -Name 'DisableSearchBoxSuggestions' -Type DWord -Value 1 -Force
		Stop-Process -name explorer -force
}

function serviceTweaks {

	# AUTO RESTART
	Write-Output "Disabling Windows Update automatic restart..."
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0


	# HIBERNATION
	Write-Output "Disabling Hibernation..."
		Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

	# FAST STARTUP
	Write-Output "Enabling Fast Startup..."
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1

	# DIAGNOSTIC TRACKING
	Write-Output "Stopping and disabling Diagnostics Tracking Service..."
		Stop-Service "DiagTrack" -WarningAction SilentlyContinue
		Set-Service "DiagTrack" -StartupType Disabled

	# Disabling Windows Recall
	Write-Output "Trying to disable Windows Recall..."
		Dism /Online /Disable-Feature /Featurename:Recall

	# OTHER SERVICES
	Write-Output "Stopping and disabling WAP Push Service..."
		Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
		Set-Service "dmwappushservice" -StartupType Disabled

	Write-Output "Stopping and disabling Superfetch service..."
		Stop-Service "SysMain" -WarningAction SilentlyContinue
		Set-Service "SysMain" -StartupType Disabled

	Write-Output "Enabling Audio..."
		Set-Service "Audiosrv" -StartupType Automatic
		Start-Service "Audiosrv" -WarningAction SilentlyContinue

	# INSTALLING PRINT TO PDF
	Write-Output "Installing Microsoft Print to PDF..."
		Enable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null

}

function appTweaks {

	# WINDOWS SETTINGS
	Write-Output "Enabling F8 boot menu options..."
		bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

	Write-Output "Enabling NumLock after startup..."
		If (!(Test-Path "HKU:")) {
			New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
		}
		Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
		Add-Type -AssemblyName System.Windows.Forms
		If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
			$wsh = New-Object -ComObject WScript.Shell
			$wsh.SendKeys('{NUMLOCK}')
		}

	# STICKY KEYS
	Write-Output "Disabling Sticky keys prompt..."
		Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

	# FILE OPERATIONS
	Write-Output "Showing file operations details..."
		If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
			New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

	Write-Output "Enabling file delete confirmation dialog..."
		If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1

	# FILE EXPLORER
	Write-Output "Showing known file extensions..."
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

	Write-Output "Changing default Explorer view to This PC..."
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

	Write-Output "Hiding This PC shortcut from desktop..."
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue

	Write-Output "Hiding User Folder shortcut from desktop..."
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue

	Write-Output "Enabling thumbnails..."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0

	Write-Output "Enable creation of Thumbs.db..."
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue

	# TASKBAR
	Write-Output "Hiding Task View button..."
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
	Write-Output "Hiding People icon..."
		If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
			New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
		}
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
	#Write-Output "Hide tray icons..."
	#	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 1

	# APP SUGGESTIONS & AUTO-INSTALL
	Write-Output "Disabling Application suggestions..."
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

	# APPLICATION BACKGROUND ACCESS
	# Disable Background application access - ie. if apps can download or update when they aren't used - Cortana is excluded as its inclusion breaks start menu search
	Write-Output "Disabling Background application access..."
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
			Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
			Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
		}
		
}

function uninstallBloatware {
    # Uninstalling bloatware
	Write-Output "Uninstalling default Microsoft applications..."
		Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
		Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage

	Write-Output "Uninstalling default third party applications..."
		Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
		Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
		Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
		Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
		Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
		Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
		Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
		Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
		Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
		Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
		Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
		Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
		Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
		Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
		Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
		Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
		Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
		Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
		Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
		Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
		Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
		Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
		Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
		Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
		Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
		Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
		Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
		Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
		Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage

	Write-Output "Disabling Xbox features..."
		Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
		Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
		Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
		Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0

	Write-Output "Removing Default Fax Printer..."
		Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue

	Write-Output "Uninstalling Microsoft XPS Document Writer..."
		Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null

}

function main {
    # SCRIPT BASICS
    relaunchAsAdmin
    createRestorePoint
    checkWingetInstallStatus
    
    # INSTALLING SOFTWARE
    installLinuxSubsystem
    installSoftware

    # TWEAKS
    runOOSU
    disableTelemetry
    serviceTweaks
    appTweaks
    uninstallBloatware

    Start-Sleep -Seconds 1
    Write-Output "`nScript has finished. Please restart your PC to apply all changes"
    Write-Output "Press any key to exit"
	[Console]::ReadKey($true) | Out-Null
}

main