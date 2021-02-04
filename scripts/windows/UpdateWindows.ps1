$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "Stop"


Write-Host "Installing PSWindowsUpdate Module..."
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Install-Module PSWindowsUpdate
Import-Module PSWindowsUpdate

Write-Host "Enabling Microsoft Update on the host"
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false -Silent

Write-Host "Installing updates on the host"
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot

Write-Host "Host upgraded!"
