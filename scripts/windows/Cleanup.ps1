
# specify the execution policy fo thte script
Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction Ignore

# stop if there is an error
$ErrorActionPreference = "stop"

# run ec2 prepare
C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\SendWindowsIsReady.ps1 -Schedule
C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\InitializeInstance.ps1 -Schedule
C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\SysprepInstance.ps1 -NoShutdown

# remove the wsman listener and cleanup firewall rule
Remove-WSManInstance -ResourceUri "winrm/config/Listener" -SelectorSet @{Address="*";Transport="https"}
Remove-NetFirewallRule -Name "WINRM-HTTPS-In-TCP-v2"
