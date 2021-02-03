<powershell>

# specify the execution policy fo thte script
Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction Ignore

# stop if there is an error
$ErrorActionPreference = "stop"

# remove the http listener
Remove-WSManInstance -ResourceUri winrm/config/Listener -SelectorSet @{Address="*";Transport="http"}

# create a self signed certificate
$LocalIp = (invoke-webrequest http://169.254.169.254/latest/meta-data/local-ipv4 -UseBasicParsing).content
$LocalDnsName = (invoke-webrequest http://169.254.169.254/latest/meta-data/local-hostname -UseBasicParsing).content
$PublicIp = (invoke-webrequest http://169.254.169.254/latest/meta-data/public-ipv4 -UseBasicParsing).content
$PublicDnsName = (invoke-webrequest http://169.254.169.254/latest/meta-data/public-hostname -UseBasicParsing).content

$Cert = New-SelfSignedCertificate -DnsName $PublicDnsName,$LocalDnsName,$PublicIp,$LocalIp -CertstoreLocation Cert:\LocalMachine\My

# seed winrm with basic configuration
Set-WSManQuickConfig -Force

# set specific parameters
Set-WSManInstance -ResourceURI WinRM/Config/Winrs -ValueSet @{MaxMemoryPerShellMB = "1024"}
Set-WSManInstance -ResourceURI WinRM/Config/Service -ValueSet @{AllowUnencrypted = "false"}
Set-WSManInstance -ResourceURI WinRM/Config/Client -ValueSet @{AllowUnencrypted = "false"}
Set-WSManInstance -ResourceURI WinRM/Config/Service -ValueSet @{AllowUnencrypted = "false"}
Set-WSManInstance -ResourceURI WinRM/Config/Client/Auth -ValueSet @{Basic = "true"}
Set-WSManInstance -ResourceURI WinRM/Config/Service/Auth -ValueSet @{Basic = "true"}
Set-WSManInstance -ResourceURI WinRM/Config/Service/Auth -ValueSet @{CredSSP = "true"}

# remove the http listener
Remove-WSManInstance -ResourceUri "winrm/config/Listener" -SelectorSet @{Address="*";Transport="http"}

# configure the listener
$listener = @{
    ResourceURI = "winrm/config/Listener"
    SelectorSet = @{Address="*";Transport="HTTPS"}
    ValueSet = @{CertificateThumbprint=$Cert.Thumbprint}
}
New-WSManInstance @listener

# list listeners
Get-WSManInstance -ResourceUri "winrm/config/Listener" -Enumerate

# create firewall rule for the listener
$rule = @{
    Name = "WINRM-HTTPS-In-TCP-v2"
    DisplayName = "Windows Remote Management (HTTPS-In)"
    Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]"
    Enabled = "true"
    Direction = "Inbound"
    Profile = "Any"
    Action = "Allow"
    Protocol = "TCP"
    LocalPort = "5986"
}
New-NetFirewallRule @rule

Get-WSManInstance -ResourceUri "winrm/config/Listener" -Enumerate

</powershell>
