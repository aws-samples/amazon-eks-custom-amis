$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "Stop"

Write-Host "Current Docker Version:"
docker version

Write-Host "Updating Mirantis Container Runtime..."
Invoke-WebRequest -Uri https://get.mirantis.com/install.ps1 -o DockerInstall.ps1
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Scope Process
.\DockerInstall.ps1

Write-Host "New Docker Version:"
docker version

Write-Host "Mirantis container runtime updated!"
