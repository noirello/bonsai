Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature -Name DNS
Import-Module ADDSDeployment

$Pwd = ConvertTo-SecureString 'P@ssw0rd1' -AsPlainText -Force
Install-ADDSForest `
    -DomainName bonsai.test `
    -DomainNetbiosName BONSAI `
    -ForestMode Win2012R2 `
    -InstallDns:$true `
    -NoRebootOnCompletion:$true `
    -CreateDnsDelegation:$false `
    -SafeModeAdministratorPassword $Pwd `
    -Force 

Write-Host 'Rebooting...'

Restart-Computer -Force
Start-Sleep -s 5

Write-Host 'Finished installing Active Directory.'