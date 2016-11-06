Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature -Name DNS
Install-WindowsFeature -Name AD-Certificate
Import-Module ADDSDeployment

openssl pkcs12 -export -in ./tests/testenv/certs/cacert.pem -inkey ./tests/testenv/certs/cacert.key -out ./cacert.p12 -name OwnCARootCert  -passin pass:p@ssword -passout pass:p@ssword

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