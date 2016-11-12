Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature -Name DNS
Import-Module ADDSDeployment

# Import Root CA.
Import-Certificate \
    -CertStoreLocation Cert:\LocalMachine\Root `
    -FilePath .\tests\testenv\certs\cacert.pem

# Generate a new server cert and accept it.
certreq -new .\.appveyor\request.info server.csr
openssl x509 -req -days 3650 -in server.csr `
    -CA .\tests\testenv\certs\cacert.pem `
    -CAkey .\tests\testenv\certs\cacert.key `
    -extfile .\.appveyor\v3ext.txt `
    -set_serial 01 -out server.crt `
    -passin pass:p@ssword
openssl x509 -in server.crt -text
certreq -accept server.crt

# Install Active Directory.
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