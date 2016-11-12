Import-module "ActiveDirectory"

Get-ADRootDSE

# Set a default password policy similar to the OpenLDAP testenv.
Set-ADDefaultDomainPasswordPolicy `
    -Identity bonsai.test `
    -LockoutDuration 00:00:05 `
    -LockoutObservationWindow 00:00:00 `
    -LockoutThreshold 2 `
    -ComplexityEnabled $false `
    -ReversibleEncryptionEnabled $true `
    -MaxPasswordAge 0.00:00:10 `
    -MinPasswordAge 0.00:00:00 `
    -MinPasswordLength 8 `
    -PasswordHistoryCount 1

# Set full control for self ace.
$Acl = Get-Acl "ad:dc=bonsai,dc=test"
$SelfSid = [System.Security.Principal.SecurityIdentifier]"S-1-5-10"
$Self = [System.Security.Principal.IdentityReference] $SelfSid
$ADFullRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
$Type = [System.Security.AccessControl.AccessControlType] "Allow"
$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Self,$ADFullRights,$Type,$InheritanceType
$Acl.AddAccessRule($Ace)
Set-Acl -aclobject $Acl "ad:dc=bonsai,dc=test"

# Set read access for everyone.
$EveryoneSid = [System.Security.Principal.SecurityIdentifier]"S-1-1-0"
$Everyone = [System.Security.Principal.IdentityReference] $EveryoneSid
$ADReadRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericRead"
$Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Everyone,$ADReadRights,$Type,$InheritanceType
$Acl.AddAccessRule($Ace)
Set-Acl -aclobject $Acl "ad:dc=bonsai,dc=test"

# Set read access for anonymus.
$AnonymSid = [System.Security.Principal.SecurityIdentifier]"S-1-5-7"
$Anonym = [System.Security.Principal.IdentityReference] $AnonymSid
$Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Anonym,$ADReadRights,$Type,$InheritanceType
$Acl.AddAccessRule($Ace)
Set-Acl -aclobject $Acl "ad:dc=bonsai,dc=test"

# Create new admin user.
$Pwd = ConvertTo-SecureString 'p@ssword' -AsPlainText -Force
New-ADUser `
    -Name admin `
    -PasswordNeverExpires $true `
    -DisplayName admin `
    -SamAccountName admin `
    -UserPrincipalName admin@bonsai.test `
    -Path "dc=bonsai,dc=test" `
    -AccountPassword $Pwd `
    -Enabled $true
Add-ADGroupMember "cn=Administrators,cn=Builtin,dc=bonsai,dc=test" admin
Add-ADGroupMember "cn=Domain Admins,cn=Users,dc=bonsai,dc=test" admin
Add-ADGroupMember "cn=Enterprise Admins,cn=Users,dc=bonsai,dc=test" admin

# Allow anonymus operations, set userPassword attribute and allow password change without secure conn.
$creds = New-Object System.Management.Automation.PSCredential ("admin", $Pwd)
Set-ADObject "cn=directory service,cn=windows nt,cn=services,cn=configuration,DC=bonsai,DC=test" `
    -Replace @{dsHeuristics="0000002011001"} `
    -Credential $creds

# Add organization unit and users with passwords.
New-ADOrganizationalUnit `
    -Name nerdherd `
    -Path "dc=bonsai,dc=test" `
    -ProtectedFromAccidentalDeletion $false
New-ADUser `
    -Name chuck `
    -GivenName "Chuck" `
    -Surname "Bartowski" `
    -PasswordNeverExpires $true `
    -DisplayName chuck `
    -SamAccountName chuck `
    -UserPrincipalName chuck@bonsai.test `
    -Path "ou=nerdherd,dc=bonsai,dc=test" `
    -AccountPassword $Pwd `
    -Enabled $true `
    -OtherAttributes @{'uidNumber'="0"}
New-ADUser `
    -Name jeff `
    -GivenName "Jeff" `
    -Surname "Barnes" `
    -PasswordNeverExpires $true `
    -DisplayName jeff `
    -SamAccountName jeff `
    -UserPrincipalName jeff@bonsai.test `
    -Path "ou=nerdherd,dc=bonsai,dc=test" `
    -AccountPassword $Pwd `
    -Enabled $true `
    -CannotChangePassword $true `
    -OtherAttributes @{'uidNumber'="2"}
New-ADUser `
    -Name skip `
    -GivenName "Michael" `
    -Surname "Johnson" `
    -PasswordNeverExpires $true `
    -DisplayName skip `
    -SamAccountName skip `
    -UserPrincipalName skip@bonsai.test `
    -Path "ou=nerdherd,dc=bonsai,dc=test" `
    -AccountPassword $Pwd `
    -Enabled $true `
    -OtherAttributes @{'uidNumber'="3"}

# Add SPNs for the server.
setspn -A ldap/bonsai.test appvyr-win
setspn -A HOST/bonsai.test appvyr-win