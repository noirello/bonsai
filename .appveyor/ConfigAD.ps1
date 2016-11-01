Get-ADRootDSE

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
Import-module "ActiveDirectory"
$Acl = Get-Acl "ad:dc=bonsai,dc=test"
$SelfSid = [System.Security.Principal.SecurityIdentifier]"S-1-5-10"
$Self = [System.Security.Principal.IdentityReference] $SelfSid
$ADRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
$Type = [System.Security.AccessControl.AccessControlType] "Allow"
$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Self,$ADRights,$Type,$InheritanceType
$Acl.AddAccessRule($Ace)
Set-acl -aclobject $Acl "ad:dc=bonsai,dc=test"

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