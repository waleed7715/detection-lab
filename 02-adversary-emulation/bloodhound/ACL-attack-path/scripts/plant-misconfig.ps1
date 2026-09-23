# Create a realistic named Domain Admin to be the target
$pw = ConvertTo-SecureString 'W1nter!Adm1n2026#' -AsPlainText -Force

New-ADUser `
  -Name 'dadmin' `
  -SamAccountName 'dadmin' `
  -UserPrincipalName 'dadmin@soc.lab' `
  -Path 'OU=Users,OU=SOCLab,DC=soc,DC=lab' `
  -AccountPassword $pw `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -Description 'Domain administrator account'

# make it Domain Admin
Add-ADGroupMember -Identity 'Domain Admins' -Members 'dadmin'

# Verify
Get-ADUser dadmin | Format-List Name,SamAccountName,Enabled
Get-ADGroupMember 'Domain Admins' | Select-Object name

# Misconfiguration: grant the Helpdesk GROUP ForceChangePassword over dadmin
$helpdesk = Get-ADGroup 'Helpdesk'
$targetDN = (Get-ADUser dadmin).DistinguishedName
$acl = Get-Acl "AD:$targetDN"

# ForceChangePassword extended right GUID
$forceChangePwGuid = [GUID]'00299570-246d-11d0-a768-00aa006e0529'

$sid = New-Object System.Security.Principal.SecurityIdentifier $helpdesk.SID
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $forceChangePwGuid
)

$acl.AddAccessRule($ace)
Set-Acl -Path "AD:$targetDN" -AclObject $acl

(Get-Acl "AD:$targetDN").Access |
  Where-Object { $_.ObjectType -eq $forceChangePwGuid } |
  Format-List IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType


  