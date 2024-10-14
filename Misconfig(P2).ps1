Import-Module ActiveDirectory
Set-Location AD:
$ADRoot = (Get-ADDomain).DistinguishedName

# --- First DACL hop ---
#Set smartcard logon required on Helpdesk Tier II
#Delegate Helpdesk password reset & re-enable on the Helpdesk OU. This includes Helpdesk Tier 2

#Give a group Password reset & re-enable over a given OU
$victim = (Get-ADOrganizationalUnit "ou=User_Accounts,$ADRoot" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity "Helpdesk Tier I").SID
#Allow specific password reset
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"ExtendedRight","ALLOW",([GUID]("00299570-246d-11d0-a768-00aa006e0529")).guid,"Descendents",([GUID]("bf967aba-0de6-11d0-a285-00aa003049e2")).guid))
#Allow specific WriteProperty on the Enabled attribute
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteProperty","ALLOW",([GUID]("a8df73f2-c5ea-11d1-bbcb-0080c76670c0")).guid,"Descendents",([GUID]("bf967aba-0de6-11d0-a285-00aa003049e2")).guid))
#Apply above ACL rules
Set-ACL $victim $acl

#Give a group Password reset & re-enable over a given OU
$victim = (Get-ADOrganizationalUnit "ou=Helpdesk,$ADRoot" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity "Helpdesk Tier I").SID
#Allow specific password reset
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"ExtendedRight","ALLOW",([GUID]("00299570-246d-11d0-a768-00aa006e0529")).guid,"Descendents",([GUID]("bf967aba-0de6-11d0-a285-00aa003049e2")).guid))
#Allow specific WriteProperty on the Enabled attribute
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteProperty","ALLOW",([GUID]("a8df73f2-c5ea-11d1-bbcb-0080c76670c0")).guid,"Descendents",([GUID]("bf967aba-0de6-11d0-a285-00aa003049e2")).guid))
#Apply above ACL rules
Set-ACL $victim $acl

#Throw a curveball though, set smartcard login required on all Helpdesk Tier II members
$T2Members = (Get-ADGroupMember "Helpdesk Tier II").SamAccountName
ForEach ($T2Member in $T2Members)
{
Set-ADUser $T2Member -SmartcardLogonRequired $true
}


# --- Next hop, Helpdesk Tier II (Frisky.McRisky) to SQL Admins ---
#Delegate Helpdesk Tier II the Self Right on SQL Admins
#Delegate SQL Admins GenericAll on itself, aka make it 'self managing'

#Allow Self with specific GUID
$victim = (Get-ADGroup "SQL Admins" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity "Helpdesk Tier II").SID
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"Self","ALLOW",([GUID]("bf9679c0-0de6-11d0-a285-00aa003049e2")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rule
Set-ACL $victim $acl

#Make SQL Admins "self managing", aka give the group GenericAll on itself
$victim = (Get-ADGroup "SQL Admins" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup "SQL Admins").SID
#Allow specific WriteProperty 'Membership'
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"GenericAll","ALLOW",([GUID]("00000000-0000-0000-0000-000000000000")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rules
Set-ACL $victim $acl


# --- Next hop, SQL Admins to Server Admins ---
#Deny CTRs GenericAll on Server Admins
#Delegate SQL Admins WriteProperty Membership Set on both CTRs and Server Admins

New-ADGroup -GroupScope Universal -GroupCategory Security -Name "CTRs" -SamAccountName "CTRs" -Path "ou=User_Accounts,$ADRoot"
Add-ADGroupMember -Identity "CTRs" -Members "SQL Admins"

$victim = (Get-ADGroup "Server Admins" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup "SQL Admins").SID
#Allow specific WriteProperty 'Membership'
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteProperty","ALLOW",([GUID]("bc0ac240-79a9-11d0-9020-00c04fc2d4cf")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rules
Set-ACL $victim $acl

$victim = (Get-ADGroup "CTRs" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup "SQL Admins").SID
#Allow specific WriteProperty 'Membership'
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteProperty","ALLOW",([GUID]("bc0ac240-79a9-11d0-9020-00c04fc2d4cf")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rules
Set-ACL $victim $acl

$victim = (Get-ADGroup "Server Admins" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup "CTRs").SID
#Deny  GenericAll
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteProperty","DENY",([GUID]("00000000-0000-0000-0000-000000000000")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rules
Set-ACL $victim $acl


# --- Next hop, Server Admins to Server Admins T2 ---
#Delegate Server Admins WriteOwner on Server Admins T2
$victim = (Get-ADGroup "Server Admins T2" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup "Server Admins").SID
#Allow specific WriteProperty 'Membership'
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteOwner","ALLOW",([GUID]("00000000-0000-0000-0000-000000000000")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteDACL","ALLOW",([GUID]("00000000-0000-0000-0000-000000000000")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rules
Set-ACL $victim $acl


# --- Last hop, Server Admins T2 to AD Admins ---

#Deny Domain Users WriteProperty on AD Admins
$victim = (Get-ADGroup "AD Admins" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup "Domain Users").SID
#Deny  GenericAll
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteProperty","DENY",([GUID]("00000000-0000-0000-0000-000000000000")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rules
Set-ACL $victim $acl

#Make Server Admins T2 "self managing", aka give the group GenericAll on itself
$victim = (Get-ADGroup "Server Admins T2" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup "Server Admins T2").SID
#Allow specific WriteProperty 'Membership'
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"GenericAll","ALLOW",([GUID]("00000000-0000-0000-0000-000000000000")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rules
Set-ACL $victim $acl

#Delegate Server Admins T2 WriteDACL on AD Admins
$victim = (Get-ADGroup "AD Admins" -Properties *).DistinguishedName
$acl = Get-ACL $victim
$user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup "Server Admins T2").SID
#Allow specific WriteProperty 'Membership'
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user,"WriteDACL","ALLOW",([GUID]("00000000-0000-0000-0000-000000000000")).guid,"None",([GUID]("00000000-0000-0000-0000-000000000000")).guid))
#Apply above ACL rules
Set-ACL $victim $acl

#Put Server Admins T2 in Account Operators
Add-ADGroupMember -Identity "CTRs" -Members "Helpdesk Tier I", "Helpdesk Tier II"