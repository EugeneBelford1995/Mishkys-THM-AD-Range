#This is just a sanity check. Run it after all the configs if you are doubting that something took.

Import-Module ActiveDirectory
Set-Location AD:
$ADRoot = (Get-ADDomain).DistinguishedName

Write-Host "--- only ManageAD & Administrators should have read access. ManageAD should be Kerberoastable ---"
(Get-Acl "C:\Share\ManageAD").Access
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties * | Select-Object SamAccountName, Description, ServicePrincipalName | Format-Table

Write-Host "--- Helpdesk Tier I should have password reset rights. Frisky.McRisky = smartcardlogonrequired, Bill.Lumbergh = ASREPRoastable ---"
(Get-Acl (Get-ADOrganizationalUnit "ou=Helpdesk,$ADRoot" -Properties *).DistinguishedName).Access | Where-Object {$_.IdentityReference -like "*Helpdesk Tier I*"}
Get-ADUser -Filter * -Properties * | Select-Object SamAccountName, Description, SmartcardLogonRequired, DoesNotRequirePreAuth | Format-Table

Write-Host "--- Helpdesk Tier II should have Self with the Member attribute. SQL Admins = self managing. ---"
(Get-Acl (Get-ADGroup "SQL Admins" -Properties *).DistinguishedName).Access | Where-Object {($_.IdentityReference -like "*Helpdesk Tier II*") -or ($_.IdentityReference -like "*SQL Admins*")}

Write-Host "--- SQL Admins should have WriteProperty Membership Set on Server Admins & CTRs ---"
(Get-Acl (Get-ADGroup "Server Admins" -Properties *).DistinguishedName).Access | Where-Object {($_.IdentityReference -like "*SQL Admins*") -or ($_.IdentityReference -like "*CTRs*")}
(Get-Acl (Get-ADGroup "Server Admins" -Properties *).DistinguishedName).Access | Where-Object {$_.IdentityReference -like "*SQL Admins*"}

Write-Host "--- Server Admins should have WriteOwner & WriteDACL ---"
(Get-Acl (Get-ADGroup "Server Admins T2" -Properties *).DistinguishedName).Access | Where-Object {$_.IdentityReference -like "*Server Admins*"}

Write-Host "--- Server Admins T2 should have WriteDACL, Domain Users are Denied WriteProperty ---"
(Get-Acl (Get-ADGroup "AD Admins" -Properties *).DistinguishedName).Access | Where-Object {($_.IdentityReference -like "*Server Admins T2*") -or ($_.IdentityReference -like "*Domain Users*")}

Write-Host "--- AD Admins should have ModifyOwner & ModifyPermissions. The.Flag should be in credman ---"
(Get-Acl "C:\Share\AdminStuff\Admin_Stuff.txt").Access

Get-StoredCredential