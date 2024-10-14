$ADRoot = (Get-ADDomain).DistinguishedName
$ADName = (Get-ADDomain).Name

#Create a share folder, drop Admin Notes in it, and set permissions
Expand-Archive "C:\Share\AdminStuff\TODO.zip" -DestinationPath "C:\Share\AdminStuff"
Expand-Archive "C:\Share\ManageAD\ShareDriveFiles.zip" -DestinationPath "C:\Share\ManageAD"
Remove-Item "C:\Share\AdminStuff\TODO.zip"
Remove-Item "C:\Share\ManageAD\ShareDriveFiles.zip"
Remove-Item "C:\Users.csv"
Clear-RecycleBin -Force
Grant-SmbShareAccess -Name "Share" -AccountName "$ADName\AD Admins" -AccessRight Full -Force

$ACL = Get-Acl -Path "C:\Share\AdminStuff\Admin_Stuff.txt"
#Disable inheritance 
$ACL.SetAccessRuleProtection($true,$false)
#Add AD Admins with read rights
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$ADName\AD Admins","ReadPermissions,TakeOwnership,ChangePermissions","Allow")
#Allow FullControl for Lab\Administrators
$AccessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Builtin\Administrators","FullControl","Allow")
#Remove Lab\Users read rights
$AccessRule3 = New-Object System.Security.AccessControl.FileSystemAccessRule("Builtin\Users","Read","Allow")
$AccessRule4 = New-Object System.Security.AccessControl.FileSystemAccessRule("Builtin\Users","ReadPermissions","Allow")

#Apply the above
$ACL.SetAccessRule($AccessRule)
$ACL.SetAccessRule($AccessRule2)
$ACL.RemoveAccessRule($AccessRule3)
$ACL.SetAccessRule($AccessRule4)
$ACL | Set-Acl -Path "C:\Share\AdminStuff\Admin_Stuff.txt"

#Simulate a fat fingered user
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskAction = New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\Scripts\Generate-TrafficII.ps1"
Register-ScheduledTask 'Fat Finger the Share name' -Action $taskAction -Trigger $taskTrigger -User "$ADName\Bill.Lumbergh" -Password 'Password12' -RunLevel Highest