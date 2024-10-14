$ADRoot = (Get-ADDomain).DistinguishedName
$ADName = (Get-ADDomain).Name

#Map the HackMe share drive to Z as The Flag
[string]$userName = "$ADName\The.Flag"
[string]$userPassword = 'THM{Hidden_In_Plain_Sight}'
# Convert to SecureString
[securestring]$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
[pscredential]$FlagCredObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)

Install-Module -Name CredentialManager -Confirm -Force -SkipPublisherCheck
Start-Sleep -Seconds 60
New-StoredCredential -Comment "Access share drvie on Lab-DC" -Credentials $FlagCredObject -Target "Lab-DC" -Persist Enterprise

Get-ADUser "Bill.Lumbergh" | Set-ADAccountControl -DoesNotRequirePreAuth $true