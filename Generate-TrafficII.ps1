#Run this on as a schedulted task to simulate a user fat fingering a share drive
#Please note that the user must have 'log on as a batch job' rights
#On Kali: sudo responder -I eth0 -dwv

$X = 0
Do
{
Get-Content "\\NoExist\C$"
Start-Sleep -Seconds 60
$X = $X + 1
}
While($X -le 60)