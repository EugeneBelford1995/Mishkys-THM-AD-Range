# Mishkys-THM-AD-Range
Configs we used to create an AD focused room on TryHackMe

TryHackMe only allows one VM, so I created a duct tape solution; one DC with an escalation path configured in it so a student can go from LAN access to Domain Admin.

This setup stresses Name Poisoning, ASREPRoasting, share drive enumeration, scraping share drives for creds, password spraying, AD & NTFS DACL enumertaion & abuse, and credentail dumping.

The Zip files go on the share drive under C:\Share\ManageAD & C:\Share\AdminStuff. Notes.txt goes C:\Share. Generate-TrafficII.ps1 goes under C:\Scripts.

Group Policy has to be set as shown in the *.jpg as some Domain Users have to be able to login to the DC for the duct tape solution to work.

It's a dumb solution, but it's just about the only way to put it on TryHackMe. If you want to use a more elegate solution than check out Mishky's AD Range in our other repo.
