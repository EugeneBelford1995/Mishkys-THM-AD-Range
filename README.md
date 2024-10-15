# Mishkys-THM-AD-Range
Configs we used to create an AD focused room on TryHackMe

TryHackMe only allows one VM, so I created a duct tape solution; one DC with an escalation path configured in it so a student can go from LAN access to Domain Admin.

This setup stresses Name Poisoning, ASREPRoasting, share drive enumeration, scraping share drives for creds, password spraying, AD & NTFS DACL enumertaion & abuse, and credentail dumping.

The Zip files go on the share drive under C:\Share\ManageAD & C:\Share\AdminStuff. Notes.txt goes C:\Share. Generate-TrafficII.ps1 goes under C:\Scripts.

