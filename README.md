get-RogueAdmins

## Synopsis

This script will identify unauthorized accounts added to "important" Active Directory groups. It can also be used to automate remediation for non-authenticated additions. 

## Motivation

This is a re-write and expansion of code I have written for a couple of other environments. Monitoring membership in important groups is just good security. The automated remediation comes out of red team experiences. 
I hope this will help others to improve their monitoring of risky groups in Active Directory.

## Installation

This is a simple linear script. It can be run from PowerShell by simply calling the script. In production it should be run as a recurring scheduled task at least every few minutes. 
This script should be scheduled to run regularly (every few minutes at most).
The service account that is used for this account must be delegated elevated privileges on AD objects to disable accounts and remove group membership. Only those rights should be granted.
If automated remediation is not used (alert only) a standard domain user will have sufficient permissions to read the AD objects unless Active Directory permissions have been modified. 
The allowed.csv file needs to reside in the same folder as the script. This is where you define what users are allowed to be in "important" groups and what those groups are. Once you add a single user with a group all other users in that group will be considered rogue so all users who are allowed in a group must be defined when adding a new group. 
The included sample allowed.csv includes some examples of groups you may want to monitor but is far from complete. In addition my SIDs will need to be replaces with your own. 

## Description 

This script takes an input file to identify monitored groups. 
If users have been added the script will compare current group members to an allowed list of accounts for that group.
Based on the comparison, the group will take actions on unauthorized account additions. 
Account actions are configurable.

## To do

I uses SIDs to assure there would be no matching errors. This is kind of a pain when updating the allowed.csv file. I may add a script to edit the allowed.csv file later. 
I do not have an SMTP relay to test with in my home lab so while I believe the email code is correct it is un-tested. If you try this please let me know. 
In a perfect world, this would generate tickets when rogues are found. I don't have a ticketing system to test against in my home lab so that will require someone else picking up the ball. 

## Known bugs

None

## Contributors

If you would like to provide bug fixes or enhancements please send me an email or a pull request. 
If you have ideas for further enhancements feel free to email me. Time and ability permitting I will consider enhancement requests.

## License

BSD 3-Clause License
