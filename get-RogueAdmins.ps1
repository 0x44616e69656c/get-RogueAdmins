<# .SYNOPSIS
	This script will identify unauthorized accounts added to "important" Active Directory groups. It can also be used to automate remediation for non-authenticated additions. 
.DESCRIPTION
    This script takes an input file to identify monitored groups. 
	If users have been added the script will compare current group members to an allowed list of accounts for that group.
	Based on the comparison, the group will take actions on unauthorized account additions. 
	Account actions are configurable.
    This script should be scheduled to run regularly (every few minutes at most).
    The service account that is used for this account must be delegated elevated privileges on AD objects to disable accounts and remove group membership. Only those rights should be granted.
    If automated remediation is not used (alert only) a standard domain user will have sufficient permissions to read the AD objects unless Active Directory permissions have been modified. 
.NOTES
	File Name  : get-RogueAdmins.ps1
	Author     : Daniel Owen - 0x44616e69656c -[AT]- danielowen.com
	First Release 	:	2017-10-29
	Most Recent Revision	:	2017-10-29
	Version 	:	1.0.0
.LINK
     https://github.com/0x44616e69656c
	 https://www.danielowen.com/
#>

#region User defined variables
#Feel free to change anything in this section as needed.
$allowed = Import-Csv '.\allowed.csv' #Path to file containing SIDs of users allowed to be a member of admin groups
$errorf = ".\logs\errors.txt"
$results = ".\logs\results.csv"
$removeGroups = 'y' #Do you want nested groups removed if they are not explicitly allowed. (This should typically be y.)
$removeUsers = 'y' #Remove the user from the group if they are not allowed. (This should typically be y.)
$disableAccount = 'y' #Disable any account that is added to a protected group when not allowed. (This should typically be y although this does create a bit of a DOS if an admin makes a mistake.)
$sendemail = 'y' #Send an email for each rogue user? An individual email will be sent for each rogue user.
$eSMTP = "smtp.example.com" #SMTP relay to send emails through
$efrom = "from@example.com" #Address to send from
$eto = "to@example.com" #Address to send to This should probably be a distribution list or could be a ticketing system.
#The subject and body can be edited at will. Use variables <group> and <sam> to stand in for the group being evaluated and the SAM account name respectively. 
#Other pseudo-variables include <RemovedFromGroup> and <DisabledAccount> which refer to whether the object was removed from the group and whether the account was disabled respectively. 
#These pseudo-variables will be substituted in the script. Standard PowerShell regex can also be used. 
$esubject = "Account <sam> was identified in the <group> group without authorization"
$ebodyuser = "Automated review of the <group> group found account <sam> had been added as a member. `r`nBased on configuration settings the following actions were taken.
`r`nRemove from Group: <RemovedFromGroup> `r`nDisable Account: <DisabledAccount>
`r`n`r`nIf <sam> should be a member of <group> this will need to be added to the get-RogueAdmins script configuration before adding <user> to the group.
`r`nIf this was not an authorized addition an investigation must be started." 
$ebodygroup = "Automated review of the <group> group found nested group <sam> had been added as a member. `r`nBased on configuration settings the following actions were taken.
`r`nRemove from Group: <RemovedFromGroup> 
`r`n`r`nIf <sam> group should be a member of <group> this will need to be added to the get-RogueAdmins script configuration before adding <user> to the group.
`r`nIf this was not an authorized addition an investigation must be started." 
 #endregion

###Do not change anything below unless you want to change the functionality of the script.###

#region Failsafe and setup steps
if ($allowed.count -eq 0) {exit} #Failsafe to kill the script if the text file does not contain any data or is not read for some reason.
$groups = $allowed.group | Sort-Object | Get-Unique #Create a unique list of groups in the configuration file
$problems = new-object -type System.Collections.ArrayList #Initialize array for problem objects
#endregion 

#region Setup an event source in the Application logs for this script. This allows for filtering in EventViewer or a log aggregator.
try{Get-EventLog -Newest 0 -LogName Application -Source 'get-RogueAdmins'} #Does the event log source already exist
catch{
    New-EventLog -LogName Application -Source 'get-RogueAdmins' #Create a new log source in the Application log
    Write-EventLog -LogName Application -Source 'get-RogueAdmins' -EntryType Information -EventId 0 -Message "Initializing get-RogueAdmins" #Initialize the new log time so the next try catch will find something
}
#endregion 

#region Inspect each member of each monitored group. 
foreach ($g in $groups) { # Loop through all the groups
    $members = $null
    try {$members = Get-ADGroupMember $g} #Make sure the group exists in AD.
    catch {
        "$(get-date)`tGroup $g is listed in the allowed.csv file but does not exist in Active Directory." | out-file -Encoding Ascii -append $errorf 
        Write-EventLog -LogName Application -Source 'get-RogueAdmins' -EntryType Information -EventId 3004 -Message "Group $g is listed in the allowed.csv file but does not exist in Active Directory."
    } #If the groups does not exist write error logs.
    if ($members -ne $null) { #Only run the test of membership if the group exists and has members. 
        $membersu = $null
        $membersg = $null
        $allowedmembers = $allowed -match $g #Create a list of allowed members for the current working group.
        $membersu = $members | Where-Object {$_.objectClass -eq 'user'}
        $membersg = $members | Where-Object {$_.objectClass -eq 'group'}

        #region Review users in the group.
        foreach ($m in $membersu) { #Evaluate each user object from the group
            if ($allowedmembers.SID -notcontains $m.SID.Value) { #Does the $allowed array contain the member of $g currently being compared? If not take action.
                if ($removeUsers -eq 'y') {
                    $RemovedFromGroup = "Success"
                    try {Remove-ADGroupMember -Identity $g -Members $m.SID.Value -Confirm:$false} #Remove account from the group.
                    catch {
                        $RemovedFromGroup = "Failed"
                        "$(get-date)`tFailed to remove $($m.distinguishedName) from $g" |out-file -Encoding Ascii -append $errorf 
                    }
                    $confirm = Get-ADGroupMember $g
                    if ($confirm.SID -contains $m.SID.Value) {$RemovedFromGroup = "Failed"}
                }
                else {$RemovedFromGroup = "Not Attempted"}
                
                $eventid = switch ($RemovedFromGroup) {
                    "Success" {"1001"}
                    "Failed" {"2001"}
                    "Not Attempted" {"3001"}
                    "default" {"9001"}
                }
                
                $eventtype = switch ($RemovedFromGroup) {
                    "Success" {"SuccessAudit"}
                    "Failed" {"Warning"}
                    "Not Attempted" {"Information"}
                    "default" {"FailureAudit"}
                }
                
                Write-EventLog -LogName Application -Source 'get-RogueAdmins' -EntryType $eventtype -EventId $eventid -Message "Attempted to remove $($m.distinguishedName) from $g with result $RemovedFromGroup"
            
                if ($disableAccount -eq 'y') {
                    $DisabledAccount = "Success"
                    try {Disable-ADAccount -Identity $m.SID.Value } #Disable the AD account that was added to group without permission. 
                    catch {
                        $DisabledAccount = "Failed"
                        "$(get-date)`t$($m.distinguishedName) is in $g. Failed to disable." | out-file -Encoding Ascii -append $errorf 
                    }
                    $confirm = Get-ADuser $m.SID.Value
                    if ($confirm.Enabled -eq $true) {$DisabledAccount = "Failed"}
                }
                else {$DisabledAccount = "Not Attempted"}

                $eventid = switch ($DisabledAccount) {
                    "Success" {"1002"}
                    "Failed" {"2002"}
                    "Not Attempted" {"3002"}
                    "default" {"9002"}
                }
                
                $eventtype = switch ($DisabledAccount) {
                    "Success" {"SuccessAudit"}
                    "Failed" {"Warning"}
                    "Not Attempted" {"Information"}
                    "default" {"FailureAudit"}
                }
                
                Write-EventLog -LogName Application -Source 'get-RogueAdmins' -EntryType $eventtype -EventId $eventid -Message "Attempted to disable $($m.distinguishedName) because it was in $g with result $DisabledAccount"
                $temp = New-Object System.Object
                $temp | Add-Member -type NoteProperty -Name "Group" -Value $g
                $temp | Add-Member -type NoteProperty -Name "SID" -Value $m.SID.Value
                $temp | Add-Member -type NoteProperty -Name "DN" -Value $m.distinguishedName
                $temp | Add-Member -type NoteProperty -Name "SamAccountName" -Value $m.SamAccountName
                $temp | Add-Member -type NoteProperty -Name "Time" -Value "$(Get-Date)"
                $temp | Add-Member -type NoteProperty -Name "RemovedFromGroup" -Value $RemovedFromGroup
                $temp | Add-Member -type NoteProperty -Name "DisabledAccount" -Value $DisabledAccount
                $problems += $temp
                $esubject1 = $esubject -replace "<group>","$g" -replace "<sam>",$($m.SamAccountName)
                $ebody1 = $ebodyuser -replace "<group>","$g" -replace "<sam>",$($m.SamAccountName) -replace "<RemovedFromGroup>","$RemovedFromGroup" -replace "<DisabledAccount>",$DisabledAccount
                Send-MailMessage -From $efrom -To $eto -subject $esubject1 -body "$ebody1" -SmtpServer $eSMTP
                Write-EventLog -LogName Application -Source 'get-RogueAdmins' -EntryType FailureAudit -EventId 9004 -Message "Sending email from get-RogueAdmins failed."
                Remove-Variable temp
                Remove-Variable ebody1
                Remove-Variable esubject1
            }
        }
        #endregion Review users in the group.

        #region Review nested groups in the group.
        foreach ($m in $membersg) { #Evaluate each user object from the group
            if ($allowedmembers.SID -notcontains $m.SID.Value) { #Does the $allowed array contain the member of $g currently being compared? If not take action.
                if ($removeGroups -eq 'y') {
                    $RemovedFromGroup = "Success"
                    try {Remove-ADGroupMember -Identity $g -Members $m.SID.Value -Confirm:$false} #Remove account from the group.
                    catch {
                        $RemovedFromGroup = "Failed"
                        "$(get-date)`tFailed to remove $($m.distinguishedName) from $g" |out-file -Encoding Ascii -append $errorf 
                    }
                    $confirm = Get-ADGroupMember $g
                    if ($confirm.SID -contains $m.SID.Value) {$RemovedFromGroup = "Failed"}
                }
                else {$RemovedFromGroup = "Not Attempted"}
            
                $eventid = switch ($RemovedFromGroup) {
                    "Success" {"1003"}
                    "Failed" {"2003"}
                    "Not Attempted" {"3003"}
                    "default" {"9003"}
                }
                
                $eventtype = switch ($RemovedFromGroup) {
                    "Success" {"SuccessAudit"}
                    "Failed" {"Warning"}
                    "Not Attempted" {"Information"}
                    "default" {"FailureAudit"}
                }

                $temp = New-Object System.Object
                $temp | Add-Member -type NoteProperty -Name "Group" -Value $g
                $temp | Add-Member -type NoteProperty -Name "SID" -Value $m.SID.Value
                $temp | Add-Member -type NoteProperty -Name "DN" -Value $m.distinguishedName
                $temp | Add-Member -type NoteProperty -Name "SamAccountName" -Value $m.SamAccountName
                $temp | Add-Member -type NoteProperty -Name "Time" -Value "$(Get-Date)"
                $temp | Add-Member -type NoteProperty -Name "RemovedFromGroup" -Value $RemovedFromGroup
                $temp | Add-Member -type NoteProperty -Name "DisabledAccount" -Value "NA"
                $problems += $temp
                Write-EventLog -LogName Application -Source 'get-RogueAdmins' -EntryType $eventtype -EventId $eventid  -Message "$m.distinguishedName was found in $g as part of the get-RogueAdmins security process. Removal attempt result was $RemovedFromGroup." 
                $esubject1 = $esubject -replace "<group>","$g" -replace "<sam>",$($m.SamAccountName)
                $ebody1 = $ebodygroup -replace "<group>","$g" -replace "<sam>",$($m.SamAccountName) -replace "<RemovedFromGroup>","$RemovedFromGroup" -replace "<DisabledAccount>",$DisabledAccount
                Send-MailMessage -From $efrom -To $eto -subject $esubject1 -body "$ebody1" -SmtpServer $eSMTP
                Write-EventLog -LogName Application -Source 'get-RogueAdmins' -EntryType FailureAudit -EventId 9004 -Message "Sending email from get-RogueAdmins failed."
                Remove-Variable temp
                Remove-Variable ebody1
                Remove-Variable esubject1
            }
        }
        #endregion Review nested groups in the group.
    }
}
#endregion Inspect each member of each monitored group. 

$problems | Export-Csv -NoTypeInformation -Append $results #Write csv file log of actions taken
if ($problems.Count -eq 0) {Write-EventLog -LogName Application -Source 'get-RogueAdmins' -EntryType Information -EventId 3005  -Message "Get-RogueAdmins ran without finding any problems." }

