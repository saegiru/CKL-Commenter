
################################################################################################################################################################################
#This script takes a completed STIG checklist file and copies the status over to a new checklist. It also copies the old comments and adds new text comments
#based on user inputs. The initials, date, location of old and new checklists are logged
#the Vulnerability numbers for both the old and new checklists are compared and it is also logged if a vulnerability appears or disappears from the new checklist
#Any changes from the old checklist are set to Not Reviewed status and appended with a message to review the vulnerability.
################################################################################################################################################################################

################################################################################################################################################################################
#Functions

#Function for GUI selection of checklist file
Function Get-Filename($title){
    #add-type -path c:\windows\assembly\GAC_MSIL\System.Windows.Forms\2.0.0.0__b77a5c561934e089\System.Windows.Forms.dll
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
    Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.title = $title
    $OpenFileDialog.initialDirectory = "[Environment]::GetFolderPath('Desktop')"
    $OpenFileDialog.filter = "CKL (*.ckl)| *.ckl"
    $OpenFileDialog.ShowHelp = $true
    $result = $OpenFileDialog.ShowDialog()
    If($result -eq "OK"){
        $OpenFileDialog.filename
    }Else{
        write-host Cancelled by User
        start-sleep 3
        exit
    }#endIf
}#endFunction Get-Filename

#Function for GUI pop up to ask for initials
Function Get-Initials(){
    #add-type -path C:\windows\assembly\GAC_MSIL\Microsoft.VisualBasic\8.0.0.0__b03f5f7f11d50a3a\Microsoft.VisualBasic.dll
    [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
    $title = "Initials"
    $msg = "Enter Your Initials"
    $data = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    If($data.length -gt 0){
        $data
    }Else{
        write-host "Initials not entered, exiting"
        start-sleep 3
        exit
    }#endIf 
}#endFunction Get-Initials

#Function for GUI pop up to ask for initials
Function Get-Comment(){
    #add-type -path C:\windows\assembly\GAC_MSIL\Microsoft.VisualBasic\8.0.0.0__b03f5f7f11d50a3a\Microsoft.VisualBasic.dll
    [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
    $title = "Comment"
    $msg = "Enter Your Comment`n(Default: 'Reviewed.')"
    $data = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    If($data.length -gt 0){
        $data
    }Else{
        $data = "Reviewed."
        $data
        #write-host "Comment not entered, exiting"
        #start-sleep 3
        #exit
    }#endIf 
}#endFunction Get-Comment

function Write-Log {
     [pscustomobject]@{
         Time = (Get-Date -f g)
         Initials = $initials
         "Old File" = $filebase
         "New File" = $outputfile
         "Old STIG" = $oldtitle + " Version " + $oldver + ", " + $oldrel
         "New STIG" = $newtitle + " Version " + $newver + ", " + $newrel
         "New Vulns" = $missnew
         "Old Vulns Removed" = $missold
     } | Export-Csv -Path "$filepath\LogFile.csv" -Append -NoTypeInformation
 }


################################################################################################################################################################################

################################################################################################################################################################################
#Pre-Process Checks and Variables
$scriptpath = split-path -parent $myinvocation.mycommand.definition

#Variables for the script
$fileold = Get-Filename("Select Old Checklist")
$filenew = Get-Filename("Select New (Blank) Checklist")
$initials = Get-Initials
$comment = Get-Comment
$d = get-date
#$datestampX = $d.ToShortDateString() + " " + $d.ToShortTimeString()
$datestamptime = $d.ToString("yyyyMMdd_HHmmss")
$datestamp = $d.ToString("yyyyMMdd")
$reviewed = "$initials - $datestamp - $comment `n"
$vulncount = 0
$filepath = Split-Path $fileold -parent
################################################################################################################################################################################

################################################################################################################################################################################
#Processes

#move data from old to new checklist

#load old checklist
$xmlold = New-Object -Typename XML
$xmlold.PreserveWhitespace = $true
$xmlold.load("$fileold")

#load new checklist
$xmlnew = New-Object -Typename XML
$xmlnew.PreserveWhitespace = $true
$xmlnew.load("$filenew")

#assign xml node to variables
$dataold = $xmlold.checklist.stigs.istig.vuln
$datanew = $xmlnew.checklist.stigs.istig.vuln

$infoold = $xmlold.checklist.stigs.istig.stig_info
$infonew = $xmlnew.checklist.stigs.istig.stig_info
 
#output versions
foreach($nodeold in $infoold) {
     $oldrel = $nodeold.si_data | where {$_.sid_name -eq "releaseinfo"} | select -expandproperty Sid_Data
     $oldtitle = $nodeold.si_data | where {$_.sid_name -eq "title"} | select -expandproperty Sid_Data
     $oldver = $nodeold.si_data | where {$_.sid_name -eq "version"} | select -expandproperty Sid_Data
     
        write-host "`nOld STIG`n" $oldtitle`n "Version "$oldver`n $oldrel`n
        
}

foreach($nodenew in $infonew) {
     $newrel = $nodenew.si_data | where {$_.sid_name -eq "releaseinfo"} | select -expandproperty Sid_Data
     $newtitle = $nodenew.si_data | where {$_.sid_name -eq "title"} | select -expandproperty Sid_Data
     $newver = $nodenew.si_data | where {$_.sid_name -eq "version"} | select -expandproperty Sid_Data
     
        write-host "New STIG`n" $newtitle`n "Version "$oldver`n $newrel`n
        
}
#End output


#copy asset info to new checklist
$assetold = $xmlold.checklist.asset
$assetnew = $xmlnew.checklist.asset

ForEach($nodeold in $assetold) {
    $ROLE = $assetold.role
    $ATYPE = $assetold.asset_type
    $HNAME = $assetold.host_name
    $HOSTIP = $assetold.HOST_IP
    $HOSTMAC = $assetold.HOST_MAC
    $HOSTFQDN = $assetold.HOST_FQDN
    $TECHAREA = $assetold.TECH_AREA
    $TARGETKEY = $assetold.TARGET_KEY
    $WEB1 = $assetold.WEB_OR_DATABASE
    $WEB2 = $assetold.WEB_DB_SITE
    $WEB3 = $assetold.WEB_DB_INSTANCE
}
foreach ($nodenew in $assetnew) {
    $assetnew.role = $ROLE
    $assetnew.asset_type = $ATYPE
    $assetnew.host_name = $HNAME
    $assetnew.HOST_IP = $HOSTIP
    $assetnew.HOST_MAC = $HOSTMAC
    $assetnew.HOST_FQDN = $HOSTFQDN
    $assetnew.TECH_AREA = $TECHAREA
    $assetnew.TARGET_KEY = $TARGETKEY
    $assetnew.WEB_OR_DATABASE = $WEB1
    $assetnew.WEB_DB_SITE = $WEB2
    $assetnew.WEB_DB_INSTANCE = $WEB3
}



#cycle through each vulnerability in $dataold and pull data
#then cycle through until the same vulnerability is found in $datanew
#and add the data
#also pull list of all old vulnerabilities


write-host "Processing, this may take a moment"
$arrayOldVulns = @()
$arrayNewVulns = @()
Foreach ($nodeold in $dataold){
    $status = $nodeold.Status
    $finding = $nodeold.Finding_Details
    $comments = $nodeold.Comments
    $sevover = $nodeold.SEVERITY_OVERRIDE
    $sevjust = $nodeold.SEVERITY_JUSTIFICATION
    
    $oldvuln = $nodeold.stig_data | where {$_.Vuln_Attribute -eq "Vuln_Num"} | select -expandproperty Attribute_Data
    $oldvulnRID = $nodeold.stig_data | where {$_.Vuln_Attribute -eq "Rule_ID"} | select -expandproperty Attribute_Data

    $arrayOldVulns += $oldvuln
    Foreach ($nodenew in $datanew){
            
        Foreach ($var in $nodenew.stig_data){
            
            If ($var.attribute_data -eq $oldvuln){
            $newvulnRID = $nodenew.stig_data | where {$_.Vuln_Attribute -eq "Rule_ID"} | select -expandproperty Attribute_Data
            $newvulnVN = $nodenew.stig_data | where {$_.Vuln_Attribute -eq "Vuln_Num"} | select -expandproperty Attribute_Data
                
                if($vulncount -le 5){
                write-host "$newvulnVN " -nonewline -ForegroundColor RED
                $vulncount++}
                else {
                write-host "$newvulnVN " -ForegroundColor Red
                $vulncount = 0
                }

                If ($status -eq "Not_Reviewed") {
                    $nodenew.Status = $status
                    $nodenew.FINDING_DETAILS = "***PREVIOUS STATUS WAS '$status'***`n" + $finding
                    $nodenew.comments = "***PREVIOUS STATUS WAS '$status'***`n" + $comments
                    $nodenew.SEVERITY_OVERRIDE = $sevover
                    $nodenew.SEVERITY_JUSTIFICATION = $sevjust
                }
                elseif ($newvulnRID -ne $oldvulnRID){
                    $nodenew.Status = "Not_Reviewed"
                    $nodenew.FINDING_DETAILS = "***DELTA - PLEASE REVIEW*** Previous status was '$status'`n" + $reviewed + $finding
                    $nodenew.comments = "***DELTA - PLEASE REVIEW*** Previous status was '$status'`n" + $reviewed + $comments
                } 
                else { 
                    $nodenew.Status = $status
                    $nodenew.FINDING_DETAILS = $reviewed + $finding
                    $nodenew.comments = $reviewed + $comments
                    $nodenew.SEVERITY_OVERRIDE = $sevover
                    $nodenew.SEVERITY_JUSTIFICATION = $sevjust
                }
            }#endIf
        }#endForeach
    }#endForeach
}#endForeach

#pull all new vulnerabilities
Foreach ($nodenew in $datanew){
    $newvuln = $nodenew.stig_data | where {$_.Vuln_Attribute -eq "Vuln_Num"} | select -expandproperty Attribute_Data
    $arrayNewVulns += $newvuln
}#endForeach

#save the changes to $xmlnew

$filebase = Split-Path $fileold -leaf
$outputfile = "$datestamptime - $initials - $filebase"
$xmlnew.save("$filepath\$outputfile")
write-host "`nSaved as $filepath\$outputfile" -ForegroundColor Green

#run comparison and filter out new and removed vulnerabilities
#trim leading comma from $missold and $missnew if present
$comparison = compare-object $arrayOldVulns $arrayNewVulns

[string]$missold = ""
[string]$missnew = ""
Foreach ($item in $comparison){
    If ($item.SideIndicator -eq "<="){$missold = $missold + "," + $item.InputObject}
    Elseif ($item.SideIndicator -eq "=>"){$missnew = $missnew + "," + $item.InputObject}
}#endForeach
If ($missold -ne $null){$missold = $missold.trimstart(",")}
If ($missnew -ne $null){$missnew = $missnew.trimstart(",")}


#Add Entries to log files

Write-Log
Read-Host -Prompt “Press Enter to exit”