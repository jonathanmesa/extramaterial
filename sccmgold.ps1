function Get-SCCMSoftwareUpdateCompliance {

<#
  Jonathan Mesa
 .SYNOPSIS
  Checks a ConfigMgr client for required Software Update compliance.

 .DESCRIPTION
  Checks a ConfigMgr client for required Software Update compliance, if it is found non-compliant for any assigned security updates the list of updates is returned.

 .PARAMETER  Computer
  The server name to target.

 .EXAMPLE
  PS C:\> Get-SCCMSoftwareUpdateCompliance -ComputerName "dlee50"

#>

[CmdletBinding()]
 param(
  [Parameter(Position=1, Mandatory=$true, HelpMessage="Computer Name", ValueFromPipelineByPropertyName=$True, ValueFromPipeline=$true)]
        [STRING[]] $ComputerName
 )

process{

    foreach ($computer in $ComputerName) { 

        if(Test-Connection -Cn $computer -BufferSize 16 -Count 1 -ea 0 -quiet){
    
            try
      { 
                Write-Host "Checking Software Updates Compliance on [$Computer]" -BackgroundColor Blue
          
                try
                    {
                        $SiteCode = $([WmiClass]"\\$computer\ROOT\ccm:SMS_Client").getassignedsite()
                    }
                catch
                    {
                        $SiteCode = "No Site Code Assigned"
                    }
                $ScanHistory = Get-WmiObject -Computer $Computer -Namespace root\ccm\scanagent -Class CCM_scanupdatesourcehistory -ErrorAction Stop #CCM_scantoolhistory -ErrorAction Stop
                $AgentGUID = Get-WmiObject -Computer $Computer -Namespace root\ccm -Class CCM_Client -ErrorAction Stop
                $ScanSource = Get-WmiObject -Computer $Computer -Namespace root\ccm\SoftwareUpdates\WUAhandler -Class CCM_UpdateSource -ErrorAction Stop
                $OSVer = Get-WmiObject -Computer $Computer -Namespace root\cimv2 -Class Win32_OperatingSystem -ErrorAction Stop
                $InstalledComponents = Get-WmiObject -Computer $Computer -Namespace root\ccm -Class CCM_InstalledComponent -ErrorAction SilentlyContinue
                $HighestComponentVer = $InstalledComponents | Sort version | Select version -last 1
                $Explorer = Get-WmiObject -Class win32_process -Computer $Computer -Filter "Name = 'explorer.exe'" | Select -first 1 -ErrorAction SilentlyContinue
                $LastBootUpTime = $osver.ConvertToDateTime($osver.LastBootUpTime)
                $SCCMservice = Get-Service -Computer $Computer ccmexec
                $WUservice = Get-Service -Computer $Computer wuauserv
                $BITSservice = Get-Service -Computer $Computer bits
                $PowerComponent = $InstalledComponents | Where {$_.Name -like '*Power*'}
                $WUVer = (Get-Command \\$Computer\c$\windows\system32\wuapi.dll).fileversioninfo
          

                try
              {
                        $User = $Explorer.getowner()
                    }
                catch
                    {
                    $User = "No User Logged On"
                    }

                $ScanHistory | Select @{Name="SCCM Assigned Site Code";Expression={$SiteCode.sSiteCode}},
                @{Name="Highest Agent Component Version";Expression={$HighestComponentVer.Version}},
                @{Name="Windows Update Agent Version";Expression={$WUVer.ProductVersion}},
                @{Name="Agent GUID";Expression={$AgentGUID.ClientId}},
                @{Name="Logged On User";Expression={$User.Domain,$User.User}},
                @{Name="Last Boot Time";Expression={$LastBootUpTime}},
                @{Name="Last SCCM Scan Time";Expression={$_.ConvertToDateTime($_.LastCompletionTime)}},
                @{Name="WSUS CAB Version";Expression={$ScanHistory.UpdateSourceVersion}},
                @{Name="WSUS Scan CAB Source";Expression={$scanSource.Contentlocation}},
                @{Name="Windows Update Service";Expression={$WUservice.Status}},
                @{Name="SMS Agent Host Service";Expression={$SCCMservice.Status}},
                @{Name="BITS Transfer Service";Expression={$BITSservice.Status}},
                @{Name="Operating System";Expression={$OSver.Caption}}

       #check if the machine has an update assignment targeted at it
       $UpdateAssigment = Get-WmiObject -Query "Select * from CCM_AssignmentCompliance" -Namespace root\ccm\SoftwareUpdates\DeploymentAgent -Computer $Computer -ErrorAction Stop
       $UpdateCIAssigment = Get-WmiObject -Query "SELECT * FROM CCM_UpdateCIAssignment" -Namespace "ROOT\ccm\policy\machine\Actualconfig" -ComputerName $Computer -ErrorAction Stop
  
                $statusHash = [hashtable]@{
                    "0" = 'No Content Sources'
                    "1" = 'Available'
                    "2" = 'Submitted'
                    "3" = 'Detecting'
                    "4" = 'Downloading CIDef'
                    "5" = 'Downloading SdmPkg'
                    "6" = 'PreDownload'
                    "7" = 'Downloading'
                    "8" = 'Wait Install'
                    "9" = 'Installing'
                    "10" = 'Pending Soft Reboot'
                    "11" = 'Pending Hard Reboot'
                    "12" = 'Wait Reboot'
                    "13" = 'Verifying'
                    "14" = 'Install Complete'
                    "15" = 'State Error'
                    "16" = 'Wait Service Window'
            } 

            $DPLocalityHash = [hashtable]@{
                    "10" = 'UNPROTECTED DP'
                    "74" = 'PROTECTED DP'
              
            } 

       #if update assignments were returned check to see if any are non-compliant
       if($UpdateAssigment)
       {
        $IsCompliant = $true 
        $UpdateAssigment | ForEach-Object{
         $ID = $_.AssignmentId
         Write-Host "Update Assignment: $($($UpdateCIAssigment | where {$_.AssignmentId -EQ $ID} ).AssignmentName) : " -NoNewline
         if($_.IsCompliant -eq $true){Write-Host "Compliant" -ForegroundColor Green}else{Write-Host "Non-Compliant" -ForegroundColor Red}
    
    
         #mark the compliance as false
         if($_.IsCompliant -eq $false -and $IsCompliant -eq $true){$IsCompliant = $false}
        }
       }
       else
       {
        Write-Host "No Software Update Assignment targeted!" -ForegroundColor Yellow
        return
       }
    
       #the machine is not compliant; search for the updates
       if($UpdateAssigment -and $IsCompliant -eq $false)
       { 
  
        #check if the machine has any targeted updates that are missing
        $TargetedUpdates = Get-WmiObject -Query "Select * from CCM_TargetedUpdateEX1 where UpdateState = 0" -Namespace root\ccm\SoftwareUpdates\DeploymentAgent -Computer $Computer -ErrorAction Stop
  
        if($TargetedUpdates)
        {
         $iMissing=0
         $UpdatesMissing=@()



         #loop through updates and get the details.
         $TargetedUpdates | ForEach-Object {

          #get the GUID
          $uID=$_.UpdateID | Select-String -Pattern "SUM_[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}" | Select -Expand Matches | Select -Expand Value
          #strip out the SUM_
          $uID=$uID.Remove(0,4)   
          $uBulletinID=""   
          $uTitle=""
                            $uDPLocality = $DPLocalityHash[$_.DPLocality.tostring()]
                            $uPercentComplete = $_.PercentComplete
                            $uStatus=$statusHash[$_.UpdateStatus.tostring()]
                      
                            #[decimal]$StatusNo = $_.UpdateStatus
                            #$uStatus=$statusHash.ContainsValue($StatusNo) 
    
          #query the update status from WMI
          Get-WmiObject -Query "Select * from CCM_UpdateStatus where UniqueID = '$($uID)'" -Namespace root\ccm\SoftwareUpdates\UpdatesStore -Computer $Computer | ForEach-Object {
           $iMissing++
           $uBulletinID = $_.Bulletin
           #if there is no MS00-000 ID swap it for the KB article number
           if($uBulletinID -eq ""){$uBulletinID="KB$($_.Article)"}   
           $uTitle=$_.Title
                          
          }
    
          #Write-Host "[$uBulletinID] :: [$uTitle]"
          $UpdatesMissing+= "[$uBulletinID] :: [$uTitle]::[$uDPLocality]::[%$uPercentComplete]::[$uStatus]"
         }
    
         Write-Host "[$iMissing] required security updates are missing:"-ForegroundColor Red
         #resort the array of missing updates and return it
         $UpdatesMissing=$UpdatesMissing | Sort-Object -Descending
         return $UpdatesMissing
        }   
       }
       #machine is targeted and compliant
       else
       {
        Write-Host "No Missing Software Updates found." -ForegroundColor Green 
       }

      }

      catch
      {
       throw 
      }

     }
    else
        {
             Write-Host ""
             Write-Host $($Computer).ToUpper()"is NOT Online." -ForegroundColor DarkYellow
             Write-Host ""
        }

        }

    }

}


Get-SCCMSoftwareUpdateCompliance -ComputerName $env:computername