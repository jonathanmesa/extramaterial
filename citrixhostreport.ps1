$a = "<style>"
$a = $a + "BODY{background-color:white;}"
$a = $a + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$a = $a + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:red}"
$a = $a + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:white}"
$a = $a + "</style>"

$citrix =  Get-Cluster LESECLOG01  | Get-VMHost | Select-Object -ExpandProperty name

    $result =@()
	foreach ($server in $citrix){
    $result += 
    Write-Host "Connection to $server"
    Get-VMHost $server|Get-View |Select-object Name, 
    @{N=“Type“;E={$_.Hardware.SystemInfo.Vendor+ “ “ + $_.Hardware.SystemInfo.Model}},
    @{N=“Serial Number“;E={(Get-EsxCli -VMHost $server).hardware.platform.get().SerialNumber}},
	@{N=“CPU“;E={“PROC:“ + $_.Hardware.CpuInfo.NumCpuPackages + “ CORES:“ + $_.Hardware.CpuInfo.NumCpuCores + “ MHZ: “ + [math]::round($_.Hardware.CpuInfo.Hz / 1000000, 0)}},
    @{N=“MEM“;E={“” + [math]::round($_.Hardware.MemorySize / 1GB, 0) + “ GB“}},
    @{N=“ESXI Version“;E={(Get-EsxCli -VMHost $server).system.version.get().Version}},
    @{N=“Build “;E={(Get-EsxCli -VMHost $server).system.version.get().Build}},
    @{N=“BiosVersion“;E={(Get-VMHost -Name $server).ExtensionData.Hardware.BiosInfo | Select-Object  -ExpandProperty BiosVersion }},
    @{N=“Datastore“;E={(get-datastore -Server $server | Select-Object -ExpandProperty name -first 1 )}},
    @{name=“CapacityGB“;Expression={(get-datastore -Server $server | Select-Object -ExpandProperty CapacityGB -first 1 )}},
	@{N=“FreeSpace“;E={(get-datastore -Server $server | select-object-ExpandProperty FreeSpaceGB -first 1 )}},
    @{N=“Datastore1“;E={(get-datastore -Server $server | select-object-ExpandProperty name -last 1 )}},
    @{N=“CapacityGB1“;E={(get-datastore -Server $server | select-object-ExpandProperty CapacityGB -last 1 )}}
    @{N=“Capis“;E={(get-datastore -Server $server | select-object-ExpandProperty CapacityGB -last 1 )}},
    @{N=“FreeSpace1“;E={(get-datastore -Server $server | select-object-ExpandProperty FreeSpaceGB -last 1 )}}
  
}


$final = $result | ConvertTo-HTML -head $a  -body "<H2>SEC LOG HW REPORT:</H2>"

$body = @"
$final 
"@

Send-MailMessage -To " wst <email@something>" `
-From "emailserver" -Subject "SECLOG HW REPORT" -Body $body  -BodyAsHtml -SmtpServer smtp.mail.XX.com  
