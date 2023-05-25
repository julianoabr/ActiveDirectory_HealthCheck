#Requires -RunAsAdministrator
#Requires -Version 3.0
<#
.SYNOPSIS
Perform a Active Directory Health Check
and Dump results into HTML

.DESCRIPTION
This script performs a Active Directory health check.
It is useful to check whether Active Directory is up & running.

.OUTPUTS
HTML document includes easy readable results.
TXT document includes full log.

.PARAMETER OutputFile
Set the name of the HTML document.

.PARAMETER LogFilename
Set the name of the TXT document.

.PARAMETER ConfigurationFile
Set the name of the XML file containing your AD configuration.
It is useful to check wether the configuration has changed.

.PARAMETER Scope
Define the scope of the health check.
All DC will be contacted if "Full" is set.
Only the current DC is used if "Limited" is set.

.EXAMPLE
.\AD_Health_Check.ps1 -LogFilename 'AD_health_check.txt' -OutputFile 'AD_health_check.html' -ConfigurationFile 'AD_configuration.xml' -Scope 'Full'
Performs a full Active Directory health check

.EXAMPLE
.\AD_Health_Check.ps1 -LogFilename 'AD_health_check.txt' -OutputFile 'AD_health_check.html' -ConfigurationFile 'AD_configuration.xml' -Scope 'Limited'
Performs a limited Active Directory health check

.NOTES
Written By: Nicolas Nerson
The script is designed to be run on a server on which the AD DS tools have been installed
'gpotool.exe' is necessary. Please see http://www.microsoft.com/en-us/download/details.aspx?id=17657
The Get-DFSROutbandInfo function is adapted from http://gallery.technet.microsoft.com/scriptcenter/dac62790-219d-4325-a57b-e79c2aa6b58e
The script requires DFSR for Sysvol Replication

Change Log
v1.00, 2013-09-06 - Initial Version
v1.01, 2013-09-10 - Create the variable '$script:numberOfPartitions'
v1.02, 2014-01-10 - Integrate an XSD schema file thanks to Karl Vernet
v1.03, 2014-01-14 - Check the Backlog Counters
v1.04, 2014-03-21 - Correct a bug with Split('<br>'). Correct minor bugs
v1.05, 2014-07-07 - Force [array] casting. Add % of RID used. Correct minor bugs
v1.06, 2014-07-10 - Correct HTML error
v1.07, 2014-07-11 - Modify the way gpotool results are handled. Remove the test using $numberOfPartitions. Better casting variables.
v1.08, 2014-07-14 - Better casting variables. Modify the way to add results from gpotool when there are many domains. Sort the GPO by domain
v1.09, 2014-10-14 - Get-DFSROutbandInfo simplification
v1.10, 2014-11-05 - Correction of the Bridgehead Servers output. Add the DCs OS Name
v1.11, 2014-11-21 - Add the Global Catalog info. Correction of Get-DFSROutbandInfo. Change the tests with 'Limited' choice.
v1.12, 2014-11-24 - Reorder the tests and use a new Test-TcpConnection function to speed up the script. Remove old code. Better casting variables. Modify Test-Ldap, Test-Ping and Test-Wmi to get rid of unnecessary messages. 
v1.13, 2014-12-03 - Correction of minor bugs. Change the way the jobs for dcdiag are started. Failback to older Test-TcpConnection because of many false positive
v1.14, 2014-12-23 - Use Test-NetConnection and Test-Connection when available. Add ping response time to HTML
v1.15, 2019-11-22 - Adjust Hash Tables to Powershell v3 and superior (Find me at jaribeiro@uoldiveo.com or julianoalvesbr@live.com or https://github.com/julianoabr)
v1.16, 2019-11-26 - Add Parameter to choose between verify Forest or Domain (Find me at jaribeiro@uoldiveo.com or julianoalvesbr@live.com or https://github.com/julianoabr)
v1.17, 2020-08-18 - Adjust to run GpoTool in mode Forest or Domain (Find me at jaribeiro@uoldiveo.com or julianoalvesbr@live.com or https://github.com/julianoabr)
v1.18, 2020-12-10 - Adjust embedded images to be sent by e-mail and put a boolean variable to choose if you want to send e-mail or not (Find me at jaribeiro@uoldiveo.com or julianoalvesbr@live.com or https://github.com/julianoabr)
v1.18.1 2021-03-25 - Attach LogFile to E-mail (Find me at julianoalvesbr@live.com or https://github.com/julianoabr)
#>

Param
(
    [System.String]$LogFilename = 'AD_Health_Check.txt',
    
    [System.String]$OutputFile = 'AD_Health_Check.html',
    
    [System.String]$ConfigurationFile = 'AD_Configuration.xml',
    
    [ValidateSet("Full","Limited")]
    [System.String]$Scope = 'Full',
    
    [ValidateSet("Forest","Domain")]
    [System.String]$Level = 'Domain',

    [System.Boolean]$sendMail = $false

    [System.Boolean]$attachLog = $true

)

# Version
[string]$ScriptVersion = 'v1.18.1'

# Normalize the Scope
[string]$scope = $scope.Substring(0,1).ToUpper() + $scope.substring(1).ToLower()

# Use to determine the limits of Backlog counters
[int]$script:warningBacklogLimit = 1
[int]$script:criticalBacklogLimit = 5

# Use to determine the DCDIAG timeout in minutes
[int]$script:dcdiagTimeout = 1

# Use to determine the DFSR analysis timeout in minutes
[int]$script:waitDcdiag = 5

# Store the older files to delete
[array]$olderFiles = @()

# contain the Jobs made by dcdiag.exe and the results
[array]$jobsDcdiag = @()
[array]$dcdiagResult = @()
[array]$diagnostics = @()

# The full list of DCs
[array]$DCs = @()

# The DCs wich respond to ping and/or tcp/135 (rpc)
[array]$servers = @()

# containing the Jobs made for DFSR diagnostics and the results
[array]$jobsDfsr = @()
[array]$dfsrOutbandInfos = @()

# Initialize the array containing the domains configuration
[array]$domainsConfiguration = @()

# Contains the GPO infos
[array]$gpoStatus = @()

# Initialize the array containing the sites configuration
[array]$sitesConfiguration = @()

# Contains the backups (raw and filtered)
[array]$repadminShowbackup = @()
[array]$backups = @()

# Array containing the Replications Status (raw and filtered)
[array]$repadminReplsum = @()
[array]$replications = @()

# Initialize the array containing the connectivity of each DC
[array]$dcConnectivity = @()

# Contains the list of domains
[array]$domains = @()

# Contains the list of AD sites
[array]$sites = @()

# Check if Test-NetConnection cmdlet is available
if (Get-Command -Name 'Test-NetConnection'  -ErrorAction SilentlyContinue)
{ [bool]$script:testNetConnection = $true }
else
{ [bool]$script:testNetConnection = $false }

# Check if Test-Connection cmdlet is available
if (Get-Command -Name 'Test-Connection'  -ErrorAction SilentlyContinue)
{ [bool]$script:testConnection = $true }
else
{ [bool]$script:testConnection = $false }



#########################################################################################
# Functions
#########################################################################################

#======================================================================================== 
# The function is adapted from http://gallery.technet.microsoft.com/scriptcenter/dac62790-219d-4325-a57b-e79c2aa6b58e
#========================================================================================
# This function gets the DFSR Outband Replications Infos
#========================================================================================
$getdFSROutbandInfo = {
function Get-DFSROutbandInfo
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$Computer,
        [string]$ReplicationGroupName = 'Domain System Volume',
        [string]$ReplicatedFolderName = 'SYSVOL Share'
    )

    [string]$missing = 'n/a'
    [string]$notAvailable = 'Partner not available'
    [string]$unknown = 'Unknown'

    # Query DFSR Groups
    [string]$wmiQuery = "SELECT * FROM DfsrReplicationGroupConfig WHERE ReplicationGroupName = '" + $replicationGroupName + "'" 
    [array]$dfsrGroups = @()
    $dfsrGroups += Get-WmiObject -computername $computer -Namespace "root\MicrosoftDFS" -Query $wmiQuery 


    # Query DFSR Outband Connections
    [string]$wmiQuery = "SELECT * FROM DfsrConnectionConfig WHERE Inbound = 'False' AND PartnerDn like '%CN=" + $replicationGroupName + ",%'" 
    [array]$dfsrConnections = @()
    $dfsrConnections += Get-WmiObject -computername $computer -Namespace "root\MicrosoftDFS" -Query $wmiQuery 


    # Query DFSR Folders
    [string]$wmiQuery = "SELECT * FROM DfsrReplicatedFolderConfig WHERE ReplicatedFolderDn like '%CN=" + $replicationGroupName + ",%' AND ReplicatedFolderName = '" + $replicatedFolderName + "'" 
    [array]$dfsrFolders = @()
    $dfsrFolders += Get-WmiObject -computername $computer -Namespace "root\MicrosoftDFS" -Query $wmiQuery

    $ComputerSendingMember = $Computer.ToLower()

    $propdfsrOutbandInfos = [ordered]@{
    ReplicationGroupName = $replicationGroupName
    ReplicatedFolderName = $replicatedFolderName
    SendingMember = $ComputerSendingMember
    ReceivingMember = ''
    BacklogCount = ''
    FolderEnabled = ''
    ConnectionEnabled = ''
}

$dfsrOutbandInfos = New-Object -TypeName PSObject -Property $propdfsrOutbandInfos


    foreach ($group in $dfsrGroups)
    {
        [string]$ReplicationGroupGUID = $group.ReplicationGroupGUID 

        foreach ($folder in $dfsrFolders)
        {
            if ($folder.ReplicationGroupGUID -eq $ReplicationGroupGUID) 
            {
                [bool]$folderEnabled = $folder.Enabled 

                foreach ($connection in $dfsrConnections)
                {
                    if ($connection.ReplicationGroupGUID -eq $replicationGroupGUID)
                    {
                        [bool]$connectionEnabled = $connection.Enabled 
                        [string]$backlogCount = $unknown

                        if ($folderEnabled -and $connectionEnabled) 
                        {
                            [string]$Smem = $Computer.ToUpper()   
                            [string]$Rmem = $Connection.PartnerName.Trim() 
                                     
                            # Get the version vector of the inbound partner 
                            [string]$wmiQuery = "SELECT * FROM DfsrReplicatedFolderInfo WHERE ReplicationGroupGUID = '" + $ReplicationGroupGUID + "' AND ReplicatedFolderName = '" + $ReplicatedFolderName + "'" 
                            [array]$InboundPartnerWMI = @()
                            $InboundPartnerWMI += Get-WmiObject -computername $Rmem -Namespace "root\MicrosoftDFS" -Query $WMIQuery 
                                     
                            [string]$wmiQuery = "SELECT * FROM DfsrReplicatedFolderConfig WHERE ReplicationGroupGUID = '" + $ReplicationGroupGUID + "' AND ReplicatedFolderName = '" + $ReplicatedFolderName + "'" 
                            [array]$PartnerFolderEnabledWMI = @()
                            $PartnerFolderEnabledWMI += Get-WmiObject -computername $Rmem -Namespace "root\MicrosoftDFS" -Query $wmiQuery
                            if ([string]$PartnerFolderEnabledWMI[0].Enabled -eq '')
                            {
                                # The partner is not available!
                                [bool]$PartnerFolderEnabled = $false
                                [string]$BacklogCount = $notAvailable
                            }
                            else
                            {
                                [bool]$PartnerFolderEnabled = $PartnerFolderEnabledWMI[0].Enabled
                            }
                                     
                            if ($PartnerFolderEnabled) 
                            { 
                                [string]$Vv = $InboundPartnerWMI[0].GetVersionVector().VersionVector
                                         
                                # Get the backlogcount from outbound partner 
                                [string]$wmiQuery = "SELECT * FROM DfsrReplicatedFolderInfo WHERE ReplicationGroupGUID = '" + $ReplicationGroupGUID + "' AND ReplicatedFolderName = '" + $ReplicatedFolderName + "'" 
                                [array]$OutboundPartnerWMI = @()
                                $OutboundPartnerWMI += Get-WmiObject -computername $Smem -Namespace "root\MicrosoftDFS" -Query $wmiQuery 
                                [string]$BacklogCount = $OutboundPartnerWMI[0].GetOutboundBacklogFileCount($Vv).BacklogFileCount 
                            }               
                        }

                        $dfsrOutbandInfos.ReceivingMember = $dfsrOutbandInfos.ReceivingMember + '<br>' + $Rmem.ToLower()
                        $dfsrOutbandInfos.BacklogCount = $dfsrOutbandInfos.BacklogCount + '<br>' + $backlogCount
                        $dfsrOutbandInfos.FolderEnabled = $dfsrOutbandInfos.FolderEnabled + '<br>' + $folderEnabled
                        $dfsrOutbandInfos.ConnectionEnabled = $dfsrOutbandInfos.ConnectionEnabled + '<br>' + $connectionEnabled
                    }
                }
            }
        }
    }

    if ($dfsrOutbandInfos.ReceivingMember -eq '') { $dfsrOutbandInfos.ReceivingMember = '<br>' + $missing }
    elseif ($dfsrOutbandInfos.ReceivingMember.Contains('<br><br>')) { $dfsrOutbandInfos.ReceivingMember = $dfsrOutbandInfos.ReceivingMember.Replace('<br><br>','<br>' + $missing + '<br>') }
    if ($dfsrOutbandInfos.BacklogCount -eq '') { $dfsrOutbandInfos.BacklogCount = '<br>' + $missing }
    elseif ($dfsrOutbandInfos.BacklogCount.Contains('<br><br>')) { $dfsrOutbandInfos.BacklogCount = $dfsrOutbandInfos.BacklogCount.Replace('<br><br>','<br>' + $missing + '<br>') }
    if ($dfsrOutbandInfos.FolderEnabled -eq '') { $dfsrOutbandInfos.FolderEnabled = '<br>' + $missing }
    elseif ($dfsrOutbandInfos.FolderEnabled.Contains('<br><br>')) { $dfsrOutbandInfos.FolderEnabled = $dfsrOutbandInfos.FolderEnabled.Replace('<br><br>','<br>' + $missing + '<br>') }
    if ($dfsrOutbandInfos.ConnectionEnabled -eq '') { $dfsrOutbandInfos.ConnectionEnabled = '<br>' + $missing }
    elseif ($dfsrOutbandInfos.ConnectionEnabled.Contains('<br><br>')) { $dfsrOutbandInfos.ConnectionEnabled = $dfsrOutbandInfos.ConnectionEnabled.Replace('<br><br>','<br>' + $missing + '<br>') }

    if ($dfsrOutbandInfos.ReceivingMember.Length -ne 0) { $dfsrOutbandInfos.ReceivingMember = $dfsrOutbandInfos.ReceivingMember.Substring(4,$dfsrOutbandInfos.ReceivingMember.Length-4) }
    if ($dfsrOutbandInfos.BacklogCount.Length -ne 0) { $dfsrOutbandInfos.BacklogCount = $dfsrOutbandInfos.BacklogCount.Substring(4,$dfsrOutbandInfos.BacklogCount.Length-4) }
    if ($dfsrOutbandInfos.FolderEnabled.Length -ne 0) { $dfsrOutbandInfos.FolderEnabled = $dfsrOutbandInfos.FolderEnabled.Substring(4,$dfsrOutbandInfos.FolderEnabled.Length-4) }
    if ($dfsrOutbandInfos.ConnectionEnabled.Length -ne 0) { $dfsrOutbandInfos.ConnectionEnabled = $dfsrOutbandInfos.ConnectionEnabled.Substring(4,$dfsrOutbandInfos.ConnectionEnabled.Length-4) }

    return $dfsrOutbandInfos
}#End of Function Get-DFSROutbandInfo
}
#======================================================================================== 


#======================================================================================== 
# Log function
#======================================================================================== 
function Write-Log($log)
{
    Add-Content -Path $logFilename -Value ([string](Get-Date -Format "dd/MM/yyyy HH:mm:ss") + " --- " + $log) -PassThru
}
#======================================================================================== 


#======================================================================================== 
# Test TCP Connection function
#======================================================================================== 
function Test-TcpConnection
{
    Param
    (
        [string]$Computer = $env:COMPUTERNAME,
        [ValidateRange(1,65535)] [Int]$Port = 135
    )

    [string]$message = ''
    
    # Use of Test-NetConnection if available
    if ($script:testNetConnection)
    {
        [DateTime]$t1 = Get-Date
        [bool]$result = Test-NetConnection -ComputerName $computer -Port $port -InformationLevel Quiet
        [DateTime]$t2 = Get-Date
    }
    else
    {
        # Create a Net.Sockets.TcpClient object to use for checking for open TCP ports.
        [DateTime]$t1 = Get-Date
        $socket = New-Object Net.Sockets.TcpClient

        try
        {
            # Connect to remote machine's port 
            $socket.Connect($computer,$port)
            if ($socket.Connected)
            {
                [bool]$result = $true
                $message += 'Port ' + $type + $port + ' on ' + $computerName + ' is open (' + $socket.Client.LocalEndPoint.ToString() + ' -> ' + $socket.Client.RemoteEndPoint.ToString() + '). '
                $socket.Close()
            }
        }
        catch [Exception]
        {
            $message += $_.Exception.Message + '. '
            [bool]$result = $false
        }
        [DateTime]$t2 = Get-Date

        $socket = $null
    }
    
    [int]$tcpResponseTime = [int](($t2-$t1).TotalMilliseconds)
    $message += 'Measure needs ' + $tcpResponseTime + ' ms to achieve'
    Remove-Variable -Name t1
    Remove-Variable -Name t2

    return $result,$message,$tcpResponseTime
}
#======================================================================================== 

#======================================================================================== 
# Ping function
#======================================================================================== 
function Test-Ping
{
    param
    (
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [int]$Timeout = 30
    )

    # Use of Test-Connection if available
    if ($script:testConnection)
    {
        [System.Collections.ArrayList]$err = @()
        $result = Test-Connection -ComputerName $ComputerName -Count '1' -ErrorVariable err -ErrorAction SilentlyContinue

        if ($err.Count -ne 0)
        #---------------------------------------------------------------
        # there is a error: log it
        #---------------------------------------------------------------
        {
            [string]$pingResult = $err.ToArray().Get(0).ToString()
            [bool]$pingOk = $false
            [int64]$pingRoundtripTime = '-1'
        }
        #---------------------------------------------------------------
        # No error
        #---------------------------------------------------------------
        else
        {
            [int64]$pingRoundtripTime = $result.ResponseTime
            [int]$statusCode = $result.StatusCode
            switch ($statusCode)
                {
                    '0'	    { [string]$pingResult = 'Success'; [bool]$pingOk = $true } 
                    '11001' { [string]$pingResult = 'Buffer Too Small '; [bool]$pingOk = $false }
                    '11002' { [string]$pingResult = 'Destination Net Unreachable'; [bool]$pingOk = $false } 
                    '11003' { [string]$pingResult = 'Destination Host Unreachable'; [bool]$pingOk = $false } 
                    '11004' { [string]$pingResult = 'Destination Protocol Unreachable'; [bool]$pingOk = $false } 
                    '11005' { [string]$pingResult = 'Destination Port Unreachable'; [bool]$pingOk = $false } 
                    '11006' { [string]$pingResult = 'No Resources'; [bool]$pingOk = $false } 
                    '11007' { [string]$pingResult = 'Bad Option'; [bool]$pingOk = $false } 
                    '11008' { [string]$pingResult = 'Hardware Error'; [bool]$pingOk = $false } 
                    '11009' { [string]$pingResult = 'Packet Too Big'; [bool]$pingOk = $false } 
                    '11010' { [string]$pingResult = 'Request Timed Out'; [bool]$pingOk = $false } 
                    '11011' { [string]$pingResult = 'Bad Request'; [bool]$pingOk = $false } 
                    '11012' { [string]$pingResult = 'Bad Route'; [bool]$pingOk = $false } 
                    '11013' { [string]$pingResult = 'TimeToLive Expired Transit'; [bool]$pingOk = $false } 
                    '11014' { [string]$pingResult = 'TimeToLive Expired Reassembly'; [bool]$pingOk = $false } 
                    '11015' { [string]$pingResult = 'Parameter Problem'; [bool]$pingOk = $false } 
                    '11016' { [string]$pingResult = 'Source Quench'; [bool]$pingOk = $false } 
                    '11017' { [string]$pingResult = 'Option Too Big'; [bool]$pingOk = $false } 
                    '11018' { [string]$pingResult = 'Bad Destination'; [bool]$pingOk = $false } 
                    '11032' { [string]$pingResult = 'Negotiating IPSEC'; [bool]$pingOk = $false } 
                    '11050' { [string]$pingResult = 'General Failure'; [bool]$pingOk = $false }  
                    default { [string]$pingResult = 'Unknown Error'; [bool]$pingOk = $false }
                }
        }
        #---------------------------------------------------------------
        
        Remove-Variable -Name result
    }
    else
    {
        try
        {
            $object = New-Object system.Net.NetworkInformation.Ping
            $ping = $object.Send($computerName, $timeout)
            [string]$pingResult = $ping.Status
            [int64]$pingRoundtripTime = $ping.RoundtripTime

            # the server exists in DNS and ping succed
            if ($pingResult -eq 'Success')
            {
                [bool]$pingOk = $true
            }
            # the server exists in DNS but ping failed
            else
            {
                [bool]$pingOk = $false
            }
        }

        # the server does not exist in DNS
        catch [Exception]
        {
            [bool]$pingOk = $false
            [string]$pingResult = $_.Exception.Message
        }

        $object = $null
    }

    return $pingOK, $pingResult, $pingRoundtripTime

}#End of Function Test-Ping
#======================================================================================== 

#======================================================================================== 
# LDAP Bind Test Function
#======================================================================================== 
function Test-LDAP
{
    Param
    (
        [string]$filter = '(cn=krbtgt)', 
        [Parameter(Mandatory=$true)][string]$server, 
        [ValidateSet("Base","Subtree","OneLevel")] [string]$ldapScope = 'Subtree',
        [string]$pageSize = '1'
    )

    [DateTime]$t1 = Get-Date
    [string]$domain = 'LDAP://' + $server
    $root = New-Object DirectoryServices.DirectoryEntry $domain
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $root
    $searcher.PageSize = $pageSize
    $searcher.Filter = $filter

    try
    {
        $adObjects = $searcher.FindAll()
        [string]$ldapMessage = $adObjects.Item(0).Path
        [bool]$pingOk = $true
    }
    # the server does not respond to LDAP requests
    catch [Exception]
    {
        [string]$ldapMessage = $_.Exception.Message
        [bool]$pingOk = $false
    }
    [DateTime]$t2 = Get-Date

    [int]$ldapResponseTime = [int](($t2-$t1).TotalMilliseconds)
    Remove-Variable -Name t1
    Remove-Variable -Name t2
    $searcher = $null
    $root = $null
    return $pingOk, $ldapMessage, $ldapResponseTime
}
#======================================================================================== 


#======================================================================================== 
# WMI Test Function 
#======================================================================================== 
function Test-WMI
{
    Param
    (
        
        [Parameter(Mandatory=$true)]
        [string]$computername,
        [string]$class = 'win32_bios'
    )

    
    try
    {
        # "-ErrorAction SilentlyContinue" is needed if RPC is unavailable
        [DateTime]$t1 = Get-Date
        $wmiObject = Get-WmiObject -ComputerName $computername -Class $class -ErrorAction SilentlyContinue
        # if server does not respond to RPC than $wmiObject is $null
        if ($wmiObject -ne $null)
        {
            
            [string]$serialNumber = $wmiObject.SerialNumber
            [string]$wmiMessage = $serialNumber
            [bool]$wmiOk = $true
        }
        else
        {
            [string]$wmiMessage = 'unknown'
            [bool]$wmiOk = $false
        }
    }
    # the server does not respond to WMI requests but RPC is available
    catch [Exception]
    {
        [string]$wmiMessage = $_.Exception.Message
        [bool]$wmiOk = $false
    }
    [DateTime]$t2 = Get-Date

    [int]$wmiResponseTime = [int](($t2-$t1).TotalMilliseconds)
    Remove-Variable -Name t1
    Remove-Variable -Name t2
    $wmiObject = $null
    
    return $wmiOk, $wmiMessage, $wmiResponseTime
}#END OF TEST-WMI
#======================================================================================== 



#======================================================================================== 
# Get the current forest name
#======================================================================================== 
function Get-CurrentForest
{
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
    return $forest.Name 
}
#======================================================================================== 

#======================================================================================== 
# Get all Domains
#======================================================================================== 
function Get-AllDomains
{
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
    return $forest.Domains 
}
#======================================================================================== 

#======================================================================================== 
# Get the number of AD Sites
#======================================================================================== 
function Get-NumberOfSites
{
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
    if ( (($forest | %{$_.Sites} |  %{$_.Name}).Count) -gt '1')
    {
        return ($forest | %{$_.Sites} |  %{$_.Name}).Count
    }
    else
    {
        return '1'
    }
}
#======================================================================================== 

#======================================================================================== 
# Get the number of AD Domains
#======================================================================================== 
function Get-NumberOfDomains
{
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
    if ( (($forest | %{$_.Domains} |  %{$_.Name}).Count) -gt '1')
    {
        return ($forest | %{$_.Domains} |  %{$_.Name}).Count
    }
    else
    {
        return '1'
    }
}
#======================================================================================== 



#======================================================================================== 
# Get the number of Site with DCs
#======================================================================================== 
function Get-NumberOfSitesWithDC
{
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
    $sites = $forest.Sites
    $numberOfSitesWithDC = 0
    foreach ($site in $sites)
    {
        [string]$DCs = '' + ($site | %{$_.Servers} | %{$_.Name})
        if ( $DCs.Contains('.') )
        {
            $numberOfSitesWithDC++
        }
    }
    return $numberOfSitesWithDC
}
#======================================================================================== 

#======================================================================================== 
# Validate if Script will Run on all DCs in a Forest or in Current Domain
#======================================================================================== 
if ($Level -eq 'Forest'){


#======================================================================================== 
# Get all DCs in current forest
#======================================================================================== 
function Get-AllDCs
    {
    $forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
    [array]$dcs = @()
    $dcs += $forest.domains | %{$_.DomainControllers} | %{$_.Name}
    return $dcs
    }
#======================================================================================== 


}#End of IF Level 
else{

#======================================================================================== 
# Get all DCs in Current Domain
#======================================================================================== 
function Get-AllDCs
    {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    
    [array]$dcs = @()
    
    $domain.DomainControllers | %{$_.Name}
    
    return $dcs
    }
#======================================================================================== 


}#end of Else Level
#======================================================================================== 


#======================================================================================== 
# Get DC OS Name
#======================================================================================== 
function Get-DcOsName
{
    Param
    (
        [string]$dc = ([ADSI]LDAP://RootDSE).dnshostname.ToString()
    )

    [string]$dc = '*' + $dc + '*'
    $forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
    [string]$os = $forest.domains | %{$_.DomainControllers} | Where-Object {$_.Name -like $dc} | %{$_.OSVersion}
    return $os
}
#======================================================================================== 



#======================================================================================== 
# Is the Dc a Global Catalog
#======================================================================================== 
function Get-DcGlobalCatalogInfo
{
    Param
    (
        [string]$dc = ([ADSI]LDAP://RootDSE).dnshostname.ToString()
    )

    [string]$dc = '*' + $dc + '*'
    $forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
    [string]$isGc = ($forest.domains | %{$_.DomainControllers} | Where-Object {$_.Name -like $dc}).IsGlobalCatalog()
    return $isGc
}
#======================================================================================== 



#======================================================================================== 
# Get FSMO Schema Role Owner (Forest role)
#======================================================================================== 
function Get-SchemaRoleOwner
{
    $forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
    $schemaRoleOwner = ($forest.SchemaRoleOwner | %{$_.Name}).Split('.')[0].ToLower()
    return $schemaRoleOwner
}
#======================================================================================== 



#======================================================================================== 
# Get FSMO Naming Role Owner (Forest role)
#======================================================================================== 
function Get-NamingRoleOwner
{
    $forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
    $namingRoleOwner = ($forest.NamingRoleOwner | %{$_.Name}).Split('.')[0].ToLower()
    return $namingRoleOwner
}
#======================================================================================== 



#======================================================================================== 
# Get FSMO PDC Role Owner (Domain role)
#======================================================================================== 
function Get-PdcRoleOwner
{
    Param
    (
        [system.directoryservices.activedirectory.Domain]$domain = [system.directoryservices.activedirectory.Domain]::GetCurrentDomain()
    )
    [string]$pdcRoleOwner = ($domain.PdcRoleOwner | %{$_.Name}).Split('.')[0].ToLower()
    return $pdcRoleOwner
}
#======================================================================================== 



#======================================================================================== 
# Get FSMO RID Role Owner (Domain role)
#======================================================================================== 
function Get-RidRoleOwner
{
    Param
    (
        [system.directoryservices.activedirectory.Domain]$domain = [system.directoryservices.activedirectory.Domain]::GetCurrentDomain()
    )
    [string]$ridRoleOwner = ($domain.RidRoleOwner | %{$_.Name}).Split('.')[0].ToLower()
    return $ridRoleOwner
}
#======================================================================================== 



#======================================================================================== 
# Get FSMO Infrastructure Role Owner (Domain role)
#======================================================================================== 
function Get-InfrastructureRoleOwner
{
    Param
    (
        [system.directoryservices.activedirectory.Domain]$domain = [system.directoryservices.activedirectory.Domain]::GetCurrentDomain()
    )
    [string]$infrastructureRoleOwner = ($domain.InfrastructureRoleOwner | %{$_.Name}).Split('.')[0].ToLower()
    return $infrastructureRoleOwner
}
#======================================================================================== 



#======================================================================================== 
# Get Forest Mode
#======================================================================================== 
function Get-ForestMode
{
    $forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
    [string]$forestMode = $forest.ForestMode
    return $forestMode
}
#======================================================================================== 



#======================================================================================== 
# Get Domain Mode
#======================================================================================== 
function Get-DomainMode
{
    Param
    (
        [system.directoryservices.activedirectory.Domain]$domain = [system.directoryservices.activedirectory.Domain]::GetCurrentDomain()
    )
    [string]$domainMode = $domain.DomainMode
    return $domainMode
}
#======================================================================================== 



#======================================================================================== 
# Get Domain Name
#======================================================================================== 
function Get-DomainName
{
    Param
    (
        [system.directoryservices.activedirectory.Domain]$domain = [system.directoryservices.activedirectory.Domain]::GetCurrentDomain()
    )
    [string]$domainName = $domain.Name
    return $domainName
}
#======================================================================================== 



#======================================================================================== 
# Get all sites
#======================================================================================== 
function Get-AllSites
{
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
    return $forest.Sites 
}
#======================================================================================== 



#======================================================================================== 
# Get Site Name
#======================================================================================== 
function Get-SiteName
{
    Param
    (
        [system.directoryservices.activedirectory.ActiveDirectorySite]$site = [system.directoryservices.activedirectory.ActiveDirectorySite]::GetComputerSite()
    )
    [string]$siteName = $site.Name
    return $siteName
}
#======================================================================================== 


#======================================================================================== 
# Get Inter Site Topology Generator
#======================================================================================== 
function Get-InterSiteTopologyGenerator
{
    Param
    (
        [system.directoryservices.activedirectory.ActiveDirectorySite]$site = [system.directoryservices.activedirectory.ActiveDirectorySite]::GetComputerSite()
    )
    [string]$interSiteTopologyGenerator = ''
    [string]$tester = $site.InterSiteTopologyGenerator
    
    # Retrieve inter site topology generator if any
    if ($tester -ne '')
    {
        $interSiteTopologyGenerator = ($site.InterSiteTopologyGenerator| %{$_.Name}).Split('.')[0].ToLower()
    }
        
    return $interSiteTopologyGenerator
}
#======================================================================================== 



#======================================================================================== 
# Get Subnets
#======================================================================================== 
function Get-Subnets
{
    Param
    (
        [system.directoryservices.activedirectory.ActiveDirectorySite]$site = [system.directoryservices.activedirectory.ActiveDirectorySite]::GetComputerSite()
    )

    [string]$subnets = ''


    # Retrieve each subnet if at least one subnet
    if ( ($site.Subnets).count -ne 0)
    {
        foreach ($subnet in $site.Subnets)
        {
            $subnets += ($subnet | %{$_.Name}) + '<br>' 
        }

        # Remove the final '<br>'
        $subnets = $subnets.Substring(0,$subnets.Length-4)
    }

    return $Subnets
}
#======================================================================================== 



#======================================================================================== 
# Get SiteLinks
#======================================================================================== 
function Get-SiteLinks
{
    Param
    (
        [system.directoryservices.activedirectory.ActiveDirectorySite]$site = [system.directoryservices.activedirectory.ActiveDirectorySite]::GetComputerSite()
    )

    [string]$siteLinks = ''

    # Retrieve each site link if at least one site link
    if ( ($site.SiteLinks).count -ne 0)
    {

        foreach ($siteLink in $site.SiteLinks)
        {
            $siteLinks += ($siteLink | %{$_.Name}) + '<br>' 
        }

        # Remove the final '<br>'
        $siteLinks = $siteLinks.Substring(0,$siteLinks.Length-4)
    }

    return $siteLinks
}
#======================================================================================== 



#======================================================================================== 
# Get Adjacent Sites
#======================================================================================== 
function Get-AdjacentSites
{
    Param
    (
        [system.directoryservices.activedirectory.ActiveDirectorySite]$site = [system.directoryservices.activedirectory.ActiveDirectorySite]::GetComputerSite()
    )
    [string]$adjacentSites = ''

    # Retrieve each adjacent site
    foreach ($adjacentSite in $site.AdjacentSites)
    {
        $adjacentSites += ($adjacentSite | %{$_.Name}) + '<br>' 
    }

    # Remove last '<br>' if at least one adjacent site
    if ( $adjacentSites.Length -ne 0)
    {
        $adjacentSites = $adjacentSites.Substring(0,$adjacentSites.Length-4)
    }



    return $adjacentSites
}
#======================================================================================== 



#======================================================================================== 
# Get Site Servers
#======================================================================================== 
function Get-SiteServers
{
    Param
    (
        [system.directoryservices.activedirectory.ActiveDirectorySite]$site = [system.directoryservices.activedirectory.ActiveDirectorySite]::GetComputerSite()
    )

    [string]$siteServers = ''

    # Retrieve each server
    foreach ($server in $site.Servers)
    {
        $siteServers += ($server | %{$_.Name}).Split('.').Get(0) + '<br>'
    }

    # Remove last '<br>' if at least one server
    if ( $siteServers.Length -ne 0)
    {
        $siteServers = $siteServers.Substring(0,$siteServers.Length-4)
    }

    return $siteServers.ToLower()
}
#======================================================================================== 



#======================================================================================== 
# Get Bridgehead Servers
#======================================================================================== 
function Get-BridgeheadServers
{
    Param
    (
        [system.directoryservices.activedirectory.ActiveDirectorySite]$site = [system.directoryservices.activedirectory.ActiveDirectorySite]::GetComputerSite()
    )

    [string]$bridgeheadServers = ''

    # Retrieve each bridgehead server if at least one bridgehead server
    if ( ($site.BridgeheadServers).count -ne 0)
    {
        foreach ($bridgeheadServer in $site.BridgeheadServers)
        {
            $bridgeheadServers += ($bridgeheadServer | %{$_.Name}).Split('.').Get(0) + '<br>'
        }

        # Remove the final '<br>'
        $bridgeheadServers = $bridgeheadServers.Substring(0,$bridgeheadServers.Length-4)
    }

    return $bridgeheadServers.ToLower()
}
#======================================================================================== 



#======================================================================================== 
# Construct the array of DCs status
#======================================================================================== 
function New-DC()
{
    Param
    (
        [string]$ComputerName,
        [string]$FQDN,
        [string]$PingFQDN,
        [string]$PingShortname,
        [string]$LDAPBind,
        [string]$WMI,
        [string]$TCPPort53,
        [string]$TCPPort88,
        [string]$TCPPort135,
        [string]$TCPPort389,
        [string]$TCPPort445,
        [string]$TCPPort3268,
        [string]$OS,
        [string]$IsGlobalCatalog
    )

    $propDC = [ordered]@{
    ComputerName = $ComputerName
    FQDN = $FQDN
    PingFQDN = $PingFQDN
    PingShortname = $PingShortname
    LDAPBind = $LDAPBind
    WMI = $WMI
    TCPPort53 = $TCPPort53
    TCPPort88 = $TCPPort88
    TCPPort135 = $TCPPort135
    TCPPort389 = $TCPPort389
    TCPPort445 = $TCPPort445
    TCPPort3268 = $TCPPort3268
    OS = $OS
    IsGlobalCatalog = $IsGlobalCatalog
}

$dc = New-Object -TypeName PSObject -Property $propDC

return $dc

}#end of Function New DC
#======================================================================================== 



#======================================================================================== 
# Construct the array of Domains
#======================================================================================== 
function New-Domain() 
{
    Param
    (
        [string]$DomainName,
        [string]$DomainMode,
        [string]$PdcRoleOwner,
        [string]$RidRoleOwner,
        [string]$InfrastructureRoleOwner,
        [string]$RidsRemainingPercent
    )

      $propDomain = [ordered]@{
        DomainName = $DomainName
        DomainMode = $DomainMode
        PdcRoleOwner = $PdcRoleOwner
        RidRoleOwner = $RidRoleOwner
        InfrastructureRoleOwner = $InfrastructureRoleOwner
        RidsRemainingPercent = $RidsRemainingPercent
}

    $domain = New-Object -TypeName PSObject -Property $propDomain

return $domain
}#end of New-Domain
#======================================================================================== 


#======================================================================================== 
# Construct the array of Sites
#======================================================================================== 
function New-Site() 
{
    Param
    (
        [string]$siteName,
        [string]$interSiteTopologyGenerator,
        [string]$subnets,
        [string]$servers,
        [string]$adjacentSites,
        [string]$siteLinks,
        [string]$bridgeheadServers
    )

     $propSite = [ordered]@{
      SiteName = $siteName
      InterSiteTopologyGenerator = $interSiteTopologyGenerator
      Subnets = $subnets
      Servers = $servers
      AdjacentSites = $adjacentSites
      SiteLinks = $siteLinks
      BridgeheadServers = $bridgeheadServers
}

    $site = New-Object -TypeName PSObject -Property $propSite

return $site
}#end of New-Site
#======================================================================================== 


#======================================================================================== 
# Construct the array of Replication Status
#======================================================================================== 
function New-Replication() 
{
    Param
    (
        [string]$SourceOrDestination ,
        [string]$ComputerName ,
        [string]$LargestDelta ,
        [string]$ReplicationFailed ,
        [string]$ReplicationTotal
    )

     $propRep = [ordered]@{
     SourceOrDestination  = $SourceOrDestination
     ComputerName  = $ComputerName
     LargestDelta  = $LargestDelta
     ReplicationFailed  = $ReplicationFailed
     ReplicationTotal  = $ReplicationTotal 
}

    $replication = New-Object -TypeName PSObject -Property $propRep

return $replication
}#end of New-Replication
#======================================================================================== 



#======================================================================================== 
# Construct the array of GPO Status
#======================================================================================== 
function New-Gpo() 
{
    Param
    (
        [string]$Domain,
        [string]$Guid,
        [string]$Name,
        [string]$Status
    )

         $propGPO = [ordered]@{
    Domain  = $Domain
    Guid  = $Guid
    Name  = $Name
    Status  = $Status
}

    $gpo = New-Object -TypeName PSObject -Property $propGPO

return $gpo
}#end of NEW-GPO
#======================================================================================== 



#======================================================================================== 
# Construct the array of Backups
#======================================================================================== 
function New-Backup() 
{
    Param
    (
        [string]$Partition ,
        [string]$LastBackupTime 
    )

         $propBKP = [ordered]@{
    Partition  = $Partition
    LastBackupTime  = $LastBackupTime
}

    $backup = New-Object -TypeName PSObject -Property $propBKP

return $backup
}#End of New-Backup
#======================================================================================== 



#======================================================================================== 
# Construct the array of Diagnostics
#======================================================================================== 
function New-Diagnosis() 
{
    Param
    (
        [string]$Target ,
        [string]$Test ,
        [string]$Result 
    )

    $propDIAG = [ordered]@{
   Target  = $Target
   Test  = $Test
   Result  = $Result
}

    $diagnosis = New-Object -TypeName PSObject -Property $propDIAG

return $diagnosis
}#end of NEW-DIAGNOSIS
#======================================================================================== 

#======================================================================================== 
# Set Value Added HTML Information 
#======================================================================================== 
function Set-ValueAddedHtmlInfo
{
    Param
    (
        [Parameter(Mandatory=$true)][ValidateSet(
            "NamingRoleOwner",
            "SchemaRoleOwner",
            "PdcRoleOwner",
            "RidRoleOwner",
            "InfrastructureRoleOwner",
            "SiteName",
            "Subnets",
            "AdjacentSites",
            "SiteLinks",
            "SuccessOrFailed",
            "Replication",
            "DFSRBacklog",
            "DFSRFolderEnabled",
            "DFSRConnectionEnabled",
            "Time")] [string]$typeOfTest = 'NamingRoleOwner',
        [string]$fieldToTest = '',
        [string]$secondaryField = ''
    )

    # ............................................
    # DFSR Backlog Test
    # ............................................
    if ($typeOfTest -eq 'DFSRBacklog')
    {
        [int]$maxBackLog = 0
        for ($j=0; $j -lt $fieldToTest.Replace('<br>','§').Split('§').Count; $j++)
        {
            if (   ($fieldToTest.Replace('<br>','§').Split('§').Get($j) -ne '') `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('Partner'))) `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('Unknown'))) `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('n/a'))) `
               )
            {
                [int]$maxBackLog = [math]::max($maxBackLog,$fieldToTest.Replace('<br>','§').Split('§').Get($j))
            }
        }
        
        if ($fieldToTest.Contains('Partner')) { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
        elseif ($fieldToTest.Contains('Unknown')) { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        elseif ($fieldToTest.Contains('n/a')) { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        elseif ($maxBackLog -gt $script:criticalBacklogLimit) { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
        elseif ($maxBackLog -gt $script:warningBacklogLimit) { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        else { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
    }
    # ............................................

    # ............................................
    # DFSR Folder Enabled Test
    # ............................................
    elseif ($typeOfTest -eq 'DFSRFolderEnabled')
    {
        [bool]$dfsrFolderEnabled = $true
        for ($j=0; $j -lt $fieldToTest.Replace('<br>','§').Split('§').Count; $j++)
        {
            if (   ($fieldToTest.Replace('<br>','§').Split('§').Get($j) -ne '') `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('Partner'))) `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('Unknown'))) `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('n/a'))) `
               )
            {
                [bool]$dfsrFolderEnabled = $dfsrFolderEnabled -and $fieldToTest.Replace('<br>','§').Split('§').Get($j)
            }
        }

        if ($fieldToTest.Contains('Partner')) { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
        elseif ($fieldToTest.Contains('Unknown')) { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        elseif ($fieldToTest.Contains('n/a')) { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        elseif ($dfsrFolderEnabled) { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
        else { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
    }
    # ............................................

    # ............................................
    # DFSR Connection Enabled Test
    # ............................................
    elseif ($typeOfTest -eq 'DFSRConnectionEnabled')
    {
        [bool]$dfsrConnectionEnabled = $true
        for ($j=0; $j -lt $fieldToTest.Replace('<br>','§').Split('§').Count; $j++)
        {
            if (   ($fieldToTest.Replace('<br>','§').Split('§').Get($j) -ne '') `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('Partner'))) `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('Unknown'))) `
              -and (!($fieldToTest.Replace('<br>','§').Split('§').Get($j).Contains('n/a'))) `
               )
            {
                [bool]$dfsrConnectionEnabled = $dfsrConnectionEnabled -and $fieldToTest.Replace('<br>','§').Split('§').Get($j)
            }
        }

        if ($fieldToTest.Contains('Partner')) { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
        elseif ($fieldToTest.Contains('Unknown')) { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        elseif ($fieldToTest.Contains('n/a')) { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        elseif ($dfsrConnectionEnabled) { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
        else { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
    }
    # ............................................

    # ............................................
    # Time Test
    # ............................................
    elseif ($typeOfTest -eq 'Time')
    {
        # Parse the Field to test to create the Date and Time
        $year = $fieldToTest.Replace(' ','').Substring(0,4)
        $month = $fieldToTest.Replace(' ','').Substring(5,2)
        $day = $fieldToTest.Replace(' ','').Substring(8,2)
        $hour = $fieldToTest.Replace(' ','').Substring(10,2)
        $minute = $fieldToTest.Replace(' ','').Substring(13,2)
        $second = $fieldToTest.Replace(' ','').Substring(16,2)
        $dateOfEvent = New-Object System.DateTime $year, $month, $day, $hour, $minute, $second, '0', ([DateTimeKind]::Utc)

        $now = Get-Date

        switch (($dateOfEvent-$now).Days)
        {
            '0' { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
            '1' { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
            '2' { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
            '3' { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
            default { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
        }
    }
    # ............................................

    # ............................................
    # Schema Master Role Owner Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'SchemaRoleOwner')
    {
        [string]$schemaMaster = $script:adConfiguration.ad.fsmo.forest.schema
        switch ($fieldToTest)
        {
            $schemaMaster { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
            default { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        }
    }
    # ............................................
    
    # ............................................
    # Naming Master Role Owner Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'NamingRoleOwner')
    {
        [string]$namingMaster = $script:adConfiguration.ad.fsmo.forest.naming
        switch ($fieldToTest)
        {
            $namingMaster { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
            default { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
        }
    }
    # ............................................

    # ............................................
    # PDC Role Owner Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'PdcRoleOwner')
    {
        [array]$pdcMaster = @()
        $pdcMaster += ''
        for ($i=0; $i -lt ($script:adConfiguration.ad.fsmo.domain).Count; $i++)
        {
            $pdcMaster += ($script:adConfiguration.ad.fsmo.domain)[$i].pdc
        }
        if ($pdcMaster.Count -eq 1)
        {
            $pdcMaster += $script:adConfiguration.ad.fsmo.domain.pdc
        }
        [bool]$configuration = $false
        for ($i=0; $i -lt  $pdcMaster.Count; $i++)
        {
            if ($pdcMaster[$i] -eq $fieldToTest)
            {
                [bool]$configuration = $true
            }
        }
        if ($configuration)
        {
            [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>'
        }
        else
        {
            [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>'
        }
    }
    # ............................................

    # ............................................
    # RID Master Role Owner Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'RidRoleOwner')
    {
        [array]$ridMaster = @()
        $ridMaster += ''
        for ($i=0; $i -lt ($script:adConfiguration.ad.fsmo.domain).Count; $i++)
        {
            $ridMaster += ($script:adConfiguration.ad.fsmo.domain)[$i].rid
        }
        if ($ridMaster.Count -eq 1)
        {
            $ridMaster += $script:adConfiguration.ad.fsmo.domain.rid
        }
        [bool]$configuration = $false
        for ($i=0; $i -lt  $ridMaster.Count; $i++)
        {
            if ($ridMaster[$i] -eq $fieldToTest)
            {
                [bool]$configuration = $true
            }
        }
        if ($configuration)
        {
            [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>'
        }
        else
        {
            [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>'
        }
    }
    # ............................................

    # ............................................
    # Infrastructure Role Owner Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'InfrastructureRoleOwner')
    {
        [array]$infrastructureMaster = @()
        $infrastructureMaster += ''
        for ($i=0; $i -lt ($script:adConfiguration.ad.fsmo.domain).Count; $i++)
        {
            $infrastructureMaster += ($script:adConfiguration.ad.fsmo.domain)[$i].infrastructure
        }
        if ($infrastructureMaster.Count -eq 1)
        {
            $infrastructureMaster += $script:adConfiguration.ad.fsmo.domain.infrastructure
        }
        [bool]$configuration = $false
        for ($i=0; $i -lt  $infrastructureMaster.Count; $i++)
        {
            if ($infrastructureMaster[$i] -eq $fieldToTest)
            {
                [bool]$configuration = $true
            }
        }
        if ($configuration)
        {
            [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>'
        }
        else
        {
            [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>'
        }
    }
    # ............................................

    # ............................................
    # Site Name Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'SiteName')
    {
        [array]$siteName = @()
        # Only one site
        if ( ($script:adConfiguration.ad.sites.site).Count -eq $null )
        {
            $siteName += ($script:adConfiguration.ad.sites.site).name
        }
        # At least two sites
        else
        {
            for ($i=0; $i -lt ($script:adConfiguration.ad.sites.site).Count; $i++)
            {
                $siteName += ($script:adConfiguration.ad.sites.site)[$i].name
            }
        }
        [bool]$configuration = $false
        for ($i=0; $i -lt  $siteName.Count; $i++)
        {
            if ($siteName[$i] -eq $fieldToTest)
            {
                [bool]$configuration = $true
            }
        }
        if ($configuration)
        {
            [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' 
        }
        else
        {
            [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>'
        }
    }
    # ............................................

    # ............................................
    # Success or Failed Test
    # ............................................
    elseif ($typeOfTest -eq 'SuccessOrFailed')
    {
        if ($fieldToTest.Contains('Success'))
        {
            [string]$fieldToTest = '<span style="color:green">Success</span>' + '<small>' + $fieldToTest.Replace('Success','') + '</small>'
        }
        else
        {
            switch ($fieldToTest)
            {
                'passed' { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
                'Policy OK' { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
                'Failed' { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
                default { [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>' }
            }
        }
    }
    # ............................................

    # ............................................
    # Replication Status Test
    # ............................................
    elseif ($typeOfTest -eq 'Replication')
    {
        if ($fieldToTest -eq 0)
        { [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>' }
        elseif ($fieldToTest -eq  65537)
        { [string]$fieldToTest = '<span style="color:red">n/a</span>' }
        else
        { [string]$fieldToTest = '<span style="color:red">' + $fieldToTest + '</span>' }
    }
    # ............................................

    # ............................................
    # Sites Links Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'SiteLinks')
    {
        # Sites Links configured in XML document
        [array]$siteLinks = @()
        $siteLinks += ''
        # Only one site
        if ( ($script:adConfiguration.ad.sites.site).Count -eq $null )
        {
            if ($script:adConfiguration.ad.sites.site.name -eq $secondaryField)
            {
                $siteLinks += ($script:adConfiguration.ad.sites.site).link
            }
        }
        # At least two sites
        else
        {
            for ($i=0; $i -lt ($script:adConfiguration.ad.sites.site).Count; $i++)
            {
                if ( ($script:adConfiguration.ad.sites.site)[$i].name -eq $secondaryField) 
                {
                    $siteLinks += ($script:adConfiguration.ad.sites.site)[$i].link
                }
            }
        }
        [array]$siteLinks = $siteLinks | Sort-Object

        # Sites Links seen in AD
        [array]$siteLinksInAD = @()
        $siteLinksInAD += ''
        for ($k=0; $k -lt $fieldToTest.Replace('<br>','§').Split('§').Count; $k++)
        {
            $siteLinkInAD = $fieldToTest.Replace('<br>','§').Split('§').Get($k)
            if ($siteLinkInAD.Length -gt 0)
            {
                $siteLinksInAD += $siteLinkInAD
            }
        }
        [array]$siteLinksInAD = $siteLinksInAD | Sort-Object
        
        # Compare
        if ( ($siteLinksInAD.GetType().ToString() -eq 'System.String') -and ($siteLinks.GetType().ToString() -eq 'System.String') )
        {
            if ( $siteLinksInAD -eq $siteLinks )
            {
                [bool]$configuration = $true
            }
        }
        elseif ( ($siteLinksInAD.GetType().ToString() -eq 'System.String') -and ($siteLinks.GetType().ToString() -ne 'System.String') )
        {
            [bool]$configuration = $false
        }
        elseif ( ($siteLinksInAD.GetType().ToString() -ne 'System.String') -and ($siteLinks.GetType().ToString() -eq 'System.String') )
        {
            [bool]$configuration = $false
        }
        elseif ($siteLinksInAD.Count -eq $siteLinks.Count)
        {
            [bool]$configuration = $true
            for ($k=0; $k -lt $siteLinksInAD.Count; $k++)
            {
                if ($siteLinksInAD.Get($k) -ne $siteLinks.Get($k))
                {
                    [bool]$configuration = $false
                }
            }
        }
        else
        {
            [bool]$configuration = $false
        }
        
        # Generate result
        if ($configuration)
        {
            [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>'
        }
        else
        {
            [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>'
        }
    }
    # ............................................

    # ............................................
    # Subnets Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'Subnets')
    {
        # Subnets configured in XML document
        [array]$subnets = @()
        $subnets += ''
        # Only one site
        if ( ($script:adConfiguration.ad.sites.site).Count -eq $null )
        {
            if ($script:adConfiguration.ad.sites.site.name -eq $secondaryField)
            {
                $subnets += ($script:adConfiguration.ad.sites.site).subnet
            }
        }
        # At least two sites
        else
        {
            for ($i=0; $i -lt ($script:adConfiguration.ad.sites.site).Count; $i++)
            {
                if ( ($script:adConfiguration.ad.sites.site)[$i].name -eq $secondaryField) 
                {
                    $subnets += ($script:adConfiguration.ad.sites.site)[$i].subnet
                }
            }
        }
        [array]$subnets = $subnets | Sort-Object
        
        #Subnets seen in AD
        [array]$subnetsInAD = @()
        $subnetsInAD += ''
         for ($k=0; $k -lt $fieldToTest.Replace('<br>','§').Split('§').Count; $k++)
        {
            $subnetInAD = $fieldToTest.Replace('<br>','§').Split('§').Get($k)
            if ($subnetInAD.Length -gt 0)
            {
                $subnetsInAD += $subnetInAD
            }
        }
        [array]$subnetsInAD = $subnetsInAD | Sort-Object

        
        # Compare
        if ( ($subnetsInAD.GetType().ToString() -eq 'System.String') -and ($subnets.GetType().ToString() -eq 'System.String') )
        {
            if ( $subnetsInAD -eq $subnets )
            {
                [bool]$configuration = $true
            }
        }
        elseif ( ($subnetsInAD.GetType().ToString() -eq 'System.String') -and ($subnets.GetType().ToString() -ne 'System.String') )
        {
            [bool]$configuration = $false
        }
        elseif ( ($subnetsInAD.GetType().ToString() -ne 'System.String') -and ($subnets.GetType().ToString() -eq 'System.String') )
        {
            [bool]$configuration = $false
        }
        elseif ($subnetsInAD.Count -eq $subnets.Count)
        {
            [bool]$configuration = $true
            for ($k=0; $k -lt $subnetsInAD.Count; $k++)
            {
                if ($subnetsInAD.Get($k) -ne $subnets.Get($k))
                {
                    [bool]$configuration = $false
                }
            }
        }
        else
        {
            [bool]$configuration = $false
        }

        # Generate result
        if ($configuration)
        {
            [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>'
        }
        else
        {
            [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>'
        }
    }
    # ............................................

    # ............................................
    # Adjacent Sites Test Configuration
    # ............................................
    elseif ($typeOfTest -eq 'AdjacentSites')
    {
        # Adjacent Sites configured in XML document
        # Powershell v3 only: $adjacentSites += ($script:adConfiguration.ad.sites.site | Where-Object name -eq $secondaryField).adjacent
        [array]$adjacentSites = @()
        $adjacentSites += ''
        for ($i=0; $i -lt ($script:adConfiguration.ad.sites.site).Count; $i++)
        {
            if ( ($script:adConfiguration.ad.sites.site)[$i].name -eq $secondaryField) 
            {
                $adjacentSites += ($script:adConfiguration.ad.sites.site)[$i].adjacent
            }
        }
        [array]$adjacentSites = $adjacentSites | Sort-Object

        # Adjacent Sites seen in AD
        [array]$adjacentSitesInAD = @()
        $adjacentSitesInAD += ''
        for ($k=0; $k -lt $fieldToTest.Replace('<br>','§').Split('§').Count; $k++)
        {
            $adjacentSiteInAD = $fieldToTest.Replace('<br>','§').Split('§').Get($k)
            if ($adjacentSiteInAD.Length -gt 0)
            {
                $adjacentSitesInAD += $adjacentSiteInAD
            }
        }
        [array]$adjacentSitesInAD = $adjacentSitesInAD | Sort-Object

        # Compare
        if ( ($adjacentSitesInAD.GetType().ToString() -eq 'System.String') -and ($adjacentSites.GetType().ToString() -eq 'System.String') )
        {
            if ( $adjacentSitesInAD -eq $adjacentSites )
            {
                [bool]$configuration = $true
            }
        }
        elseif ( ($adjacentSitesInAD.GetType().ToString() -eq 'System.String') -and ($adjacentSites.GetType().ToString() -ne 'System.String') )
        {
            [bool]$configuration = $false
        }
        elseif ( ($adjacentSitesInAD.GetType().ToString() -ne 'System.String') -and ($adjacentSites.GetType().ToString() -eq 'System.String') )
        {
            [bool]$configuration = $false
        }
        if ($adjacentSitesInAD.Count -eq $adjacentSites.Count)
        {
            [bool]$configuration = $true
            for ($k=0; $k -lt $adjacentSitesInAD.Count; $k++)
            {
                if ($adjacentSitesInAD.Get($k) -ne $adjacentSites.Get($k))
                {
                    [bool]$configuration = $false
                }
            }
        }
        else
        {
            [bool]$configuration = $false
        }

        # Generate result
        if ($configuration)
        {
            [string]$fieldToTest = '<span style="color:green">' + $fieldToTest + '</span>'
        }
        else
        {
            [string]$fieldToTest = '<span style="color:#ffaf00">' + $fieldToTest + '</span>'
        }
    }
    # ............................................

    return $fieldToTest
}
#======================================================================================== 


#########################################################################################
# Main
#########################################################################################
# Set the location to the current PowerShell script location
$scriptDirectory = Split-Path -parent $MyInvocation.MyCommand.Definition
Set-Location -Path $scriptDirectory

# Set filenames and Delete old log file
$outputFile = $scriptDirectory + '\' + $outputFile

$logFilename = $scriptDirectory + '\' + $logFilename

Remove-Item $logFilename -ErrorAction SilentlyContinue

Write-Log ('----------------------------------------------------------------------------------------------------')

Write-Log ('------------------------------------- START on ' + $env:computername + ' ---------------------------------------')


# ----------------------------------------------------------------------------------------------------------------
# Get the AD Configuration
# ----------------------------------------------------------------------------------------------------------------
[XML]$script:adConfiguration = Get-Content -Path ($scriptDirectory + '\' + $configurationFile)
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Validate XML against an XSD schema
# ----------------------------------------------------------------------------------------------------------------
# Get the file
$xmlFile = Get-Item -Path ($scriptDirectory + '\' + $configurationFile)

# Keep count of how many errors there are in the XML file
[int]$script:errorCount = 0

# Perform the XSD Validation
$readerSettings = New-Object -TypeName System.Xml.XmlReaderSettings
$readerSettings.ValidationType = [System.Xml.ValidationType]::Schema
$readerSettings.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessInlineSchema -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessSchemaLocation
$readerSettings.add_ValidationEventHandler(
{
    # Triggered each time an error is found in the XML file
    Write-Log ('Error found in XML: ' + $_.Message)
    Write-Host $("`nError found in XML: " + $_.Message + "`n") -ForegroundColor Red
    $script:errorCount++
});
$reader = [System.Xml.XmlReader]::Create($xmlFile.FullName, $readerSettings)
while ($reader.Read()) { }
$reader.Close()

# Verify the results of the XSD validation
if($script:errorCount -gt 0)
{
    # XML is NOT valid
    exit 1
}
else
{
    Write-Log ("Running a $scope Health Check")
    Write-Log ("Script version: $ScriptVersion")
    Write-Log ('XML file is correct')
}
# ----------------------------------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------------------------------
# List all DCs Current Domain
# ----------------------------------------------------------------------------------------------------------------
$DCs += Get-AllDCs | Sort-Object

[int]$numberOfDCs = $DCs.Count

Write-Log ('----------------------------------------------------------------------------------------------------')

# ----------------------------------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------------------------------
# List all DCs Current Forrest
# ----------------------------------------------------------------------------------------------------------------
#======================================================================================== 
# Get all DCs in current forest
#======================================================================================== 
function Get-AllDCsCurrentForrest
{
    $forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
    [array]$DCsF = @()
    $DCsF += $forest.domains | %{$_.DomainControllers} | %{$_.Name}
    return $DCsF
}
#======================================================================================== 
$DCsF += Get-AllDCsCurrentForrest

[int]$numberOfDCsF = $DCsF.Count

Write-Log ('----------------------------------------------------------------------------------------------------')

# ----------------------------------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------------------------------
# Creating the list of DCs responding to rpc or limits to a single Dc if tests are limited
# ----------------------------------------------------------------------------------------------------------------
Write-Log ('Creating the list of responding DCs')
# Get the current DC
[string]$currentServer = ([ADSI]LDAP://RootDSE).dnshostname.ToString()
[string]$currentServer = $currentServer.Split('.').Get(0).ToLower()

# Create the list of DCs to test
# Depending on the scope
if ($scope.ToLower() -eq 'full')
{
    foreach ($dc in $dcs)
    {
        # Only get the DCs responding to rpc
        [string]$server = $dc.Split('.').Get(0).ToLower()
        [array]$connection = Test-TcpConnection -Computer $dc -Port '135'
        if ($connection[0])
        {
            [string]$server = $dc.Split('.').Get(0).ToLower()
            $servers += $server
            Write-Log ($dc + ' is listening on Port tcp/135')
        }
        else
        {
            Write-Log ($dc + ' is not listening on Port tcp/135')
        }
        Write-Log ('    Message: ' + $connection[1])
    }
}
else
{
    $servers += $currentServer
}
Write-Log ('----------------------------------------------------------------------------------------------------')
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Start the dcdiag Status
# ----------------------------------------------------------------------------------------------------------------
Write-Log ("Starting dcdiag status")


[string]$random = Get-Random
New-Item -Path 'trash' -ItemType directory -ErrorAction SilentlyContinue

# Remove Files older than 2 days
$olderFiles += Get-ChildItem -Path ('.\trash\*.*') | Where-Object { $_.LastWriteTimeUtc -lt ((Get-Date).AddDays(-2)) }
if ($olderFiles.Count -gt 1)
{
    Remove-Item -Path $olderFiles -ErrorAction SilentlyContinue
}


# Create the job for each DC
foreach ($server in $servers)
{
    [string]$cmd = 'dcdiag.exe'
    [string]$arg1 = '/s:' + $server
    [string]$outputOverall = $scriptDirectory + '\trash\' + $server + '_overall_' + $random + '.log'
    [string]$outputDns = $scriptDirectory + '\trash\' + $server + '_dns_' + $random + '.log'
    [string]$scriptPowershellOverall = $scriptDirectory + '\trash\' + $server + '_overall_' + $random + '.ps1'
    [string]$scriptPowershellDNS = $scriptDirectory + '\trash\' + $server + '_dns_' + $random + '.ps1'
    [string]$arg2 = '/f:"' + $output + '"'

    # Limited tests only (in this case '$server -eq $currentServer')
    if ($scope.ToLower() -eq 'limited')
    {
        [string]$scriptOverall = 'dcdiag.exe /s:' + $server + ' /i /skip:SystemLog /skip:OutboundSecureChannels /skip:Dns /skip:DFSREvent /f:"' + $outputOverall +'"'
        [string]$scriptDns = 'dcdiag.exe /s:' + $server + ' /i /test:dns /DnsBasic /f:"' + $outputDns +'"'
    }
    # Some tests will be done only on the current DC
    elseif ($server -eq $currentServer)
    {
        [string]$scriptOverall = 'dcdiag.exe /s:' + $server + ' /c /i /skip:SystemLog /skip:OutboundSecureChannels /skip:Dns /skip:DFSREvent /f:"' + $outputOverall +'"'
        [string]$scriptDns = 'dcdiag.exe /s:' + $server + ' /i /test:dns /DnsBasic /DnsRecordRegistration /DnsDynamicUpdate /f:"' + $outputDns +'"'
    }
    # Limits the tests on other DCs
    else
    {
        [string]$scriptOverall = 'dcdiag.exe /s:' + $server + ' /c /i /skip:SystemLog /skip:OutboundSecureChannels /skip:Dns /skip:DFSREvent /skip:CheckSDRefDom /skip:CrossRefValidation /skip:LocatorCheck /skip:FsmoCheck /skip:Intersite /f:"' + $outputOverall +'"'
        [string]$scriptDns = 'dcdiag.exe /s:' + $server + ' /i /test:dns /DnsBasic /DnsRecordRegistration /DnsDynamicUpdate /f:"' + $outputDns +'"'
    }

    Write-Log ("Starting '$scriptOverall'" )
    $jobsDcdiag += Start-Job -Name ($server + '_dcdiag') -InitializationScript ([scriptblock]::Create("$scriptOverall")) -ScriptBlock { }
    Write-Log ("Starting '$scriptDns'" )
    $jobsDcdiag += Start-Job -Name ($server + '_dcdiag') -InitializationScript ([scriptblock]::Create("$scriptDns")) -ScriptBlock { }
}
Write-Log ('----------------------------------------------------------------------------------------------------')
# ----------------------------------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------------------------------
# Start the DFSR Outband Infos including the BackLog Counters
# ----------------------------------------------------------------------------------------------------------------
Write-Log ("Starting DFSR Outband Infos")

foreach ($server in $servers)
{
    Write-Log ("Starting DFSR Analyzing for '$server'" )
    $jobsDfsr += Start-Job -Name ($server + '_dfsr') -InitializationScript $getdFSROutbandInfo -ScriptBlock { param($arg1) Get-DFSROutbandInfo -Computer $arg1 } -ArgumentList $server
}
Write-Log ('----------------------------------------------------------------------------------------------------')
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Get the Forest configuration
# ----------------------------------------------------------------------------------------------------------------
[string]$forestName = Get-CurrentForest
Write-Log ('Adding forest ' + $forestName)

[int]$numberOfSites = Get-NumberOfSites
[int]$numberOfDomains = Get-NumberOfDomains
[int]$numberOfSitesWithDC = Get-NumberOfSitesWithDC
[string]$schemaRoleOwner = Get-SchemaRoleOwner
[string]$namingRoleOwner = Get-NamingRoleOwner
[string]$forestMode = Get-ForestMode

Write-Log ('Forest Mode: ' + $forestMode)
Write-Log ('Schema Role Owner: ' + $schemaRoleOwner)
Write-Log ('Naming Role Owner: ' + $namingRoleOwner)

# Add the Value-Added HTML info
[string]$schemaRoleOwner = Set-ValueAddedHtmlInfo -FieldToTest $schemaRoleOwner -TypeOfTest 'SchemaRoleOwner'
[string]$namingRoleOwner = Set-ValueAddedHtmlInfo -FieldToTest $namingRoleOwner -TypeOfTest 'NamingRoleOwner'

Write-Log ('----------------------------------------------------------------------------------------------------')
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Get the Domains configuration
# ----------------------------------------------------------------------------------------------------------------
$domains += Get-AllDomains
foreach ($domain in $domains)
{
    Write-Log ('Adding domain ' + $domain)

    [string]$domainMode = Get-DomainMode -Domain $domain
    [string]$domainName = Get-DomainName -Domain $domain
    [string]$pdcRoleOwner = Get-PdcRoleOwner -Domain $domain
    [string]$ridRoleOwner = Get-RidRoleOwner -Domain $domain
    [string]$infrastructureRoleOwner = Get-InfrastructureRoleOwner -Domain $domain

    Write-Log ('Domain Mode: ' + $domainMode)
    Write-Log ('PDC Role Owner: ' + $pdcRoleOwner)
    Write-Log ('RID Role Owner: ' + $ridRoleOwner)
    Write-Log ('Infrastructure Role Owner: ' + $infrastructureRoleOwner)

    # Get the % of available RID
    #if ( (Test-Ping -ComputerName $ridRoleOwner).Get(0) )
    if ( (Test-TcpConnection -Computer $ridRoleOwner -Port '389').Get(0) )
    {
        $root = New-Object DirectoryServices.DirectoryEntry ('LDAP://' + $ridRoleOwner)
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $root
        $searcher.PageSize = 1
        $searcher.Filter = '(cn=rid manager$)'
        $rid = $searcher.FindAll()
        [long]$ridAvailablePool = [long][string]$rid.item(0).Properties.ridavailablepool
        [long]$TotalSIDS = $ridAvailablePool / ([math]::Pow(2,32))
        [long]$temp64Val = $TotalSIDS * ([math]::Pow(2,32))
        [long]$currentRidPoolCount = $ridAvailablePool  $temp64Val
        [long]$ridsRemaining = $totalSIDS  $currentRidPoolCount
        [double]$ridsIssuedPcntOfTotal = ( $currentRIDPoolCount / $totalSIDS )
        [string]$ridsIssuedPercentofTotal = "{0:P3}" -f $RIDsIssuedPcntOfTotal
        [double]$ridsRemainingPcntOfTotal = ( $ridsRemaining / $totalSIDS )
        [string]$ridsRemainingPercentofTotal = "{0:P3}" -f $ridsRemainingPcntOfTotal
        Write-Log ('RID Available Pool: ' + $ridAvailablePool)
        Write-Log ('Total SIDS: ' + $totalSIDS)
        Write-Log ('current RID Pool Count: ' + $currentRidPoolCount)
        Write-Log ('RIDs Issued Pcnt of Total: ' + $ridsIssuedPcntOfTotal)
        Write-Log ('RIDs Issued Percent of Total: ' + $ridsIssuedPercentofTotal)
        Write-Log ('RIDs Remaining Pcnt of Total: ' + $ridsRemainingPcntOfTotal)
    }
    else
    {
        [string]$ridsRemainingPercentofTotal = 'not evaluated'
    }
    Write-Log ('RIDs Remaining Percent of Total: ' + $ridsRemainingPercentofTotal)

    # Add the Value-Added HTML info
    [string]$pdcRoleOwner = Set-ValueAddedHtmlInfo -FieldToTest $pdcRoleOwner -TypeOfTest 'PdcRoleOwner'
    [string]$ridRoleOwner = Set-ValueAddedHtmlInfo -FieldToTest $ridRoleOwner -TypeOfTest 'RidRoleOwner'
    [string]$infrastructureRoleOwner = Set-ValueAddedHtmlInfo -FieldToTest $infrastructureRoleOwner -TypeOfTest 'InfrastructureRoleOwner'

    $domainsConfiguration += New-Domain -DomainMode $domainMode `
                                        -DomainName $domainName `
                                        -PdcRoleOwner $pdcRoleOwner `
                                        -RidRoleOwner $ridRoleOwner `
                                        -InfrastructureRoleOwner $infrastructureRoleOwner `
                                        -RIDsRemainingPercent $ridsRemainingPercentofTotal
                              
    Write-Log ('----------------------------------------------------------------------------------------------------')
}

# Sort the Domains
[array]$domainsConfiguration  = $domainsConfiguration | Sort-Object -Property DomainName
# ----------------------------------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------------------------------
# Get the GPO Status
# ----------------------------------------------------------------------------------------------------------------
Write-Log ("Starting GPO Analysis")
Write-Log ('............................................................')

# Initialization
[int]$numberOfPolicies = 0

[string]$cmd = '.\gpotool.exe'

#SCOPE FULL OR DOMAIN
if ($Level -eq 'Forest'){

# Parse all domains
    foreach ($domain in $domains)
    {
        [array]$gpoToolRaw = @()
        [array]$gpoTool = @()

        [string]$server = Get-PdcRoleOwner -Domain $domain
        Write-Log ('Domain: ' + $domain)
        
        Write-Log ('PDC Emulator to use: ' + $server)

        # The Test!
        [string]$arg1 = '/domain:' + $domain.Name
        [string]$arg2 = '/dc:' + $server
        if ( (Test-Ping -ComputerName $server).Get(0) )
        {
            # .........................................................................
            # Analysis the GPOs
            # .........................................................................
            Write-Log ('............................................................')
            $gpoToolRaw += & $cmd $arg1 $arg2
            [bool]$firstPolicy = $true
            foreach ($line in $gpoToolRaw)
            {
                    Write-Log ($line)
                # Get rid of garbage lines
                if (     !$line.StartsWith('Validating DCs...') `
                    -and !$line.StartsWith('Available DCs:') `
                    -and !$line.StartsWith($server) `
                    -and !$line.StartsWith('Searching for policies...') `
                    -and !$line.StartsWith('Found ') `
                    -and !$line.StartsWith('Policies ') `
                   )
                {
                    if (!$firstPolicy)
                    {
                        $gpoTool += $line
                    }
                    else
                    {
                        [bool]$firstPolicy = $false
                    }
                }
            }
            # .........................................................................
        
            # .........................................................................
            # Add the GPO infos
            # .........................................................................
            [string]$gpoGuid = ''
            [string]$gpoResult = ''
            [string]$gpoName = ''

            for ($i=0; $i -le $gpotool.Count-1; $i++)
            {
                # Start of a new GPO
                if ( $gpotool.get($i).StartsWith('Policy {') )
                {
                    [string]$gpoGuid = $gpotool.get($i).Substring(8,36)
                    [string]$gpoResult = ''
                    [string]$gpoName = ''
                    $numberOfPolicies++
                }
    
                # Get the friendly name the GPO
                elseif ( $gpotool.get($i).StartsWith('Friendly name:') )
                {
                    [string]$gpoName = $gpotool.get($i).Substring(15,$gpotool.get($i).Length-15)
                }

                # Get the status of the GPO
                elseif ( !($gpotool.get($i).StartsWith('============================================================')) )
                {
                    $gpoResult += $gpotool.get($i) + '<br>'
                }

                # Dump the info
                elseif ( $gpotool.get($i).StartsWith('============================================================') )
                {
                    # Remove the final '<br>'
                    [string]$gpoResult = $gpoResult.Substring(0,$gpoResult.Length-4)

                    Write-Log ("Found '" + $gpoName + "' {"+ $gpoGuid +"} with status '" + $gpoResult + "'")

                    # Add the Value-Added HTML info
                    [string]$gpoResult = Set-ValueAddedHtmlInfo -FieldToTest $gpoResult -TypeOfTest 'SuccessOrFailed'

                    $gpoStatus += New-Gpo -Domain $domain `
                                          -Guid $gpoGuid `
                                          -Name $gpoName `
                                          -Status $gpoResult
                }
            }
            # .........................................................................

        }
        else
        {
            Write-Log ('not evaluated')
        }

        Remove-Variable -Name gpoToolRaw -ErrorAction SilentlyContinue
    
        Remove-Variable -Name gpoTool -ErrorAction SilentlyContinue
    }#End of ForEach

}#End of IF Forest
else{
 
    [array]$gpoToolRaw = @()
    
    [array]$gpoTool = @()

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    [string]$server = Get-PdcRoleOwner
    
    Write-Log ('Domain: ' + $domain)
    
    Write-Log ('PDC Emulator to use: ' + $server)

    # The Test!
    [string]$arg = '/dc:' + $server

    if ( (Test-Ping -ComputerName $server).Get(0) )
    {
        # .........................................................................
        # Analysis the GPOs
        # .........................................................................
        Write-Log ('............................................................')
        $gpoToolRaw += & $cmd $arg
        
        [bool]$firstPolicy = $true
        
        foreach ($line in $gpoToolRaw)
        {
            Write-Log ($line)
            # Get rid of garbage lines
            if (     !$line.StartsWith('Validating DCs...') `
                -and !$line.StartsWith('Available DCs:') `
                -and !$line.StartsWith($server) `
                -and !$line.StartsWith('Searching for policies...') `
                -and !$line.StartsWith('Found ') `
                -and !$line.StartsWith('Policies ') `
               )
            {
                if (!$firstPolicy)
                {
                    $gpoTool += $line
                }
                else
                {
                    [bool]$firstPolicy = $false
                }
            }
        }
        # .........................................................................
        
        # .........................................................................
        # Add the GPO infos
        # .........................................................................
        [string]$gpoGuid = ''
        [string]$gpoResult = ''
        [string]$gpoName = ''

        for ($i=0; $i -le $gpotool.Count-1; $i++)
        {
            # Start of a new GPO
            if ( $gpotool.get($i).StartsWith('Policy {') )
            {
                [string]$gpoGuid = $gpotool.get($i).Substring(8,36)
                [string]$gpoResult = ''
                [string]$gpoName = ''
                $numberOfPolicies++
            }
    
            # Get the friendly name the GPO
            elseif ($gpotool.get($i).StartsWith('Friendly name:') )
            {
                [string]$gpoName = $gpotool.get($i).Substring(15,$gpotool.get($i).Length-15)
            }

            # Get the status of the GPO
            elseif ( !($gpotool.get($i).StartsWith('============================================================')) )
            {
                $gpoResult += $gpotool.get($i) + '<br>'
            }

            # Dump the info
            elseif ( $gpotool.get($i).StartsWith('============================================================') )
            {
                # Remove the final '<br>'
                [string]$gpoResult = $gpoResult.Substring(0,$gpoResult.Length-4)

                Write-Log ("Found '" + $gpoName + "' {"+ $gpoGuid +"} with status '" + $gpoResult + "'")

                # Add the Value-Added HTML info
                [string]$gpoResult = Set-ValueAddedHtmlInfo -FieldToTest $gpoResult -TypeOfTest 'SuccessOrFailed'

                $gpoStatus += New-Gpo -Domain $domain `
                                      -Guid $gpoGuid `
                                      -Name $gpoName `
                                      -Status $gpoResult
            }
        }
        # .........................................................................

    }
    else
    {
        Write-Log ('not evaluated')
    }

Remove-Variable -Name gpoToolRaw -ErrorAction SilentlyContinue

Remove-Variable -Name gpoTool -ErrorAction SilentlyContinue

}#End of Else

# Sort the GPO Status
[array]$gpoStatus  = $gpoStatus | Sort-Object -Property Domain,Name

Write-Log ('----------------------------------------------------------------------------------------------------')

# ----------------------------------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------------------------------
# Get the Sites configuration
# ----------------------------------------------------------------------------------------------------------------
$sites += Get-AllSites
foreach ($site in $sites)
{
    Write-Log ('Adding site ' + $site)

    # Get all infos from functions!
    [string]$siteName = Get-SiteName -Site $site
    [string]$interSiteTopologyGenerator = Get-InterSiteTopologyGenerator -Site $site
    [string]$subnets = Get-Subnets -Site $site
    [string]$siteServers = Get-SiteServers -Site $site
    [string]$adjacentSites = Get-AdjacentSites -Site $site
    [string]$siteLinks = Get-SiteLinks -Site $site
    [string]$bridgeheadServers = Get-BridgeheadServers -Site $site

    Write-Log ('Subnets: ' + $subnets.Replace('<br>','; '))
    Write-Log ('Inter Site Topology Generator: ' + $interSiteTopologyGenerator)
    Write-Log ('Site Servers: ' + $siteServers.Replace('<br>','; '))
    Write-Log ('Adjacent Sites: ' + $adjacentSites.Replace('<br>','; '))
    Write-Log ('Site Links: ' + $siteLinks.Replace('<br>','; '))
    Write-Log ('Bridgehead Servers: ' + $bridgeheadServers.Replace('<br>','; '))

    # Add the Value-Added HTML info
    [string]$siteLinks = Set-ValueAddedHtmlInfo -FieldToTest $siteLinks -TypeOfTest 'SiteLinks' -SecondaryField $siteName
    [string]$subnets = Set-ValueAddedHtmlInfo -FieldToTest $subnets -TypeOfTest 'Subnets' -SecondaryField $siteName
    [string]$adjacentSites = Set-ValueAddedHtmlInfo -FieldToTest $adjacentSites -TypeOfTest 'AdjacentSites' -SecondaryField $siteName
    [string]$siteName = Set-ValueAddedHtmlInfo -FieldToTest $siteName -TypeOfTest 'SiteName'

    $sitesConfiguration += New-Site -SiteName $siteName `
                                    -InterSiteTopologyGenerator $interSiteTopologyGenerator `
                                    -Subnets $subnets `
                                    -Servers $siteServers `
                                    -AdjacentSites $adjacentSites `
                                    -SiteLinks $siteLinks `
                                    -BridgeheadServers $bridgeheadServers
                              
    Write-Log ('----------------------------------------------------------------------------------------------------')
}

# Sort the Sites
[array]$sitesConfiguration  = $sitesConfiguration | Sort-Object -Property SiteName
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Get the Backups Date and Time
# ----------------------------------------------------------------------------------------------------------------
# The Test!
$repadminShowbackup += @(repadmin /showbackup)

# Remove some garbage caracters
[array]$repadminShowbackup = $repadminShowbackup | Where-Object { $_ }

# Log the result
foreach ($line in $repadminShowbackup)
{
    Write-Log ($line)
}
Write-Log ('............................................................')

# Initialization
[int]$numberOfBackups = 0

foreach ($line in $repadminShowbackup)
{
    # Get the name of the partition
    if ($line.Contains('DC='))
    {
        $partition = $line
    }
    
    # Get the time of the backup
    # It corresponds to the line next the partition name
    if ($line.Contains('dSASignature'))
    {
        # Remove Unnecessary "double" space ('  ')
        [string]$line = [system.String]::Join(" ", ($line.Split("",[StringSplitOptions]::RemoveEmptyEntries)))

        [string]$backupTime = $line.Split(' ').Get(3) + ' ' + $line.Split(' ').Get(4)

        $numberOfBackups++
        Write-Log ("Partition '" + $partition + "' last backup time: " + $backupTime)

        # Add the Value-Added HTML info
        [string]$backupTime = Set-ValueAddedHtmlInfo -FieldToTest $backupTime -TypeOfTest 'Time'

        $backups += New-Backup -Partition $partition `
                               -LastBackupTime $backupTime

    } 
          
}
Write-Log ('----------------------------------------------------------------------------------------------------')

# Sort the Backups
[array]$backups  = $backups | Sort-Object -Property Partition
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Get the Replications Status
# ----------------------------------------------------------------------------------------------------------------
Write-Log ("Addding the Replication status")

# The Test!
$repadminReplsum  += @(repadmin /replsum /sort:delta)

# Remove some garbage caracters
[array]$repadminReplsum = $repadminReplsum | Where-Object { $_ }

# Log the result
foreach ($line in $repadminReplsum)
{
    Write-Log ($line)
}
Write-Log ('............................................................')

# Initialization
[int]$numberOfReplications = 0
[string]$sourceOrDestination = ''
[bool]$lastLine = $false

foreach ($line in $repadminReplsum)
{
    # Get the first words to use switch
    [string]$firstWords = $line.Split(' ').Get(0)  + $line.Split(' ').Get(1) + $line.Split(' ').Get(2)

    # If $firstWord contains 1 or more '.' than set it to '[Dots]'
    [int] $numberOfDots = $firstWords.Length -  $firstWords.Replace('.','').Length
    if ($numberOfDots -ge 1 )
    {
        [string]$firstWords = '[Dots]'
    }
         
    # Analysis the $firstWord
    switch ($firstWords)
    {
        'ReplicationSummaryStart' {}
        'Beginningdatacollection' {}
        '[Dots]' {}
        'SourceDC' { [string]$sourceOrDestination = 'Source DC' }
        'DestinationDC' { [string]$sourceOrDestination = 'Destination DC' }
        'SourceDSA' { [string]$sourceOrDestination = 'Source DC' }
        'DestinationDSA' { [string]$sourceOrDestination = 'Destination DC' }

        # In case of error, there is only one line available
        'Experiencedthefollowing' { [bool]$lastLine = $true }
        
        
        # The 'default' are DC
        default
        {
            # If the server generated an error just before then the outpout is different
            if ( $lastLine -eq $true )
            {            
                [string]$server = $line.Substring(15,$line.Length-15).Split('.').Get(0)
                Write-Log ('Adding Replication Status for ' + $server)
                
                [string]$sourceOrDestination = 'n/a'
                [string]$largestDelta = 'n/a'
                [int]$replicationFailed = 0
                [int]$replicationTotal = 0
            }
            # If the server did not generate any error
            else
            {            
                [string]$server = $line.Split(' ').Get(1)
                Write-Log ('Adding Replication Status for ' + $server + ' as a ' + $sourceOrDestination)

                [string]$largestDelta = $line.Substring(19,16).Replace(' ','')
                [string]$replicationFailed = $line.Substring(37,3).Replace(' ','')
                [string]$replicationTotal = $line.Substring(43,3).Replace(' ','')
            }

            $numberOfReplications++
            
            # Add the Value-Added HTML info
            [string]$replicationFailed = Set-ValueAddedHtmlInfo -FieldToTest $replicationFailed -TypeOfTest 'Replication'

            $replications += New-Replication -SourceOrDestination $sourceOrDestination `
                                             -Computer $server `
                                             -LargestDelta $largestDelta `
                                             -ReplicationFailed $replicationFailed `
                                             -ReplicationTotal $replicationTotal
        }

    }
}

Write-Log ('----------------------------------------------------------------------------------------------------')



# Adding the Summary at the end of the arrray
# Initialization
#[int]$total = $numberOfReplications/2
[string]$sourceOrDestinationLast = ''
[string]$sourceOrDestinationNew = ''
[string]$largestDelta = ''
[string]$replicationFailed = ''
[string]$replicationTotal = ''
[string]$server = ''
[int]$numberOfReplicationsSummaries = 0

for ($j=0; $j -le $numberOfReplications-1; $j++)
{
    $sourceOrDestination = $replications.Get($j).SourceOrDestination
    
    # if $sourceOrDestinationNew and $sourceOrDestinationLast are equal that we need to add info into the same summary
    if ($sourceOrDestination -eq $sourceOrDestinationLast)
    {
        $largestDelta += '<br>' + $replications.Get($j).LargestDelta
        $replicationFailed += '<br>' + $replications.Get($j).ReplicationFailed
        $replicationTotal += '<br>' + $replications.Get($j).ReplicationTotal
        $server += '<br>' + $replications.Get($j).ComputerName
    }

    # if $sourceOrDestinationNew and $sourceOrDestinationLast are different that we need to start a new summary
    if ($sourceOrDestination -ne $sourceOrDestinationLast)
    {
        $sourceOrDestinationLast = $sourceOrDestination
        $largestDelta = $replications.Get($j).LargestDelta 
        $replicationFailed = $replications.Get($j).ReplicationFailed 
        $replicationTotal = $replications.Get($j).ReplicationTotal 
        $server = $replications.Get($j).ComputerName
    }

    # Check if this is the last test of the same target
    if ($replications.Count -eq ($j+1))
    {
        [string]$sourceOrDestinationNew = 'Last Event'
    }
    else
    {
        [string]$sourceOrDestinationNew = $replications.Get($j+1).SourceOrDestination
    }
    if ($sourceOrDestination -ne $sourceOrDestinationNew)
    {
        $numberOfReplicationsSummaries ++        

        # Add the summary
        $replications += New-Replication -SourceOrDestination $sourceOrDestination `
                                         -Computer $server `
                                         -LargestDelta $largestDelta `
                                         -ReplicationFailed $replicationFailed `
                                         -ReplicationTotal $replicationTotal
    }

}
# ----------------------------------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------------------------------
# Connectivity of all DCs
# ----------------------------------------------------------------------------------------------------------------
foreach ($DC in $DCs)
{

    [string]$server = $DC.Split('.')[0].ToLower()
    Write-Log ('Adding server ' + $server + ' Connectivity')

    # .........................................................................
    # FQDN retrival
    # .........................................................................
    [string]$fqdn = ''
    [array]$serverSplit = $DC.Split('.')
    for ($i=1; $i -lt ($serverSplit.Count); $i++)
    {
        $fqdn += $DC.Split('.')[$i].ToLower() + '.'
    }
    # .........................................................................

    # .........................................................................
    # Remove the final '.'
    # .........................................................................
    [string]$fqdn = $fqdn.Substring(0,$fqdn.Length-1).ToLower()
    # .........................................................................
    
    # .........................................................................
    # Ping FQDN
    # .........................................................................
    Write-Log ('Trying to ping ' + $server + '.' + $fqdn)
    [array]$ping = @()
    $ping += Test-Ping -ComputerName ($server + '.' + $fqdn)
    if ($ping[0])
    {
        [string]$pingFqdn = 'Success (' +  $ping[2] + ' ms)'
        Write-Log ('    Ping ' + $server + '.' + $fqdn + ' was successful (round trip time = ' + $ping[2] + ' ms)')
    }
    else
    {
        [string]$pingFqdn = 'Failed'
        Write-Log ('    Ping ' + $server + '.' + $fqdn + ' failed')
    }
    Write-Log ('    Message: ' + $ping[1])
    # .........................................................................

    # .........................................................................
    # Ping short name
    # .........................................................................
    Write-Log ('Trying to ping ' + $server)
    [array]$ping = @()
    $ping += Test-Ping -ComputerName $server
    if ($ping[0])
    {
        [string]$pingShortName = 'Success (' +  $ping[2] + ' ms)'
        Write-Log ('    Ping ' + $server + ' was successful (round trip time = ' + $ping[2] + ' ms)')
    }
    else
    {
        [string]$pingShortName = 'Failed'
        Write-Log ('    Ping ' + $server + ' failed')
    }
    Write-Log ('    Message: ' + $ping[1])
    # .........................................................................
    

    #ONLY TRY TO CONNECT IF PING FQDN OR PING SHORT NAME IS OK
    if (($pingShortName -match 'Success') -or ($pingFqdn -match 'Success')){
    
            # .........................................................................
            # Port tcp/53 (DNS)
            # .........................................................................
            Write-Log ('Trying to open DNS Port tcp/53 on ' + $server)
            [array]$connection = Test-TcpConnection -Computer $server -Port '53'
            if ( $connection[0] )
            {
                #[string]$port88 = 'Success (' + $connection[2] + ' ms)'
                [string]$port53 = 'Success'
            }
            else
            {
                [string]$port53 = 'Failed'
            }
            Write-Log ('    Access to Port tcp/53 on ' + $server + ': ' + $port53)
            Write-Log ('    Message: ' + $connection[1])
            # .........................................................................
    
            # .........................................................................
            # Port tcp/88 (Kerberos)
            # .........................................................................
            Write-Log ('Trying to open Port tcp/88 on ' + $server)
            [array]$connection = Test-TcpConnection -Computer $server -Port '88'
            if ( $connection[0] )
            {
                #[string]$port88 = 'Success (' + $connection[2] + ' ms)'
                [string]$port88 = 'Success'
            }
            else
            {
                [string]$port88 = 'Failed'
            }
            Write-Log ('    Access to Port tcp/88 on ' + $server + ': ' + $port88)
            Write-Log ('    Message: ' + $connection[1])
            # .........................................................................
    
            # .........................................................................
            # Port tcp/135 (RPC) and WMI
            # .........................................................................
            Write-Log ('Trying to open Port tcp/135 on ' + $server)
            [array]$connection = Test-TcpConnection -Computer $server -Port '135'
            if ($connection[0])
                {
                    #[string]$port135 = 'Success (' + $connection[2] + ' ms)'
                    [string]$port135 = 'Success'
                    Write-Log ('    Access to Port tcp/135 on ' + $server + ': ' + $port135)
                }
                else
                {
                    [string]$port135 = 'Failed'
                    Write-Log ('    Access to Port tcp/135 on ' + $server + ': ' + $port135)
                }
                Write-Log ('    Message: ' + $connection[1])

                if ($connection[0])
                {
                    Write-Log ('        Trying to get WMI info from ' + $server)
                    [array]$wmiTest = @()
                    $wmiTest += Test-Wmi -Computername $server
                    if ($wmiTest[0])
                    {
                        #[string]$wmi = 'Success (' + $wmiTest[2] + ' ms)'
                        [string]$wmi = 'Success'
                        Write-Log ('        WMI service is up on ' + $server + ' (S/N is ' + $wmiTest[1] + ')' )
                        Write-Log ('        Elapsed Time = ' + $wmiTest[2] + ' ms')
                    }
                    else
                    {
                        [string]$wmi = 'Failed'
                        Write-Log ('        Get WMI status failed')
                        Write-Log ('        Known error: ' + $wmiTest[1])
                    }
                }
                else
                {
                    [string]$wmi ='Not tested'
                }

                # .........................................................................


                # .........................................................................
                # Port tcp/389 (LDAP) and bind LDAP
                # .........................................................................
                Write-Log ('Trying to open Port tcp/389 on ' + $server)
                [array]$connection = Test-TcpConnection -Computer $server -Port '389'
                if ($connection[0])
                {
                    #[string]$port389 = 'Success (' + $connection[2] + ' ms)'
                    [string]$port389 = 'Success'
                    Write-Log ('    Access to Port tcp/389 on ' + $server + ': ' + $port389)
                }
                else
                {
                    [string]$port389 = 'Failed'
                    Write-Log ('    Access to Port tcp/389 on ' + $server + ': ' + $port389)
                }
                Write-Log ('    Message: ' + $connection[1])

                if ($connection[0])
                {
                    Write-Log ('        Trying to LDAP bind to ' + $server )
                    [array]$ldapBindTest = @()
                    $ldapBindTest += Test-Ldap -Server $server
                    if ($ldapBindTest[0])
                    {
                        #[string]$ldapBind = 'Success (' + $ldapBindTest[2] + ' ms)'
                        [string]$ldapBind = 'Success'
                        Write-Log ('        LDAP Binding to ' + $server + ' was successful (object path = ' + $ldapBindTest[1] + ')')
                        Write-Log ('        Elaspe Time = ' + $ldapBindTest[2] + ' ms')
                    }
                    else
                    {
                        [string]$ldapBind = 'Failed'
                        Write-Log ('        LDAP Binding to ' + $server + ' failed')
                        Write-Log ('        Message: ' + $ldapBindTest[1])
                    }
                }
                else
                {
                    [string]$ldapBind ='Not tested'
                }
                # .........................................................................

    
                # .........................................................................
                # Port tcp/445 (SMB)
                # .........................................................................
                Write-Log ('Trying to open Port tcp/445 on ' + $server)
                [array]$connection = Test-TcpConnection -Computer $server -Port '445'
                if ($connection[0])
                {
                    #[string]$port445 = 'Success (' + $connection[2] + ' ms)'
                    [string]$port445 = 'Success'
                }
                else
                {
                    [string]$port445 = 'Failed'
                }
                Write-Log ('    Access to Port tcp/445 on ' + $server + ': ' + $port445)
                Write-Log ('    Message: ' + $connection[1])
                # .........................................................................

                
                # .........................................................................
                # Port tcp/3268 (Global Catalog)
                # .........................................................................
                Write-Log ('Trying to open Port tcp/3268 on ' + $server)
                [array]$connection = Test-TcpConnection -Computer $server -Port '3268'
                if ($connection[0])
                {
                    #[string]$port3268 = 'Success (' + $connection[2] + ' ms)'
                    [string]$port3268 = 'Success'
                }
                else
                {
                    [string]$port3268 = 'Failed'
                }
                Write-Log ('    Access to Port tcp/3268 on ' + $server + ': ' + $port3268)
                Write-Log ('    Message: ' + $connection[1])
                # .........................................................................



    }#END OF IF SHORT NAME PING VALIDATION
    else{

            # .........................................................................
            # Port tcp/53 (DNS)
            # .........................................................................
            Write-Log ('DNS Port tcp/53 on ' + $server + ' will not be tested')
            [string]$port53 = 'Not tested'
            
            Write-Log ('    Port tcp/53 on ' + $server + ': ' + $port53)
           
            Write-Log ('    Message: Not Tested')
            # .........................................................................


             # .........................................................................
            # Port tcp/88 (Kerberos)
            # .........................................................................
            Write-Log ('DNS Port tcp/88 on ' + $server + ' will not be tested')
            [string]$port88 = 'Not tested'
            
            Write-Log ('    Port tcp/88 on ' + $server + ': ' + $port88)
           
            Write-Log ('    Message: Not Tested')
            
            # .........................................................................


            # .........................................................................
            # Port tcp/135 (RPC) and WMI
            # .........................................................................
            Write-Log ('Port tcp/135 on ' + $server + ' will not be tested')
            [string]$port135 = 'Not Tested'

            Write-Log ('    Port tcp/135 on ' + $server + ': ' + $port135)

            [string]$wmi ='Not tested'
            
            Write-Log ('        WMI service will not be tested ' + $server)
            
            # .........................................................................
            
      
            # .........................................................................
            # Port tcp/389 (LDAP) and bind LDAP
            # .........................................................................
            Write-Log ('Port tcp/389 on ' + $server + ' will not be tested')
            
            [string]$port389 = 'Not Tested'

            Write-Log ('    Port tcp/389 on ' + $server + ': ' + $port389)

            [string]$ldapBind ='Not tested'

            Write-Log ('        LDAP Binding to ' + $server + ' Not tested')

            # .........................................................................

            # .........................................................................
            # Port tcp/445 (SMB)
            # .........................................................................
            Write-Log ('Port tcp/445 on ' + $server + ' will not be tested')
            
            [string]$port445 = 'Not Tested'

            Write-Log ('    Port tcp/445 on ' + $server + ': ' + $port445)

            # .........................................................................

            # .........................................................................
            # Port tcp/3268 (Global Catalog)
            # .........................................................................
            Write-Log ('Port tcp/3268 on ' + $server + ' will not be tested')
            
            [string]$port3268 = 'Not Tested'

            Write-Log ('    Port tcp/3268 on ' + $server + ': ' + $port3268)
                   
            # .........................................................................

}#END OF ELSE SHORT NAME PING VALIDATION

    # .........................................................................
    # Get OS name and GC status
    # .........................................................................
    if ( ($ldapBind.Contains('Success')) -and ($scope.ToLower() -eq 'full') )
    {
        Write-Log ('Trying to get OS name of ' + $dc.ToLower())
        [string]$os = Get-DcOsName -dc $dc
        Write-Log ('    OS name of ' + $dc.ToLower() + ' is ' + $os)
        #[string]$os = $os.Replace('','').Replace('®','').Replace('©','').Replace('Windows ','').Replace('Server ','')

        Write-Log ('Trying to get Global Catalog Info for  ' + $dc.ToLower())
        [string]$isGlobalCatalog = Get-DcGlobalCatalogInfo -dc $dc
        Write-Log ('    ' + $dc.ToLower() + ' is a Global Catalog: ' + $isGlobalCatalog)
    }
    else
    {
        [string]$os = ''
        [string]$isGlobalCatalog = ''
    }
    # .........................................................................

    # .........................................................................
    # Add the Value-Added HTML info
    # .........................................................................
    [string]$pingFqdn = Set-ValueAddedHtmlInfo -FieldToTest $pingFqdn -TypeOfTest 'SuccessOrFailed'
    [string]$pingShortName = Set-ValueAddedHtmlInfo -FieldToTest $pingShortName -TypeOfTest 'SuccessOrFailed'
    [string]$ldapBind = Set-ValueAddedHtmlInfo -FieldToTest $ldapBind -TypeOfTest 'SuccessOrFailed'
    [string]$wmi = Set-ValueAddedHtmlInfo -FieldToTest $wmi -TypeOfTest 'SuccessOrFailed'
    [string]$port53 = Set-ValueAddedHtmlInfo -fieldToTest $port53 -typeOfTest 'SuccessOrFailed'
    [string]$port88 = Set-ValueAddedHtmlInfo -FieldToTest $port88 -TypeOfTest 'SuccessOrFailed'
    [string]$port135 = Set-ValueAddedHtmlInfo -FieldToTest $port135 -TypeOfTest 'SuccessOrFailed'
    [string]$port389 = Set-ValueAddedHtmlInfo -FieldToTest $port389 -TypeOfTest 'SuccessOrFailed'
    [string]$port445 = Set-ValueAddedHtmlInfo -FieldToTest $port445 -TypeOfTest 'SuccessOrFailed'
    [string]$port3268 = Set-ValueAddedHtmlInfo -FieldToTest $port3268 -TypeOfTest 'SuccessOrFailed'
    # .........................................................................

    $dcConnectivity += New-DC -ComputerName $server `
                              -FQDN $fqdn `
                              -PingFQDN $pingFqdn `
                              -PingShortname $pingShortName `
                              -LDAPBind $ldapBind `
                              -WMI $wmi `
                              -TCPPort53 $port53 `
                              -TCPPort88 $port88 `
                              -TCPPort135 $port135 `
                              -TCPPort389 $port389 `
                              -TCPPort445 $port445 `
                              -TCPPort3268 $port3268 `
                              -OS $os `
                              -IsGlobalCatalog $isGlobalCatalog
                              
    Write-Log ('----------------------------------------------------------------------------------------------------')

}#End ForEach DC Connectivity

# Sort the DCs
[array]$dcConnectivity  = $dcConnectivity | Sort-Object -Property ComputerName
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Compile the DFSR Outband Infos including the BackLog Counters
# ----------------------------------------------------------------------------------------------------------------
Write-Log ("Compiling DFSR Outband Infos")

# Wait for the jobs to finish
[datetime]$startJobsTime = Get-Date
[Bool]$jobsCompleted = $false
while (!$jobsCompleted)
{
    # Test the state of each job
    [Bool]$jobsCompleted = $true
    for ($i=0; $i -lt $jobsDfsr.Count; $i++)
    {
        [Bool]$jobsCompleted = $jobsCompleted -and ($jobsDfsr[$i].State -ne 'Running')
    }

    # Stop jobs and force loop to stop if longer than the deined timeout
    if ( (((Get-Date) - $startJobsTime).TotalMinutes ) -gt $script:waitDcdiag )
    {
        for ($i=0; $i -lt $jobsDfsr.Count; $i++)
        {
            Stop-Job -Job $jobsDfsr[$i]
        }
        [Bool]$jobsCompleted = $true
        Write-Log('Force Jobs to complete!')
    }
    if (!$jobsCompleted)
    {
        Start-Sleep -Seconds 5
    }
}

# Concat the results
foreach ($server in $servers)
{
    $dfsrOutbandInfo = New-Object psobject 
    Receive-Job -Name ($server + '_dfsr') -OutVariable dfsrOutbandInfo | Out-Null
    $dfsrOutbandInfos += $dfsrOutbandInfo
}
Write-Log ('............................................................')

# Log the results and add value added infos
for ($i=0; $i -lt $dfsrOutbandInfos.Count; $i++)
{
    Write-Log ('ReplicationGroupName: ' + $dfsrOutbandInfos[$i].ReplicationGroupName)
    Write-Log ('ReplicatedFolderName: ' + $dfsrOutbandInfos[$i].ReplicatedFolderName)
    Write-Log ('SendingMember: ' + $dfsrOutbandInfos[$i].SendingMember)
    Write-Log ('ReceivingMember: ' + $dfsrOutbandInfos[$i].ReceivingMember)
    Write-Log ('BacklogCount: ' + $dfsrOutbandInfos[$i].BacklogCount)
    Write-Log ('FolderEnabled: ' + $dfsrOutbandInfos[$i].FolderEnabled)
    Write-Log ('ConnectionEnabled: ' + $dfsrOutbandInfos[$i].ConnectionEnabled)

    # Add the Value-Added HTML info
    if ([string]$dfsrOutbandInfos[$i].BacklogCount -ne '')
    {
        [string]$dfsrOutbandInfos[$i].BacklogCount = Set-ValueAddedHtmlInfo -FieldToTest ([string]$dfsrOutbandInfos[$i].BacklogCount) -TypeOfTest 'DFSRBacklog'
    }
    if ([string]$dfsrOutbandInfos[$i].FolderEnabled -ne '')
    {
        [string]$dfsrOutbandInfos[$i].FolderEnabled = Set-ValueAddedHtmlInfo -FieldToTest ([string]$dfsrOutbandInfos[$i].FolderEnabled) -TypeOfTest 'DFSRFolderEnabled'
    }
    if ([string]$dfsrOutbandInfos[$i].ConnectionEnabled -ne '')
    {
        [string]$dfsrOutbandInfos[$i].ConnectionEnabled = Set-ValueAddedHtmlInfo -FieldToTest ([string]$dfsrOutbandInfos[$i].ConnectionEnabled) -TypeOfTest 'DFSRConnectionEnabled'
    }

    Write-Log ('............................................................')
}

# Sort the BackLog Counters
[array]$dfsrOutbandInfos = $dfsrOutbandInfos | Sort-Object -Property SendingMember

Write-Log ('----------------------------------------------------------------------------------------------------')
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Compile the dcdiag Status
# ----------------------------------------------------------------------------------------------------------------
Write-Log ("Compiling dcdiag status")


# Wait for the jobs to finish
[datetime]$startJobsTime = Get-Date
[Bool]$jobsCompleted = $false
while (!$jobsCompleted)
{
    # Test the state of each job
    [Bool]$jobsCompleted = $true
    for ($i=0; $i -lt $jobsDcdiag.Count; $i++)
    {
        [Bool]$jobsCompleted = $jobsCompleted -and ($jobsDcdiag[$i].State -ne 'Running')
    }

    # Stop jobs and force loop to stop if longer than defined timeout
    if ( (((Get-Date) - $startJobsTime).TotalMinutes ) -gt $script:dcdiagTimeout )
    {
        for ($i=0; $i -lt $jobsDcdiag.Count; $i++)
        {
            Stop-Job -Job $jobsDcdiag[$i]
        }
        [Bool]$jobsCompleted = $true
        Write-Log('Force Jobs to complete!')
    }

    if (!$jobsCompleted)
    {
        Start-Sleep -Seconds 2
    }
}
Write-Log('Jobs completed!')
for ($i=0; $i -lt $jobsDcdiag.Count; $i++)
{
    Write-Log ("Job's Name: " + $jobsDcdiag[$i].Name + "   State: " + $jobsDcdiag[$i].State)
}

# Log and Concat the results
foreach ($server in $servers)
{
    [string]$outputOverall = $scriptDirectory + '\trash\' + $server + '_overall_' + $random + '.log'
    [string]$outputDns = $scriptDirectory + '\trash\' + $server + '_dns_' + $random + '.log'
    [string]$scriptPowershellOverall = $scriptDirectory + '\trash\' + $server + '_overall_' + $random + '.ps1'
    [string]$scriptPowershellDNS = $scriptDirectory + '\trash\' + $server + '_dns_' + $random + '.ps1'
    
    [array]$dcdiagOverall = @()
    $dcdiagOverall += Get-Content -Path $outputOverall
    [array]$dcdiagDns = @()
    $dcdiagDns += Get-Content -Path $outputDns
    
    # Remove some garbage caracters
    [array]$dcdiagOverall  = $dcdiagOverall | Where-Object { $_ }
    [array]$dcdiagDns  = $dcdiagDns | Where-Object { $_ }

    # Log the results
    foreach ($line in $dcdiagOverall)
    {
        Write-Log ($line)
    }
    Write-Log ('............................................................')
    foreach ($line in $dcdiagDns)
    {
        Write-Log ($line)
    }
    Write-Log ('............................................................')

    # Check if the files are correct
    [bool]$dcdiagOverallfileIsCorrect = $false
    foreach ($line in $dcdiagOverall)
    {
        if ($line.Contains('Doing primary tests'))
        {
            [bool]$dcdiagOverallfileIsCorrect = $true
        }
    }
    [bool]$dcdiagDnsfileIsCorrect = $false
    foreach ($line in $dcdiagDns)
    {
        if ($line.Contains('Doing primary tests'))
        {
            [bool]$dcdiagDnsfileIsCorrect = $true
        }
    }
    [bool]$filesAreCorrect = $dcdiagOverallfileIsCorrect -and $dcdiagDnsfileIsCorrect

    # Add the files only if they are correct
    if ($filesAreCorrect)
    {

        # Remove first lines of $dcdiagDns because they are already included in $dcdiagOverall
        [bool]$keepGoing = $true
        [int]$i = 0
        While ($keepGoing)
        {
            if ($dcdiagDns[$i].Contains('Doing primary tests'))
            {
                [bool]$keepGoing = $false
            }
            else
            {
                [string]$dcdiagDns[$i] = ' '
                $i++
            }
        }


        # Modify last lines to see which server has made the DNS test
        [bool]$change = $false
        for ($i=0; $i -lt $dcdiagDns.Count; $i++)
        {
            if (!$change -and $dcdiagDns[$i].Contains('Running partition tests'))
            {
                [bool]$change = $true
            }
            if ($change)
            {
                [string]$dcdiagDns[$i] = $dcdiagDns[$i].Replace('test DNS','test DNS_' + $server )
            }
        }
    
        $dcdiagResult += $dcdiagOverall
        $dcdiagResult += $dcdiagDns

    }

    Remove-Variable -Name dcdiagOverall -ErrorAction SilentlyContinue
    Remove-Variable -Name dcdiagDns -ErrorAction SilentlyContinue

    Remove-Item -Path $outputOverall -ErrorAction SilentlyContinue
    Remove-Item -Path $outputDns -ErrorAction SilentlyContinue
    Remove-Item -Path $scriptPowershellOverall -ErrorAction SilentlyContinue
    Remove-Item -Path $scriptPowershellDNS -ErrorAction SilentlyContinue
}


# Remove unnecessary "double" space ('  ')
for ($i=0; $i -le $dcdiagResult.Count-1; $i++)
{
    [string]$line = $dcdiagResult[$i]
    While ($line.Contains('  '))
    {
        [string]$line = $line.Replace('  ',' ')
        [string]$dcdiagResult[$i] = $line
    }
}


# Use dcdiagOverall for legacy reason! I deeply modified the first part of dcdiag part of this script
[array]$dcdiagOverall = $dcdiagResult


# Concat line if needed (sometimes the result is split in 2 lines, sometimes it's even more!)
# The script is unfortunately very approximative!
for ($i=0; $i -le $dcdiagOverall.Count-1; $i++)
{
    if ($dcdiagOverall[$i].Contains('....') -and $dcdiagOverall[$i].Split(' ').Count -ne 6)
    {
        [int]$numberOfSplits = 10 - $dcdiagOverall[$i].Split(' ').Count
        [string]$line = $dcdiagOverall[$i]

        for ($j=1; $j -lt $numberOfSplits; $j++)
        {
            $line += $dcdiagOverall[$i+$j]
            [string]$line = $line.Replace('. .', '..')
        }

        [string]$dcdiagOverall[$i] = $line
    }
}


# Sort dcdiag output
[array]$dcdiagOverall  = $dcdiagOverall | Sort-Object

# Initialization
[int]$numberOfDiagnostics= 0

foreach ($line in $dcdiagOverall)
{
    if ($line.StartsWith(' .........................'))
    {
        if ($line.Split(' ').Count -ge 6)
        {
            [string]$target = $line.Split(' ').Get(2).ToLower()
            [string]$test = $line.Split(' ').Get(5)
            [string]$result = $line.Split(' ').Get(3)
            
            Write-Log ("Target '" + $target + "' " + $result + " " + $test)
            $numberOfDiagnostics++
        
            # Add the Value-Added HTML info
            [string]$result = Set-ValueAddedHtmlInfo -FieldToTest $result -TypeOfTest 'SuccessOrFailed'

            $diagnostics += New-Diagnosis -Target $target `
                                          -Test $test `
                                          -Result $result
        }
        else
        {
            Write-Log ("Error: impossible to import '" + $line + "'")
        }
    }

}
Write-Log ('----------------------------------------------------------------------------------------------------')



# Adding the Summary at the end of the arrray
# Initialization
[string]$target = ''
[string]$targetLast = ''
[string]$targetNew = ''
[string]$test = ''
[string]$result = ''
[int]$numberOfDiagnosticsSummaries = 0

for ($j=0; $j -le $numberOfDiagnostics-1; $j++)
{
    [string]$target = $diagnostics.Get($j).Target
    
    # if $targetNew and $targetLast are equal that we need to add info into the same summary
    if ($target -eq $targetLast)
    {
        $test += '<br>' + $diagnostics.Get($j).Test
        $result += '<br>' + $diagnostics.Get($j).Result
    }

    # if $target and $targetLast are different that we need to start a new summary
    if ($target -ne $targetLast)
    {
        [string]$targetLast = $target
        [string]$test = $diagnostics.Get($j).Test
        [string]$result = $diagnostics.Get($j).Result

    }

    # Check if this is the last test of the same target
    $targetNew = $diagnostics.Get($j+1).Target
    if ($target -ne $targetNew)
    {
        $numberOfDiagnosticsSummaries ++        

        # Add the summary
        $diagnostics += New-Diagnosis -Target $target `
                                      -Test $test `
                                      -Result $result
    }
    
}
# ----------------------------------------------------------------------------------------------------------------

#Import Gray Image
$grayImagefile = $scriptDirectory + "\Images\Button-Blank-Gray-icon.png"
$grayImageBits = [Convert]::ToBase64String((Get-Content $grayImagefile -Encoding Byte))
$grayImageHTML = "<img src=data:image/png;base64,$($grayImageBits) alt='gray icon' width='64' heigh='64'/>"

# ----------------------------------------------------------------------------------------------------------------
# Create the HTML document
# ----------------------------------------------------------------------------------------------------------------
[datetime]$currentDate = Get-Date
[string]$title = 'AD Health Check'
[string]$subtitle  = $scope + ' Configuration & Connectivity Tests Performed on '
$subtitle += ("{0:dd-MM-yyyy HH:mm}" -f $currentDate)
$subtitle += ' (' + ("{0:dd-MM-yyyy HH:mm}" -f $currentDate.ToUniversalTime()) + ' UTC)'

[array]$htmlCode = @()
$htmlCode += '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">'
$htmlCode += '<html xmlns="http://www.w3.org/1999/xhtml">'
$htmlCode += '<head>'
$htmlCode += '<title>' + $title + '</title>'
$htmlCode += '    <style>'
$htmlCode += '        small {'
$htmlCode += '            font-size: 8pt;'
$htmlCode += '        }'
$htmlCode += '        body {'
$htmlCode += '            color:#333333;'
$htmlCode += '            font-family:Calibri,Tahoma;'
$htmlCode += '            font-size: 10pt;'
$htmlCode += '        }'
$htmlCode += '        h1 {'
$htmlCode += '            text-align:center;'
$htmlCode += '        }'
$htmlCode += '        h2 {'
$htmlCode += '             border-top:1px solid #666666;'
$htmlCode += '        }'
$htmlCode += '        th {'
$htmlCode += '             font-weight:bold;'
$htmlCode += '             color:#eeeeee;'
$htmlCode += '             background-color:#333333;'
$htmlCode += '        }'
$htmlCode += '        thead {'
$htmlCode += '            text-align:center;'
$htmlCode += '            font-weight:bold;'
$htmlCode += '        }'
$htmlCode += '        .odd {'
$htmlCode += '             background-color:#ffffff;'
$htmlCode += '        }'
$htmlCode += '        .even {'
$htmlCode += '             background-color:#dddddd;'
$htmlCode += '        }'
$htmlCode += '        red {'
$htmlCode += '             color:red;'
$htmlCode += '        }'
$htmlCode += '        green {'
$htmlCode += '             color:green;'
$htmlCode += '        }'
$htmlCode += '        yellow {'
$htmlCode += '             color:#ffaf00;'
$htmlCode += '        }'
$htmlCode += '    </style>'
$htmlCode += '</head>'
$htmlCode += ''
$htmlCode += ''
$htmlCode += '<body>'
$htmlCode += '    <h2>'
$htmlCode += '    ' + $subtitle

$htmlCode += '    <br><br>'
$htmlCode += '    Overall Status from ' + $env:computername.ToLower() + $grayImageHTML 
$KpiToModifyPosition = $htmlCode.Count - 1

$htmlCode += '    </h2>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert Forest configuration infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>Forest Configuration</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
$htmlCode += '    <tr><th>Forest Name</th><th>Forest Mode</th><th>Schema Role Owner</th><th>Naming Role Owner</th><th>DC Count</th><th>Domain Count</th><th>Site Count</th><th>Site With DCs</th></tr>'
$htmlCode += '</thead>'
$htmlCode += '<tbody>'
$htmlCode += '    <tr class="even"><td>' + $forestName + '</td><td>' + $forestMode + '</td><td>' + $schemaRoleOwner + '</td><td>' + $namingRoleOwner + '</td><td>' + $numberOfDCsF + '</td><td>' + $numberOfDomains + '</td><td>' + $numberOfSites + '</td><td>' + $numberOfSitesWithDC + '</td></tr>'
$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert Domains configuration infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>Domains Configuration</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
$htmlCode += '    <tr><th>Domain Name</th><th>Domain Mode</th><th>PDC Role Owner</th><th>RID Role Owner</th><th>Infrastructure Role Owner</th><th>RIDs Remaining</th></tr>'
$htmlCode += '</thead>'
$htmlCode += '<tbody>'

# Parse the domains configuration
for ( $i=0; $i -le $numberOfDomains-1; $i++) 
{
    if ($i%2 -eq 0)
    {
        $class = 'class="even"'
    }
    else
    {
        $class = 'class="odd"'
    }
    $htmlCode += '    <tr ' + $class + '><td>' + $domainsConfiguration.Get($i).DomainName + '</td><td>' + $domainsConfiguration.Get($i).DomainMode + '</td><td>' + $domainsConfiguration.Get($i).PdcRoleOwner + '</td><td>' + $domainsConfiguration.Get($i).RidRoleOwner + '</td><td>' + $domainsConfiguration.Get($i).InfrastructureRoleOwner + '</td><td>' + $domainsConfiguration.Get($i).RIDsRemainingPercent + '</td></tr>'
}

$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert Connectivity Status infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>Connectivity Status</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
if ($scope.ToLower() -eq 'full')
{
    $htmlCode += '    <tr><th>Computer Name</th><th>FQDN</th><th>OS</th><th>GC</th><th>Ping FQDN</th><th>Ping Short Name</th><th>LDAP Bind</th><th>WMI</th><th>TCP Port 53</th><th>TCP Port 88</th><th>TCP Port 135</th><th>TCP Port 389</th><th>TCP Port 445</th><th>TCP Port 3268</th></tr>'
}
else
{
    $htmlCode += '    <tr><th>Computer Name</th><th>FQDN</th><th>Ping FQDN</th><th>Ping Short Name</th><th>LDAP Bind</th><th>WMI</th><th>TCP Port 53</th><th>TCP Port 88</th><th>TCP Port 135</th><th>TCP Port 389</th><th>TCP Port 445</th><th>TCP Port 3268</th></tr>'
}
$htmlCode += '</thead>'
$htmlCode += '<tbody>'

# Parse the Connectivy Status
for ( $i=0; $i -le $numberOfDCs-1; $i++) 
{
    if ($i%2 -eq 0)
    {
        $class = 'class="even"'
    }
    else
    {
        $class = 'class="odd"'
    }
    if ($scope.ToLower() -eq 'full')
    {
        $htmlCode += '    <tr ' + $class + '><td>' + $dcConnectivity.Get($i).ComputerName + '</td><td>' + $dcConnectivity.Get($i).FQDN + '</td><td>' + $dcConnectivity.Get($i).OS + '</td><td>' + $dcConnectivity.Get($i).IsGlobalCatalog + '</td><td>' + $dcConnectivity.Get($i).PingFQDN + '</td><td>' + $dcConnectivity.Get($i).PingShortname + '</td><td>' + $dcConnectivity.Get($i).LDAPBind + '</td><td>' + $dcConnectivity.Get($i).WMI + '</td><td>' + $dcConnectivity.Get($i).TCPPort53 + '</td><td>' + $dcConnectivity.Get($i).TCPPort88 + '</td><td>' + $dcConnectivity.Get($i).TCPPort135 + '</td><td>' + $dcConnectivity.Get($i).TCPPort389 + '</td><td>' + $dcConnectivity.Get($i).TCPPort445 + '</td><td>' + $dcConnectivity.Get($i).TCPPort3268 + '</td></tr>'
    }
    else
    {
        $htmlCode += '    <tr ' + $class + '><td>' + $dcConnectivity.Get($i).ComputerName + '</td><td>' + $dcConnectivity.Get($i).FQDN + '</td><td>' + $dcConnectivity.Get($i).PingFQDN + '</td><td>' + $dcConnectivity.Get($i).PingShortname + '</td><td>' + $dcConnectivity.Get($i).LDAPBind + '</td><td>' + $dcConnectivity.Get($i).WMI + '</td><td>' + $dcConnectivity.Get($i).TCPPort53 + '</td><td>' + $dcConnectivity.Get($i).TCPPort88 + '</td><td>' + $dcConnectivity.Get($i).TCPPort135 + '</td><td>' + $dcConnectivity.Get($i).TCPPort389 + '</td><td>' + $dcConnectivity.Get($i).TCPPort445 + '</td><td>' + $dcConnectivity.Get($i).TCPPort3268 + '</td></tr>'
    }
}

$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert Backups infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>Backups</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
$htmlCode += '    <tr><th>Partition</th><th>Last Backup Time</th></tr>'
$htmlCode += '</thead>'
$htmlCode += '<tbody>'

# Parse the backups
for ( $i=0; $i -le $numberOfBackups-1; $i++) 
{
    if ($i%2 -eq 0)
    {
        $class = 'class="even"'
    }
    else
    {
        $class = 'class="odd"'
    }
    $htmlCode += '    <tr ' + $class + '><td>' + $backups.Get($i).Partition + '</td><td>' + $backups.Get($i).LastBackupTime + '</td></tr>'
}

$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert Sites configuration infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>Sites Configuration</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
$htmlCode += '    <tr><th>Site Name</th><th>Inter Site Topology Generator</th><th>Subnets</th><th>Servers</th><th>Adjacent Sites</th><th>Site Links</th><th>Bridgehead Servers</th></tr>'
$htmlCode += '</thead>'
$htmlCode += '<tbody>'

# Parse the sites configuration
for ( $i=0; $i -le $numberOfSites-1; $i++) 
{
    if ($i%2 -eq 0)
    {
        $class = 'class="even"'
    }
    else
    {
        $class = 'class="odd"'
    }
    $htmlCode += '    <tr ' + $class + '><td>' + $sitesConfiguration.Get($i).SiteName + '</td><td>' + $sitesConfiguration.Get($i).InterSiteTopologyGenerator + '</td><td>' + $sitesConfiguration.Get($i).Subnets + '</td><td>' + $sitesConfiguration.Get($i).Servers + '</td><td>' + $sitesConfiguration.Get($i).AdjacentSites + '</td><td>' + $sitesConfiguration.Get($i).SiteLinks + '</td><td>' + $sitesConfiguration.Get($i).BridgeheadServers + '</td></tr>'
}

$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert Replication Status infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>Replication Status</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
$htmlCode += '    <tr><th>Source or Destination</th><th>Computer Name</th><th>Largest Delta</th><th>Failed Replication</th><th>Total Replication</th></tr>'
$htmlCode += '</thead>'
$htmlCode += '<tbody>'

# Parse the sites configuration
for ( $i=$numberOfReplications; $i -le $numberOfReplications+$numberOfReplicationsSummaries-1; $i++) 
{
    if ($i%2 -eq 0)
    {
        $class = 'class="even"'
    }
    else
    {
        $class = 'class="odd"'
    }
    $htmlCode += '    <tr ' + $class + '><td>' + $replications.Get($i).SourceOrDestination + '</td><td>' + $replications.Get($i).ComputerName + '</td><td>' + $replications.Get($i).LargestDelta + '</td><td>' + $replications.Get($i).ReplicationFailed + '</td><td>' + $replications.Get($i).ReplicationTotal + '</td></tr>'
}

$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert Backlog Status infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>DFSR Backlog Status</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
$htmlCode += '    <tr><th>Sending Member</th><th>Receiving Member</th><th>Backlog Count</th><th>Folder Enabled</th><th>Connection Enabled</th></tr>'
$htmlCode += '</thead>'
$htmlCode += '<tbody>'

# Parse the DFSR Outband Status
for ($i=0; $i -lt $dfsrOutbandInfos.Count; $i++)
{
    if ($i%2 -eq 0)
    {
        $class = 'class="even"'
    }
    else
    {
        $class = 'class="odd"'
    }
    $htmlCode += '    <tr ' + $class + '><td>' + $dfsrOutbandInfos[$i].SendingMember + '</td><td>' + $dfsrOutbandInfos[$i].ReceivingMember + '</td><td>' + $dfsrOutbandInfos[$i].BacklogCount + '</td><td>' + $dfsrOutbandInfos[$i].FolderEnabled + '</td><td>' + $dfsrOutbandInfos[$i].ConnectionEnabled + '</td></tr>'
}

$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert GPO Status infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>GPO Status</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
$htmlCode += '    <tr><th>Domain</th><th>GPO Name</th><th>GUID</th><th>Status</th></tr>'
$htmlCode += '</thead>'
$htmlCode += '<tbody>'

# Parse the SYSVOL array 
for ( $i=0; $i -le $numberOfPolicies-1; $i++) 
{
    if ($i%2 -eq 0)
    {
        $class = 'class="even"'
    }
    else
    {
        $class = 'class="odd"'
    }
    $htmlCode += '    <tr ' + $class + '><td>' + $gpoStatus.Get($i).Domain + '</td><td>' + $gpoStatus.Get($i).Name + '</td><td>' + $gpoStatus.Get($i).Guid + '</td><td>' + $gpoStatus.Get($i).Status + '</td></tr>'
}

$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Insert dcdiag Diagnostics infos into HTML document
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '<h2>Domain Controllers State</h2>'
$htmlCode += '<table>'
$htmlCode += '<thead>'
$htmlCode += '    <tr><th>Target</th><th>Test</th><th>Result</th></tr>'
$htmlCode += '</thead>'
$htmlCode += '<tbody>'
    
# Parse the diagnosis
for ( $i=$numberOfDiagnostics; $i -le $numberOfDiagnostics+$numberOfDiagnosticsSummaries-1; $i++) 
{
    if ($i%2 -eq 0)
    {
        $class = 'class="even"'
    }
    else
    {
        $class = 'class="odd"'
    }
    $htmlCode += '    <tr ' + $class + '><td>' + $diagnostics.Get($i).Target + '</td><td>' + $diagnostics.Get($i).Test + '</td><td>' + $diagnostics.Get($i).Result + '</td></tr>'
}

$htmlCode += '</tbody>'
$htmlCode += '</table>'
$htmlCode += ''
$htmlCode += ''
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Ending HTML code
# ----------------------------------------------------------------------------------------------------------------
$htmlCode += '</body>'
$htmlCode += '</html>'

# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Modify the Overall Status icon
# ----------------------------------------------------------------------------------------------------------------
# Set the Overall Status icon
[bool]$flagRed = $false
[bool]$flagYellow = $false

foreach ($line in $htmlCode)
{
    if ($line.Contains('<span style="color:red">'))
    {
        $flagRed = $true
    }
    if ($line.Contains('<span style="color:#ffaf00">'))# -and !$line.Contains('<span style="color:#ffaf00"><span style="color:green">'))
    {
        $flagYellow = $true
    }
}

if ($flagRed)
{
    # Overall Status is 'red'
    #Import Red Image
    $RedImagefile = $scriptDirectory + "\Images\Button-Blank-Red-icon.png"
    $RedImageBits = [Convert]::ToBase64String((Get-Content $RedImagefile -Encoding Byte))
    $RedImageHTML = "<img src=data:image/png;base64,$($RedImageBits) alt='Red icon'/>"
    
    $htmlCode[$KpiToModifyPosition] = $htmlCode[$KpiToModifyPosition].Replace($grayImageHTML, $redImageHTML)
}
elseif ($flagYellow)
{
    # Overall Status is 'yellow'
    #Import Yellow Image
    $YellowImagefile = $scriptDirectory + "\Images\Button-Blank-Yellow-icon.png"
    $YellowImageBits = [Convert]::ToBase64String((Get-Content $YellowImagefile -Encoding Byte))
    $YellowImageHTML = "<img src=data:image/png;base64,$($YellowImageBits) alt='Yellow icon'/>"

    $htmlCode[$KpiToModifyPosition] = $htmlCode[$KpiToModifyPosition].Replace($grayImageHTML, $YellowImageHTML)
}
else
{
    # Overall Status is 'green'
    #Import Green Image
    $greenImagefile = $scriptDirectory + "\Images\Button-Blank-Green-icon.png"
    $greenImageBits = [Convert]::ToBase64String((Get-Content $greenImagefile -Encoding Byte))
    $greenImageHTML = "<img src=data:image/png;base64,$($greenImageBits) alt='green icon'/>"
    
    $htmlCode[$KpiToModifyPosition] = $htmlCode[$KpiToModifyPosition].Replace($grayImageHTML, $greenImageHTML)
}
# ----------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------------------------------------
# Creating the ouput file
# ----------------------------------------------------------------------------------------------------------------
Remove-Item -Path $outputFile -ErrorAction SilentlyContinue
foreach ($line in $htmlCode)
{
    Add-Content -Path $outputFile -Value $line
}
# ----------------------------------------------------------------------------------------------------------------
 

# ----------------------------------------------------------------------------------------------------------------
# Check If SendMail
# ----------------------------------------------------------------------------------------------------------------

If ($SendMail)
{
   
   $EmailFrom = "powershellrobot@yourdomain.com"

    $EmailTo = ("l-microsoft-team@yourdomain.com","l-n2-infraestrutura@yourdomain.com")
    #$EmailTo = "your-team-leader@yourdomain.com"

    $EmailSMTPServer = "yoursmtpserver.com"

    $EmailCC = ("your-team-leader@yourdomain.com","infra-team@yourdomain.com","yourboss@yourdomain.com","unclephill@yourdomain.com")

    If ($attachLog){
    
        Send-MailMessage -SmtpServer $EmailSMTPServer -from $EmailFrom -to $EmailTo -Cc $emailCC -Subject "[COMPANY-DOMAIN] HealthCheck - Forest $forestName" -Body "$htmlCode" -BodyAsHtml -Attachments $logFileName -Priority High  

    
    }#End of If Attach Log
    else{
    
        Send-MailMessage -SmtpServer $EmailSMTPServer -from $EmailFrom -to $EmailTo -Cc $emailCC -Subject "[COMPANY-DOMAIN] HealthCheck - Forest $forestName" -Body "$htmlCode" -BodyAsHtml -Priority High

    
    }#end of Else Attach Log
   

}#end of IF Send Mail
Else{

    Write-Host "You Choose Not To Send Email. Finishing Script" -ForegroundColor White -BackgroundColor DarkBlue

}#End of Else Send Mail
