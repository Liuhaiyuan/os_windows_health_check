#######################    Run on PowerShell 3.0 +
#######################    Author:              g00390666
#######################    Create Date:         2018-04-16          V0.1
#######################    Modify time:         2018-04-22          V0.2


$logs_path = "C:\Check_Health"
$logs = "Check_Health"
if (Test-Path $logs_path){
        Write-Host "目录: " $logs_path "is exists"
    }
    else{
        new-item -path c:\  -name $logs -type directory
    }
$File = "Check_Report" + (Get-Date).ToString('yyyy-MM-dd hh-mm-ss') + ".html"

"<html>
<head>
<link rel=stylesheet href=https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css>
<title>$env:COMPUTERNAME</title>
<style>
html, body
{
font-family: tahoma, arial;
font-size: 14px;
margin: 5px;
padding: 0px;
color: #2E1E2E;
}
table
{
border-collapse: collapse;
    width: 100%;
}
th
{
border: 1px solid #8899AA;
padding: 3px 7px 2px 7px;
font-size: 1.1em;
text-align: left;
padding-top: 5px;
padding-bottom: 4px;
background-color: #AABBCC;
color: #ffffff;
}
td
{
border: 1px solid #8899AA;
padding: 3px 7px 2px 7px;
    overflow: hidden;
}
h2
{
    text-align: center;
font-size: 22px;
    text-shadow: 1px 1px 1px rgba(150, 150, 150, 0.5);
}
h1
{
    margin-top: 20px;
    text-align: center;
font-size: 25px;
    text-shadow: 1px 1px 1px rgba(150, 150, 150, 0.5);
}
pre {
    white-space: pre-wrap;
    white-space: -moz-pre-wrap;
    white-space: -pre-wrap;
    white-space: -o-pre-wrap;
    word-wrap: break-word;
}
#sysinfo
{
    width: 49% !important;
    float: left;
    margin-bottom: 0px;
}
#action
{
    width: 49% !important;
    float: right;
}
#menu 
{
    position: fixed;
    right: 0;
    left: 0;
    top: 0;
    width: 100%;
    height: 25px;
    background: #AABBCC;
    color: #FFFFFF;
    text-align: center;
    overflow: hidden;
}
#menu a
{
    color: #FFFFFF;
    font-weight: bold;
}
@media screen and (max-width: 1010px)
{
    #sysinfo
    {
        float: none;
        margin-bottom: 20px;
        width: 100% !important;
    }
    #action
    {
        width: 100% !important;
        float: none;
    }
}
</style>
</head>
<body>
<div id='menu'>
<a href=#sysinfo>System</a> | <a href=#disks>Disks</a> | <a href=#network>Network</a> | <a href=#processes>Processes</a> | <a href=#services>Services</a> |
 <a href=#hotfixes>Hotfixes</a> | <a href=#InstalledApps>Installed Apps</a> | <a href=#NetConnections>Network Connections</a>| <a href=#ScheduledTasks>Get ScheduledTasks</a> |
 <a href=#UpdatePolicy>Get UpdatePolicy</a> 
</div>
<a name='sysinfo'></a><h1>$env:COMPUTERNAME System Report</h1>
" > $File

Write-Output "Fetching data:"
Write-Output "* Processor"
$processor = Get-WmiObject win32_processor
Write-Output "* System"
$sysinfo = Get-WmiObject win32_computersystem
Write-Output "* BIOS"
$bios = Get-WmiObject -Class win32_bios
Write-Output "* Operating System"
$os = Get-WmiObject win32_operatingsystem
Write-Output "* Users"
$users = Get-WmiObject win32_systemusers
$timezone=(Get-WmiObject -Class win32_timezone).Caption
$NetAdapters = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |Where-Object {$_.NetworkInterfaceType -eq "Ethernet"}| Select Name,Description,NetworkInterfaceType,speed 
foreach ($NetAdapter in $NetAdapters){
    $netinfor = "Network Name: "+ $NetAdapter.Name +" Network Driver: "+ $NetAdapter.Description + "Network Speed: "+ $NetAdapter.Speed /1000000000 + "Gbps"
}

function perf_monitor{
	#$date = get-date -format "MM_dd_yyyy"
	$perf_file="perf"+(Get-Date).ToString('yyyy-MM-dd hh-mm-ss')+".csv"
	#$exportlocation = New-Item c:\logs\$date -type directory -force
	$proccounter = "\Processor(*)\% Processor Time"
	$memcounter = "\Memory\Available Bytes"
	$diskcounter = "\LogicalDisk(*)\Current Disk Queue Length"
	$interval = 30
	$maxsmpl = 30
	################################################################################################################################################################################
	#get-counter -counter $proccounter,$memcounter,$diskcounter -SampleInterval $interval -MaxSamples $maxsmpl | export-counter -path $exportlocation\perf.blg -force
	get-counter -counter $proccounter,$memcounter,$diskcounter -SampleInterval $interval -MaxSamples $maxsmpl | export-counter -path $logs_path\$perf_file -Fileformat csv -force
	#################################################################################################################################################################################
	#           csv file to convert   #
	###################################
	$csv = "$exportlocation\$perf_file";
	###################################
	#           xml file to create    #
	###################################
	$xml = "$exportlocation\perf.xml";
	##################################################
	#           convert csv file to xml file         #
	##################################################
	Import-Csv -Path $csv | Export-Clixml -Path $xml;
	##################################################
	#stop-transcript
}
function Get-ScheduledTask{ 
    param(
    	[string]$ComputerName = $env:COMPUTERNAME,
        [switch]$RootFolder
    )
    
    #region Functions
    function Get-AllTaskSubFolders {
        [cmdletbinding()]
        param (
            # Set to use $Schedule as default parameter so it automatically list all files
            # For current schedule object if it exists.
            $FolderRef = $Schedule.getfolder("\")
        )
        if ($FolderRef.Path -eq '\') {
            $FolderRef
        }
        if (-not $RootFolder) {
            $ArrFolders = @()
            if(($Folders = $folderRef.getfolders(1))) {
                $Folders | ForEach-Object {
                    $ArrFolders += $_
                    if($_.getfolders(1)) {
                        Get-AllTaskSubFolders -FolderRef $_
                    }
                }
            }
            $ArrFolders
        }
    }
    
    function Get-TaskTrigger {
        [cmdletbinding()]
        param (
            $Task
        )
        $Triggers = ([xml]$Task.xml).task.Triggers
        if ($Triggers) {
            $Triggers | Get-Member -MemberType Property | ForEach-Object {
                $Triggers.($_.Name)
            }
        }
    }
    #endregion Functions
    
    
    try {
    	$Schedule = New-Object -ComObject 'Schedule.Service'
    } catch {
    	Write-Warning "Schedule.Service COM Object not found, this script requires this object"
    	return
    }
    
    $Schedule.connect($ComputerName) 
    $AllFolders = Get-AllTaskSubFolders
    
    foreach ($Folder in $AllFolders) {
        if (($Tasks = $Folder.GetTasks(1))) {
            $Tasks | Foreach-Object {
    	        New-Object -TypeName PSCustomObject -Property @{
    	            'Name' = $_.name
                    'Path' = $_.path
                    'State' = switch ($_.State) {
                        0 {'Unknown'}
                        1 {'Disabled'}
                        2 {'Queued'}
                        3 {'Ready'}
                        4 {'Running'}
                        Default {'Unknown'}
                    }
                    'Enabled' = $_.enabled
                    'LastRunTime' = $_.lastruntime
                    'LastTaskResult' = $_.lasttaskresult
                    'NumberOfMissedRuns' = $_.numberofmissedruns
                    'NextRunTime' = $_.nextruntime
                    'Author' =  ([xml]$_.xml).Task.RegistrationInfo.Author
                    'UserId' = ([xml]$_.xml).Task.Principals.Principal.UserID
                    'Description' = ([xml]$_.xml).Task.RegistrationInfo.Description
                    'Trigger' = Get-TaskTrigger -Task $_
                    'ComputerName' = $Schedule.TargetServer
                }
            }
        }
    }
}

function Get-NetworkStatistics {
    <#
    .SYNOPSIS
	    Display current TCP/IP connections for local or remote system

    .FUNCTIONALITY
        Computers

    .DESCRIPTION
	    Display current TCP/IP connections for local or remote system.  Includes the process ID (PID) and process name for each connection.
	    If the port is not yet established, the port number is shown as an asterisk (*).	
	
    .PARAMETER ProcessName
	    Gets connections by the name of the process. The default value is '*'.
	
    .PARAMETER Port
	    The port number of the local computer or remote computer. The default value is '*'.

    .PARAMETER Address
	    Gets connections by the IP address of the connection, local or remote. Wildcard is supported. The default value is '*'.

    .PARAMETER Protocol
	    The name of the protocol (TCP or UDP). The default value is '*' (all)
	
    .PARAMETER State
	    Indicates the state of a TCP connection. The possible states are as follows:
		
	    Closed       - The TCP connection is closed. 
	    Close_Wait   - The local endpoint of the TCP connection is waiting for a connection termination request from the local user. 
	    Closing      - The local endpoint of the TCP connection is waiting for an acknowledgement of the connection termination request sent previously. 
	    Delete_Tcb   - The transmission control buffer (TCB) for the TCP connection is being deleted. 
	    Established  - The TCP handshake is complete. The connection has been established and data can be sent. 
	    Fin_Wait_1   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint or for an acknowledgement of the connection termination request sent previously. 
	    Fin_Wait_2   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint. 
	    Last_Ack     - The local endpoint of the TCP connection is waiting for the final acknowledgement of the connection termination request sent previously. 
	    Listen       - The local endpoint of the TCP connection is listening for a connection request from any remote endpoint. 
	    Syn_Received - The local endpoint of the TCP connection has sent and received a connection request and is waiting for an acknowledgment. 
	    Syn_Sent     - The local endpoint of the TCP connection has sent the remote endpoint a segment header with the synchronize (SYN) control bit set and is waiting for a matching connection request. 
	    Time_Wait    - The local endpoint of the TCP connection is waiting for enough time to pass to ensure that the remote endpoint received the acknowledgement of its connection termination request. 
	    Unknown      - The TCP connection state is unknown.
	
	    Values are based on the TcpState Enumeration:
	    http://msdn.microsoft.com/en-us/library/system.net.networkinformation.tcpstate%28VS.85%29.aspx
        
        Cookie Monster - modified these to match netstat output per here:
        http://support.microsoft.com/kb/137984

    .PARAMETER ComputerName
        If defined, run this command on a remote system via WMI.  \\computername\c$\netstat.txt is created on that system and the results returned here

    .PARAMETER ShowHostNames
        If specified, will attempt to resolve local and remote addresses.

    .PARAMETER tempFile
        Temporary file to store results on remote system.  Must be relative to remote system (not a file share).  Default is "C:\netstat.txt"

    .PARAMETER AddressFamily
        Filter by IP Address family: IPv4, IPv6, or the default, * (both).

        If specified, we display any result where both the localaddress and the remoteaddress is in the address family.

    .EXAMPLE
	    Get-NetworkStatistics | Format-Table

    .EXAMPLE
	    Get-NetworkStatistics iexplore -computername k-it-thin-02 -ShowHostNames | Format-Table

    .EXAMPLE
	    Get-NetworkStatistics -ProcessName md* -Protocol tcp

    .EXAMPLE
	    Get-NetworkStatistics -Address 192* -State LISTENING

    .EXAMPLE
	    Get-NetworkStatistics -State LISTENING -Protocol tcp

    .EXAMPLE
        Get-NetworkStatistics -Computername Computer1, Computer2

    .EXAMPLE
        'Computer1', 'Computer2' | Get-NetworkStatistics

    .OUTPUTS
	    System.Management.Automation.PSObject

    .NOTES
	    Author: Shay Levy, code butchered by Cookie Monster
	    Shay's Blog: http://PowerShay.com
        Cookie Monster's Blog: http://ramblingcookiemonster.github.io/

    .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Get-NetworkStatistics-66057d71
    #>	
	[OutputType('System.Management.Automation.PSObject')]
	[CmdletBinding()]
	param(
		
		[Parameter(Position=0)]
		[System.String]$ProcessName='*',
		
		[Parameter(Position=1)]
		[System.String]$Address='*',		
		
		[Parameter(Position=2)]
		$Port='*',

		[Parameter(Position=3,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)]
        [System.String[]]$ComputerName=$env:COMPUTERNAME,

		[ValidateSet('*','tcp','udp')]
		[System.String]$Protocol='*',

		[ValidateSet('*','Closed','Close_Wait','Closing','Delete_Tcb','DeleteTcb','Established','Fin_Wait_1','Fin_Wait_2','Last_Ack','Listening','Syn_Received','Syn_Sent','Time_Wait','Unknown')]
		[System.String]$State='*',

        [switch]$ShowHostnames,
        
        [switch]$ShowProcessNames = $true,	

        [System.String]$TempFile = "C:\netstat.txt",

        [validateset('*','IPv4','IPv6')]
        [string]$AddressFamily = '*'
	)
    
	begin{
        #Define properties
            $properties = 'ComputerName','Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','State','ProcessName','PID'

        #store hostnames in array for quick lookup
            $dnsCache = @{}
            
	}
	
	process{

        foreach($Computer in $ComputerName) {

            #Collect processes
            if($ShowProcessNames){
                Try {
                    $processes = Get-Process -ComputerName $Computer -ErrorAction stop | select name, id
                }
                Catch {
                    Write-warning "Could not run Get-Process -computername $Computer.  Verify permissions and connectivity.  Defaulting to no ShowProcessNames"
                    $ShowProcessNames = $false
                }
            }
	    
            #Handle remote systems
                if($Computer -ne $env:COMPUTERNAME){

                    #define command
                        [string]$cmd = "cmd /c c:\windows\system32\netstat.exe -ano >> $tempFile"
            
                    #define remote file path - computername, drive, folder path
                        $remoteTempFile = "\\{0}\{1}`${2}" -f "$Computer", (split-path $tempFile -qualifier).TrimEnd(":"), (Split-Path $tempFile -noqualifier)

                    #delete previous results
                        Try{
                            $null = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c del $tempFile" -ComputerName $Computer -ErrorAction stop
                        }
                        Catch{
                            Write-Warning "Could not invoke create win32_process on $Computer to delete $tempfile"
                        }

                    #run command
                        Try{
                            $processID = (Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $cmd -ComputerName $Computer -ErrorAction stop).processid
                        }
                        Catch{
                            #If we didn't run netstat, break everything off
                            Throw $_
                            Break
                        }

                    #wait for process to complete
                        while (
                            #This while should return true until the process completes
                                $(
                                    try{
                                        get-process -id $processid -computername $Computer -ErrorAction Stop
                                    }
                                    catch{
                                        $FALSE
                                    }
                                )
                        ) {
                            start-sleep -seconds 2 
                        }
            
                    #gather results
                        if(test-path $remoteTempFile){
                    
                            Try {
                                $results = Get-Content $remoteTempFile | Select-String -Pattern '\s+(TCP|UDP)'
                            }
                            Catch {
                                Throw "Could not get content from $remoteTempFile for results"
                                Break
                            }

                            Remove-Item $remoteTempFile -force

                        }
                        else{
                            Throw "'$tempFile' on $Computer converted to '$remoteTempFile'.  This path is not accessible from your system."
                            Break
                        }
                }
                else{
                    #gather results on local PC
                        $results = netstat -ano | Select-String -Pattern '\s+(TCP|UDP)'
                }

            #initialize counter for progress
                $totalCount = $results.count
                $count = 0
    
            #Loop through each line of results    
	            foreach($result in $results) {
            
    	            $item = $result.line.split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)
    
    	            if($item[1] -notmatch '^\[::'){
                    
                        #parse the netstat line for local address and port
    	                    if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $localAddress = $la.IPAddressToString
    	                        $localPort = $item[1].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $localAddress = $item[1].split(':')[0]
    	                        $localPort = $item[1].split(':')[-1]
    	                    }
                    
                        #parse the netstat line for remote address and port
    	                    if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $remoteAddress = $ra.IPAddressToString
    	                        $remotePort = $item[2].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $remoteAddress = $item[2].split(':')[0]
    	                        $remotePort = $item[2].split(':')[-1]
    	                    }

                        #Filter IPv4/IPv6 if specified
                            if($AddressFamily -ne "*")
                            {
                                if($AddressFamily -eq 'IPv4' -and $localAddress -match ':' -and $remoteAddress -match ':|\*' )
                                {
                                    #Both are IPv6, or ipv6 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                                elseif($AddressFamily -eq 'IPv6' -and $localAddress -notmatch ':' -and ( $remoteAddress -notmatch ':' -or $remoteAddress -match '*' ) )
                                {
                                    #Both are IPv4, or ipv4 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                            }
    	    		
                        #parse the netstat line for other properties
    	    		        $procId = $item[-1]
    	    		        $proto = $item[0]
    	    		        $status = if($item[0] -eq 'tcp') {$item[3]} else {$null}	

                        #Filter the object
		    		        if($remotePort -notlike $Port -and $localPort -notlike $Port){
                                write-verbose "remote $Remoteport local $localport port $port"
                                Write-Verbose "Filtered by Port:`n$result"
                                continue
		    		        }

		    		        if($remoteAddress -notlike $Address -and $localAddress -notlike $Address){
                                Write-Verbose "Filtered by Address:`n$result"
                                continue
		    		        }
    	    			     
    	    			    if($status -notlike $State){
                                Write-Verbose "Filtered by State:`n$result"
                                continue
		    		        }

    	    			    if($proto -notlike $Protocol){
                                Write-Verbose "Filtered by Protocol:`n$result"
                                continue
		    		        }
                   
                        #Display progress bar prior to getting process name or host name
                            Write-Progress  -Activity "Resolving host and process names"`
                                -Status "Resolving process ID $procId with remote address $remoteAddress and local address $localAddress"`
                                -PercentComplete (( $count / $totalCount ) * 100)
    	    		
                        #If we are running showprocessnames, get the matching name
                            if($ShowProcessNames -or $PSBoundParameters.ContainsKey -eq 'ProcessName'){
                        
                                #handle case where process spun up in the time between running get-process and running netstat
                                if($procName = $processes | Where {$_.id -eq $procId} | select -ExpandProperty name ){ }
                                else {$procName = "Unknown"}

                            }
                            else{$procName = "NA"}

		    		        if($procName -notlike $ProcessName){
                                Write-Verbose "Filtered by ProcessName:`n$result"
                                continue
		    		        }
    	    						
                        #if the showhostnames switch is specified, try to map IP to hostname
                            if($showHostnames){
                                $tmpAddress = $null
                                try{
                                    if($remoteAddress -eq "127.0.0.1" -or $remoteAddress -eq "0.0.0.0"){
                                        $remoteAddress = $Computer
                                    }
                                    elseif($remoteAddress -match "\w"){
                                        
                                        #check with dns cache first
                                            if ($dnsCache.containskey( $remoteAddress)) {
                                                $remoteAddress = $dnsCache[$remoteAddress]
                                                write-verbose "using cached REMOTE '$remoteAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $remoteAddress
                                                    $remoteAddress = [System.Net.DNS]::GetHostByAddress("$remoteAddress").hostname
                                                    $dnsCache.add($tmpAddress, $remoteAddress)
                                                    write-verbose "using non cached REMOTE '$remoteAddress`t$tmpAddress"
                                            }
                                    }
                                }
                                catch{ }

                                try{

                                    if($localAddress -eq "127.0.0.1" -or $localAddress -eq "0.0.0.0"){
                                        $localAddress = $Computer
                                    }
                                    elseif($localAddress -match "\w"){
                                        #check with dns cache first
                                            if($dnsCache.containskey($localAddress)){
                                                $localAddress = $dnsCache[$localAddress]
                                                write-verbose "using cached LOCAL '$localAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $localAddress
                                                    $localAddress = [System.Net.DNS]::GetHostByAddress("$localAddress").hostname
                                                    $dnsCache.add($localAddress, $tmpAddress)
                                                    write-verbose "using non cached LOCAL '$localAddress'`t'$tmpAddress'"
                                            }
                                    }
                                }
                                catch{ }
                            }
    
    	    		    #Write the object	
    	    		        New-Object -TypeName PSObject -Property @{
		    		            ComputerName = $Computer
                                PID = $procId
		    		            ProcessName = $procName
		    		            Protocol = $proto
		    		            LocalAddress = $localAddress
		    		            LocalPort = $localPort
		    		            RemoteAddress =$remoteAddress
		    		            RemotePort = $remotePort
		    		            State = $status
		    	            } | Select-Object -Property $properties								

                        #Increment the progress counter
                            $count++
                    }
                }
        }
    }
}

function Get-InstalledAppsFromRegistry
{
    
    $scriptBlock={

        #this function gets all properties from registry
        #It doesn't fail if a property value is corrupted
        
        function read-AppPropertiesToObj{
            param($Application, $Architecture)

            $prop = @{
                APP_Architecture = $Architecture
                APP_GUID = $Application.PSChildName
            }

            #for PS 2.0 compatibility
            $itemslist = @($Application | select -ExpandProperty Property)

            foreach ($item in $itemslist)
            {
                #if value is corrupted, get-itemproperty function fails
                try
                {
                    $prop.$item = $Application | Get-ItemProperty -name $item | select -ExpandProperty $item
                }
                catch
                {
                    $prop.$item = '(invalid value)'
                }
            }

            $result = New-Object psobject -Property $prop

            return $result
        }#function

        $apps = @()
        $results = @()

        if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node\microsoft\Windows\CurrentVersion\Uninstall')
        {
            #
            #"64 bit system, 32 bit node"
            $apps = Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\microsoft\Windows\CurrentVersion\Uninstall'
        
            foreach ($app in $apps)
            {
                $results += read-AppPropertiesToObj -Application $app -Architecture 32
            }

            #64 bit system, 64 bit node
            $apps = Get-ChildItem 'HKLM:\SOFTWARE\microsoft\Windows\CurrentVersion\Uninstall'

            foreach ($app in $apps)
            {
                $results += read-AppPropertiesToObj -Application $app -Architecture 64
            }

        }
        else
        {
            #32 bit system, 32 bit node
            $apps = Get-ChildItem 'HKLM:\SOFTWARE\microsoft\Windows\CurrentVersion\Uninstall'

            foreach ($app in $apps)
            {
                $results += read-AppPropertiesToObj -Application $app -Architecture 32
            }
        }#if else

        return $results | sort DisplayName

    }#scriptblock
    
    #determine OS architecture and path to the native powershell.exe

    #-----32 bit process running on a 64 bit machine
    if (([intptr]::size -eq 4) -and (test-path env:\PROCESSOR_ARCHITEW6432))
    {
        $PsExePath = "C:\windows\sysnative\WindowsPowerShell\v1.0\powershell.exe"
    }
    #-----64 bit process running on a 64 bit machine
    elseif (([intptr]::size -eq 8) -and !(test-path env:\PROCESSOR_ARCHITEW6432))
    {
        $PsExePath = "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
    }
    #-----32 bit process running on a 32 bit machine
    else
    {
        $PsExePath = "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
    }

    #execute command
    $tmp = & $PsExePath $scriptBlock

    #return results
    return $tmp
}

function Get-Virtual{
    $NetAdapters = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() #Get NetAdapter Information
    foreach ($NetAdapter in $NetAdapters){
    	$Net_Type = $NetAdapter.NetworkInterfaceType    #Get NetAdapter Type ,such as Ethernet
    	#write-host $Net_Type
    	if ($Net_Type -eq "Ethernet"){ 
    		$Net_Dec=$NetAdapter.Description       # NetAdapter Drivers type
    		#write-host $Net_Dec
    		if ($Net_Dec.contains("VirtIO")){
    		    $vm_platform = "KVM Platform"
                return $vm_platform    
    		}else{
    		    $vm_platform = "Xen Platform"
                return $vm_platform
    		}
    	}
    }
}
function Get-WindowsUpdatePolicy
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([Microsoft.Win32.RegistryKey])]
    Param
    (
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [string[]]$ComputerName=$env:COMPUTERNAME,

        # Windows Update policy registry key path
        [string]$Key='HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate',
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        # Helper function to get the registry keys and values
        function Get-RegistryKey ($Key, $Computer) {
            Write-Verbose "$Computer"
            if (Test-Path $Key) {
                # Get the WindowsUpdate policy information
                Get-ItemProperty $Key
                
                # Get the WindowsUpdate AU sub key values
                if (Test-Path $Key\AU) {
                    Get-ItemProperty $Key\AU
                    }
                
                }
            else {
                Write-Host "No Windows Update policy set for $Computer."
                }
            }

    }
    Process
    {
        foreach ($Computer in $ComputerName) {
            if ($Computer -eq $env:COMPUTERNAME) {
                Write-Verbose "Getting Windows Update policy registry settings from $Computer."
                Get-RegistryKey -Key $Key
                }
            else {
                Write-Verbose "Getting remote Windows Update policy registry settings from $Computer."
                Invoke-Command -ScriptBlock ${function:Get-RegistryKey} -ComputerName $Computer -ArgumentList $Key,$Computer -Credential $Credential
                }
            }
    }
    End
    {
    }
}

function Compress-Files{
    $EmlPath="C:\check_health\" #文件所在的文件夹  
    $ZipPath="C:\" + (Get-Date).ToString('yyyy-MM-dd hh-mm-ss') + ".zip" #最终输出的Zip文件，以时间动态生成。  
      
    #加载依赖  
    #[System.Reflection.Assembly]::Load("WindowsBase,Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35")  
    Set-StrictMode -Version Latest
    #删除已有的压缩包  
    if (Test-Path($ZipPath))  
    {  
        Remove-Item $ZipPath  
    }  
      
    #获取文件集合  
    $Di=New-Object System.IO.DirectoryInfo($EmlPath)
    $files = $Di.GetFiles()
    #write-host $files
    if($files.Count -eq 0)  
    {  
        exit  
    }  
      
    #打开压缩包  
    $pkg=[System.IO.Packaging.ZipPackage]::Open($ZipPath,  
       [System.IO.FileMode]"OpenOrCreate", [System.IO.FileAccess]"ReadWrite")  
      
    #加入文件到压缩包  
    ForEach ($file In $files)  
    {  
        $uriString="/" +$file.Name  
        $partName=New-Object System.Uri($uriString, [System.UriKind]"Relative")  
        $pkgPart=$pkg.CreatePart($partName, "application/zip",  
            [System.IO.Packaging.CompressionOption]"Maximum")  
        $bytes=[System.IO.File]::ReadAllBytes($file.FullName)  
        $stream=$pkgPart.GetStream()  
        $stream.Seek(0, [System.IO.SeekOrigin]"Begin");  
        $stream.Write($bytes, 0, $bytes.Length)  
        $stream.Close()  
        Remove-Item $file.FullName  
    }  
      
    #关闭压缩包  
    $pkg.Close() 
}


$vm_virtual_platform = Get-Virtual
$PageFile = Get-WmiObject -class Win32_PageFileSetting -EnableAllPrivileges
$minSize = $PageFile.InitialSize
$maxSize = $PageFile.MaximumSize

"<table id='sysinfo'><tr><th colspan=2>System Information</th></tr>" >> $File
"<tr><td>Computer Name</td><td>" + $sysinfo.Name + "</td></tr>" >> $File
"<tr><td>Computer Type</td><td>" + $sysinfo.SystemType + "</td></tr>" >> $File
"<tr><td>Computer Manufacturer</td><td>" + $vm_virtual_platform + "</td></tr>" >> $File
"<tr><td>Computer Model</td><td>" + $sysinfo.Model + "</td></tr>" >> $File
"<tr><td>CPU Information</td><td>" + $processor.Name + "</td></tr>" >> $File
"<tr><td>Installed RAM</td><td>" + [math]::Round($sysinfo.TotalPhysicalMemory / 1000000000) + " GB</td></tr>" >> $File
"<tr><td>BIOS Manufacturer</td><td>" + $bios.Manufacturer + "</td></tr>" >> $File
"<tr><td>BIOS Name</td><td>" + $bios.Name + "</td></tr>" >> $File
"<tr><td>BIOS Serial</td><td>" + $bios.SerialNumber + "</td></tr>" >> $File
"<tr><td>Hostname</td><td>" + $sysinfo.DNSHostName + "</td></tr>" >> $File
"<tr><td>Domain</td><td>" + $sysinfo.Domain + "</td></tr>" >> $File
"<tr><td>Operating System</td><td>" + $os.Caption + " (" + $os.OSArchitecture + ")</td></tr>" >> $File
"<tr><td>Build Number</td><td>" + (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion" |Select -ExpandProperty CurrentBuildNumber) + "</td></tr>" >> $File
"<tr><td>Product ID</td><td>" + (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion" |Select -ExpandProperty ProductId) + "</td></tr>" >> $File
"<tr><td>Local Users</td><td>" >> $File
ForEach ($u in $users) { $u.PartComponent -match ".*Name=(?<username>.*),.*Domain=(?<domain>.*).*" | Out-Null; $matches.username >> $File; " " >> $File }
"</td></tr>" >> $File
"</table>" >> $File

Write-Output "* Action Center"
#$as = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiSpywareProduct
#$av = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
$fw_std = Get-ItemProperty "HKLM:System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" | select -ExpandProperty EnableFirewall
$fw_dmn = Get-ItemProperty "HKLM:System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" | select -ExpandProperty EnableFirewall
$fw_pub = Get-ItemProperty "HKLM:System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" | select -ExpandProperty EnableFirewall
#Write-Output "* Windows Updates"
#$lastupd = Get-HotFix | Where-Object {$_.InstalledOn} | Sort-Object -Property InstalledOn | Select -Last 1 | Select -ExpandProperty InstalledOn
#$UpdateSession = New-Object -ComObject Microsoft.Update.Session
#$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
#$wu = $UpdateSearcher.Search("IsInstalled=0")
Write-Output "* System Load"
$cpuload = Get-Counter -Counter "\Processor(*)\% Processor Time" | Select -ExpandProperty CounterSamples | Select -ExpandProperty CookedValue | Measure-Object -Average | Select -ExpandProperty Average
$freemem = Get-Counter -Counter "\Memory\Available MBytes" | Select -ExpandProperty CounterSamples | Select -ExpandProperty CookedValue
$freemem = $freemem / 1000
$netload = [math]::round(((Get-Counter -Counter "\Network Interface(*)\Bytes Total/sec" -SampleInterval 1 -MaxSamples 3 | Select -ExpandProperty CounterSamples | Select -ExpandProperty CookedValue |Measure -Maximum |Select -ExpandProperty Maximum) / 1000),1)
$original=Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'portnumber'
$remote_port = $original.PortNumber
"<table id='action'><tr><th colspan=2>系统配置信息及负载信息</th></tr>" >> $File
#"<tr><td>Anti-Virus Software</td><td>" + $av.displayName + " " + $av.VersionNumber + "</td></tr>" >> $File
#"<tr><td>Anti-Spyware Software</td><td>" + $as.displayName + " " + $as.VersionNumber + "</td></tr>" >> $File
"<tr><td>Firewall Status</td><td>Domain: " + (&{If($fw_dmn -eq 1) {"On"} Else {"<font color=red>Off</font>"}}) + ", Private: " + (&{If($fw_std -eq 1) {"On"} Else {"<font color=red>Off</font>"}}) + ", Public: " + (&{If($fw_pub -eq 1) {"On"} Else {"<font color=red>Off</font>"}}) + "</td></tr>" >> $File
"<tr><td>Processor Load</td><td>" + (&{If($cpuload -lt 80) {[math]::Round($cpuload,2)} Else {"<font color=red>"+[math]::Round($cpuload,2)+"</font>"}}) + "%</td></tr>" >> $File
"<tr><td>Network Adapters</td><td>" + $netinfor + "</td></tr>" >> $File
"<tr><td>Network Load</td><td>" + $netload + " KBytes/s</td></tr>" >> $File
"<tr><td>Free Memory</td><td>" + (&{If($freemem -gt 0.4) {"$freemem GB"} Else {"<font color=red>$freemem GB</font>"}}) + "</td></tr>" >> $File
"<tr><td>Last Boot</td><td>" + $os.ConvertToDateTime($os.LastBootUpTime) + " (" + (&{If($sysinfo.BootupState -eq "Normal boot") {$sysinfo.BootupState} Else {"<font color=red>"+$sysinfo.BootupState+"</font>"}}) + ")</td></tr>" >> $File
"<tr><td>Last Windows Update</td><td>" + $lastupd + (&{If(Get-ChildItem "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" | Where {$_.PSChildName -eq "RebootPending"}) { " <font color=red>(Reboot pending)</font>" }}) + "</td></tr>" >> $File
"<tr><td>Time Zone</td><td>" + $timezone+ "</td></tr> ">> $File
"<tr><td>Pagefile</td><td>" +"Min Pagefile: "+ $minSize+ "  "+"Max Pagefile: "+ $maxSize + "</td></tr> ">> $File
"<tr><td>RDP Port Number</td><td>" + $remote_port + "</td></tr> ">> $File
#"<tr><td>Available Critical Updates</td><td>" >> $File
$criticals = $wu.updates | where { $_.MsrcSeverity -eq "Critical" }
ForEach($critical in $criticals)
{
    "<font color=red>" >> $File
    $critical | Select -ExpandProperty Title >> $File
    "</font><br>" >> $File 
}
"</td></tr>" >> $File
#Write-Host "* Event log"
#$events = Get-EventLog Security -EntryType FailureAudit -After (Get-Date).AddHours(-1)
#if($events)
#{
#    ForEach($event in $events) 
#    {
#        $id = $event.InstanceID
#        $msg = $event.Message
#      	$tim = $event.TimeGenerated
#        "<tr><td>Event Audit Failure ($id)</td><td><font color=red><pre>$msg</pre>Time Generated: $tim</font></td></tr>" >> $File
#    }
#}
"</table><div style='clear:both'></div>" >> $File


"<a name='services'></a><h2>Running Services</h2>" >> $File
Write-Output "* Services"
Get-WmiObject -Class win32_service | Sort -Property DisplayName | Select @{Name='Name';Expression={$_.DisplayName}},@{Name='Mode';Expression={$_.StartMode}},@{Name='Path';Expression={$_.PathName}},Description | ConvertTo-Html -Fragment >> $File

#获取磁盘数据信息 
"</table><div style='clear:both'></div>" >> $File
"<a name='disks'></a><h2>Disk Space</h2>" >> $File
Write-Output "* Disks"
$disks = Get-WmiObject -Class win32_logicaldisk

"<table><tr><th>Drive</th><th>Type</th><th>Size</th><th>Free Space</th></tr>" >> $File
ForEach($d in $disks)
{
    $drive = $d.Name
    $type = $d.Description
    $size = [math]::Round($d.Size / 1000000000,1)
    $freespace = [math]::Round($d.FreeSpace / 1000000000,1)
    If($freespace -le 1 -And $freespace -ne 0) { "<tr><td>$drive</td><td>$type</td><td>$size GB</td><td><font color=red>$freespace GB</font></td></tr>" >> $File }
    Else { "<tr><td>$drive</td><td>$type</td><td>$size GB</td><td>$freespace GB</td></tr>" >> $File }
}
"</table>" >> $File

"<a name='network'></a><h2>Network Addresses</h2>" >> $File
Write-Output "* Network"
Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = True' | Select @{Name='Interface';Expression={$_.Description}},@{Name='IP Addresses';Expression={$_.IPAddress}} | ConvertTo-Html -Fragment >> $File

"<a name='processes'></a><h2>Running Processes</h2>" >> $File
Write-Output "* Processes"
Get-WmiObject -Class win32_process | Sort -Property WorkingSetSize -Descending | Select @{Name='ID';Expression={$_.ProcessId}},@{Name='Name';Expression={$_.ProcessName}},@{Name='Path';Expression={$_.CommandLine}},@{Name='Memory Usage (MB)';Expression={[math]::Round($_.WorkingSetSize / 1000000, 3)}} | ConvertTo-Html -Fragment >> $File

"<a name='hotfixes'></a><h2>HotFixes</h2>" >> $File
Write-Output "* Hotfixes"
get-hotfix | sort InstalledOn -Descending | Select @{Name='Hotfix Type';Expression={$_.Description}},@{Name='Hotfix ID';Expression={$_.HotFixID}},@{Name='Installed User';Expression={$_.InstalledBy}},@{Name='Installed Date';Expression={$_.InstalledOn}} | ConvertTo-Html -Fragment >> $File

"<a name='InstalledApps'></a><h2>Installed Apps</h2>" >> $File
Write-Output "* Installed Apps"
#Get-WmiObject -Class Win32_Product | Sort -Property Name -Descending | Select @{Name='APP Name ';Expression={$_.Name}},@{Name='APP Verdor ';Expression={$_.Vendor}},@{Name='APP Version';Expression={$_.Version}} | ConvertTo-Html -Fragment >> $File


$InstallApps = Get-InstalledAppsFromRegistry
$apps=@()
foreach ($app in $InstallApps){
    if ($app.DisplayName.length -gt 0){
        #Write-Host $app.DisplayName
        $apps +=$app | Select-Object DisplayName,DisplayVersion,InstallDate,Publisher
    }
}
$apps | Select @{Name='Name';Expression={$_.DisplayName}},@{Name='App Version';Expression={$_.DisplayVersion}},@{Name='Installed Date';Expression={$_.InstallDate}},@{Name='Publisher';Expression={$_.Publisher}} | ConvertTo-Html -Fragment >> $File

"<a name='NetConnections'></a><h2>Network Connections</h2>" >> $File
Write-Output "* Network Connections"
$netstats=Get-NetworkStatistics
$netstats | Sort |Select @{Name='Protocal';Expression={$_.Protocol}},@{Name='LocalAddress';Expression={$_.LocalAddress}},@{Name='LocalPort';Expression={$_.LocalPort}},
@{Name='RemoteAddress';Expression={$_.RemoteAddress}},@{Name='RemotePort';Expression={$_.RemotePort}},@{Name='State';Expression={$_.State}},@{Name='ProcessName';Expression={$_.ProcessName}},@{Name='PID';Expression={$_.PID}} | ConvertTo-Html -Fragment >> $File

"<a name='ScheduledTasks'></a><h2>Get-ScheduledTasks</h2>" >> $File
Write-Output "* Get ScheduledTasks"
$ScheduledTasks =Get-ScheduledTask
$ScheduledTasks |Select @{Name='Name';Expression={$_.Name}},@{Name='State';Expression={$_.State}},@{Name='Author';Expression={$_.Author}},
@{Name='UserId';Expression={$_.UserId}},@{Name='LastRunTime';Expression={$_.LastRunTime}},@{Name='LastTaskResult';Expression={$_.LastTaskResult}},
@{Name='NextRunTime';Expression={$_.NextRunTime}},@{Name='Trigger';Expression={$_.Trigger}}|Where-Object {$_.state -ne "Disabled" } | ConvertTo-Html -Fragment >> $File

Write-Output "* Get-WindowsUpdatePolicy"
$UpdateFile = "C:/check_health/UpdatePolicy.txt"
$UpdatePolicy = Get-WindowsUpdatePolicy
Write-Output "* Get-WindowsUpdatePolicy" > $UpdateFile
$UpdatePolicy  >> $UpdateFile


$date = Get-Date
"<p><i>Report produced: $date</i></p>" >> $File

if ( Test-Path C:/check_health/* -include *.evtx){
    write-host "Delete logs ..."
    remove-item C:/check_health/* -include *.evtx
    write-host "Re-Generate New  Logs...."
    cmd /c wevtutil epl System C:/check_health/system.evtx
    cmd /c wevtutil epl Application C:/check_health/app.evtx
    cmd /c wevtutil epl Security C:/check_health/security.evtx
    cmd /c wevtutil epl Setup C:/check_health/setup.evtx
    write-host "Re-Generate New  Logs Completely...."
}
else{
	write-host "Generate New logs"
	cmd /c wevtutil epl System C:/check_health/system.evtx
	cmd /c wevtutil epl Application C:/check_health/app.evtx
	cmd /c wevtutil epl Security C:/check_health/security.evtx
	cmd /c wevtutil epl Setup C:/check_health/setup.evtx
}

#perf_monitor