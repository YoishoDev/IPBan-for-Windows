# Automatically block IP addresses
# Use ESET RMM to retrieve the firewall log and write it to a file
# Version 1: initial functions
# Pending: handling subnets in firewall rules, unbanning
# For a continuously running Fail2Ban system, I would also consider:
# retaining only the last X days, automatic unblocking, CIDR aggregation

# Version 1.0 - initial creation
# Version 1.1 - add /24 subnets to firewall rule starting from threshold

$debugMode = $true
$esetFWLogFile = "C:\Program Files\IPBan\esetFWLog.json"

$logFile = "C:\Program Files\IPBan\IPBan.log"

$fwRuleName = "0_IPBan-List"

# Define IP ranges to be ignored
$excludePatterns = @(
    '10.10.220.*'
    #'192.168.*.*'
)

# Block entire subnets instead of individual IP addresses
$subNetThreshold = 5   # Use subnet instead of individual addresses starting at 5 IPs
$subNetPrefixLength = 24 # Use only /24 networks

# Today's date in firewall log format
$today = (Get-Date).ToString('yyyy-MM-dd')

# Graylog
$version="1.1"
$short_message = "IPBan messages from Windows PowerShell script"
$full_message = "IPBan action Ban "
$sourceModuleName = "fail2ban"
$grayLogServer = "graylogserver.domain.com"
[int]$grayLogServerPort = 12201


# Logging
function Write-Log
{
    Param
    (
        $text
    )
	
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $text" | Out-File $logFile -Append -Encoding UTF8
}

if ($debugMode) {
	Write-Log "----------------------------------------------------------"
	Write-Log "Lese $esetFWLogFile mittel ermm.exe (ESET) ein."
}

# Use RMM to retrieve the ESET log file
& "C:\Program Files\ESET\ESET Security\eRmm.exe" get logs --name epfwlog --start-date "$today 00-00-00" > $esetFWLogFile

# Create an empty list (HashSet) to store the IP as a (unique) string
$updatedIpList = [System.Collections.Generic.HashSet[string]]::new()

# Importing as JSON didn't work; considering the effort vs. benefit, read and parse as a text file instead
foreach($line in [System.IO.File]::ReadLines($esetFWLogFile))
{
		# we are interested in the "attacker's" IP
		if ($line -match '"SourceIpv4":"([^"]+)"') {
		$ip = $matches[1]

		# only IPs that are not excluded
		if (-not ($excludePatterns | Where-Object { $ip -like $_ })) {
		$null = $updatedIpList.Add($ip)
					}
		}
}

if ($updatedIpList.Count -eq 0) {
	if ($debugMode) {
		Write-Log "No relevant IP addresses found in the ESET log."
	}
	Exit 0
	
}

if ($debugMode) {
	Write-Log "$($updatedIpList.Count) IP address(es) found in the ESET log."
}

# Check if firewall rule exists
$rule = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue

if ($rule) {
    $currentIpList = @(
        ($rule | Get-NetFirewallAddressFilter).RemoteAddress | Where-Object {
            $_ -ne 'Any'
        }
    )
}
else {
    $currentIpList = @()
}

if ($debugMode) {
	Write-Log "Aktuell werden $($currentIpList.Count) IP-Adressen bzw. Subnetze geblockt."
}

# Merge existing and new IP addresses
# Combine both lists
$bannedIpList = @($currentIpList) + $updatedIpList

# Remove duplicates
$bannedIpList = $bannedIpList | Sort-Object -Unique

# Optionally replace IP addresses with subnets
# Group by /24 network

# Handle existing subnets separately before grouping
$existingSubnets = @()
$singleIPs = @()

foreach ($entry in $bannedIpList) {

    # CIDR entry?
    if ($entry -match '^\d+\.\d+\.\d+\.\d+/\d+$') {
        $existingSubnets += $entry
    }
    else {
        $singleIPs += $entry
    }
}

$singleIPs = $singleIPs | Where-Object {

    $ip = $_
    $covered = $false

    foreach ($subnet in $existingSubnets) {

        $network,$prefix = $subnet.Split('/')

        $ipBytes  = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
        $netBytes = ([System.Net.IPAddress]::Parse($network)).GetAddressBytes()

        $ipInt =
            ($ipBytes[0] -shl 24) -bor
            ($ipBytes[1] -shl 16) -bor
            ($ipBytes[2] -shl 8)  -bor
            $ipBytes[3]

        $netInt =
            ($netBytes[0] -shl 24) -bor
            ($netBytes[1] -shl 16) -bor
            ($netBytes[2] -shl 8)  -bor
            $netBytes[3]

        $mask = ([uint32]0xffffffff) -shl (32 - [int]$prefix)

        if (($ipInt -band $mask) -eq ($netInt -band $mask)) {
            $covered = $true
            break
        }
    }

    -not $covered
}

# group only individual IP addresses
$subNetGroups = $singleIPs | Group-Object {
    $octets = $_.Split('.')
    "$($octets[0]).$($octets[1]).$($octets[2]).0/$subNetPrefixLength"
}

# re-add existing networks
$updatedBannedIpList = [System.Collections.Generic.List[string]]::new()

foreach ($subnet in $existingSubnets) {
    $updatedBannedIpList.Add($subnet)
}

foreach ($subNetGroup in $subNetGroups) {

    if ($subNetGroup.Count -ge $subNetThreshold) {
        $updatedBannedIpList.Add($subNetGroup.Name)
    }
    else {
        foreach ($ip in $subNetGroup.Group) {
            $updatedBannedIpList.Add($ip)
        }
    }
}

# Accept the result of the CIDR aggregation
$bannedIpList = $updatedBannedIpList | Sort-Object -Unique

# Check if the two lists are identical
$isEqual = -not (Compare-Object $currentIpList $bannedIpList)
if ($isEqual) {
	if ($debugMode) {
	Write-Log "No new IP addresses to block." 
	}
Exit 0

}

# Create or update firewall rule
if (-not $rule) {
	New-NetFirewallRule `
        -DisplayName $fwRuleName `
        -Direction Inbound `
        -Action Block `
        -Enabled True `
        -Profile Any `
        -RemoteAddress $bannedIpList
	
	if ($debugMode) {
		Write-Log "Firewall rule '$fwRuleName' has been newly created."
	}
}else {

    Set-NetFirewallRule `
        -DisplayName $fwRuleName `
        -RemoteAddress $bannedIpList
	
	if ($debugMode) {
		Write-Log "Firewall rule '$fwRuleName' has been updated."
	}
}

if ($debugMode) {
	Write-Log "A total of $($bannedIpList.Count) IP addresses or subnets are now being blocked."
}

# Send blocked IP addresses as JSON to a central SIEM
# ClientIP, Fail2BanAction (Ban, Unban), SourceModuleName (fail2ban), source
# 2026-05-29 08:27:04.000
$timeStamp = [DateTimeOffset]::Now.ToUnixTimeSeconds()

# report only IP addresses, no subnets
$ipOnlyList = $bannedIpList | Where-Object {
    $_ -match '^\d{1,3}(\.\d{1,3}){3}$'
}

ForEach ($ip in $ipOnlyList) {
	
	# only report newly blocked IP addresses 
	if (-not ($currentIpList -contains $ip)) { 

	#Create JSON with blocked IP
		$payload = @{
			version         = $version
			short_message   = $short_message
			full_message    = "$full_message$ip"
			source          = ($env:COMPUTERNAME).ToLower()
			SourceModuleName= $sourceModuleName
			ClientIP        = $ip
			Fail2BanAction  = "Ban"
			timestamp       = $timeStamp
		}
		$jsonString = $payload | ConvertTo-Json -Compress
		
		# send to Graylog
		try {
			$Address = [System.Net.Dns]::GetHostAddresses($grayLogServer) |
				Where-Object AddressFamily -eq InterNetwork |
				Select-Object -First 1
			$EndPoints = New-Object System.Net.IPEndPoint($Address, $grayLogServerPort)
			$Socket = New-Object System.Net.Sockets.UDPClient
			$EncodedText = [Text.Encoding]::UTF8.GetBytes($jsonString)
			$SendMessage = $Socket.Send($EncodedText, $EncodedText.Length, $EndPoints)
			$SendMessage | Out-Null
			$Socket.Close()
		} catch {
			Write-Log "Failed to send UDP message to Graylog SIEM: $_"
		}
	}
}	
Exit 0