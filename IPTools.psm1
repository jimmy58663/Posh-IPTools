Function Get-IPv4Mask {
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,Position=0)]
    [ValidateRange(0,32)]
    [Int]$CIDRBits
)
    Begin {}
    Process {
        $Mask = ([Math]::Pow(2, $CIDRBits) - 1) * [Math]::Pow(2, (32 - $CIDRBits))
        $Bytes = [System.BitConverter]::GetBytes([uint32]$Mask)
        $MaskString = (($Bytes.Count - 1)..0 | ForEach-Object { [String] $Bytes[$PSItem] }) -join '.'
        Write-Output $MaskString
    }
    End {}
}

Function Convert-IPToInt64 {
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,Position=0)]
    [string]$IPString
)
    Begin {}
    Process {
        $Octets = $IPString.Split('.')
        $First = [int64]$Octets[0] * 16777216
        $Second = [int64]$Octets[1] * 65536
        $Third = [int64]$Octets[2] * 256
        $Fourth = [int64]$Octets[3]
        Write-Output ($First + $Second + $Third + $Fourth)
    }
    End {}
}

Function Get-IPRange {
<#
	.SYNOPSIS
		A function used to quickly obtain a whole IP Range.
	
	.DESCRIPTION
		Calculates and provides all IP addresses within a given range based on start and end, IP and CIDR bits, or IP and subnet mask.
	
	.PARAMETER Start
		The beginning IP of the range you want.
	
	.PARAMETER End
		The end IP of the range you want.
	
	.PARAMETER IPString
		The IP value that is inside of the specified subnet.
	
	.PARAMETER Mask
		The subnet mask for the given IPString.
	
	.PARAMETER CIDR
		The CIDR bits for the given IPString.
	
	.EXAMPLE
		PS C:\> Get-IPRange -Start '192.168.0.1' -End '192.168.0.254'
	
	.EXAMPLE
		PS C:\> Get-IPRange -IPString '192.168.0.50' -Mask '255.255.255.0'
	
	.EXAMPLE
		PS C:\> Get-IPRange -IPString '192.168.0.50' -CIDR 24
#>
[CmdletBinding(DefaultParameterSetName='Range')]
Param(
    [Parameter(ParameterSetName='Range',Mandatory=$true,Position=1)]
    [string]$Start,

    [Parameter(ParameterSetName='Range',Mandatory=$true,Position=2)]
    [string]$End,
    
    [Parameter(ParameterSetName='Mask',Mandatory=$true)]
    [Parameter(ParameterSetName='CIDR',Mandatory=$true)] 
    [string]$IPString,

    [Parameter(ParameterSetName='Mask',Mandatory=$true)]
    [string]$Mask,

    [Parameter(ParameterSetName='CIDR',Mandatory=$true)]
    [ValidateRange(0,32)]
    [int]$CIDR,

    [Parameter()]
    [switch]$ExcludeBroadcast,

    [Parameter()]
    [switch]$ExcludeNetAddress
)
    Begin {}
    Process {
        If ($PSCmdlet.ParameterSetName -eq 'CIDR') {
            $Mask = Get-IPv4Mask -CIDRBits $CIDR
        }
        If ($PSCmdlet.ParameterSetName -eq 'CIDR' -or $PSCmdlet.ParameterSetName -eq 'Mask') {
            $IP = [ipaddress]$IPString
            $IPMask = [ipaddress]$Mask
            [ipaddress]$StartIP = $IPMask.Address -band $IP.Address
            $EndIPAddress = (([ipaddress]'255.255.255.255').Address -bxor $IPMask.Address -bor $StartIP.Address)
            $End = ([ipaddress]$EndIPAddress).IPAddressToString
            $Start = $StartIP.IPAddressToString
        }
        $IPStart = Convert-IPToInt64 -IPString $Start
        $IPEnd = Convert-IPToInt64 -IPString $End
        If ($ExcludeBroadcast) {
            $IPEnd = $IPEnd - 1
        }
        If ($ExcludeNetAddress) {
            $IPStart = $IPStart + 1
        }
        For ($CurrentIP = $IPStart; $CurrentIP -le $IPEnd; $CurrentIP++){
            $CurrentIPString = ([ipaddress]::Parse($CurrentIP)).IPAddressToString
            Write-Output $CurrentIPString
        }
    }
    End {}
}

Function Test-ConnectionAsync {
<#
	.SYNOPSIS
		Performs asynchronous pings to multiple ComputerNames.
	
	.DESCRIPTION
		Performs a ping sweep of all provided ComputerNames in an asynchronous manner so that it is expedient.
	
	.PARAMETER ComputerName
		An array of IPs or computer hostnames.
	
	.EXAMPLE
		PS C:\> Test-ConnectionAsync -ComputerName $IPArray
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, Position = 1)]
    [string[]]$ComputerName
)
    Begin {}
    Process {
        $Tasks = ForEach ($HostName in $ComputerName){
            [System.Net.NetworkInformation.Ping]::new().SendPingAsync($HostName)
        }
        [Threading.Tasks.Task]::WaitAll($Tasks)
        Write-Output ($Tasks.Result)
    }
    End {}
}

Function Get-HostEntry {
<#
	.SYNOPSIS
		Performs host lookups to multiple IPs.
	
	.DESCRIPTION
		Resolves all provided IPs with DNS and provides hostnames.
	
	.PARAMETER IPString
		An array of IPs as strings.
	
	.EXAMPLE
		PS C:\> Get-HostEntry -IPString $IPArray
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, Position = 1)]
    [string[]]$IPString
)
    Begin {}
    Process {
        ForEach ($IP in $IPString){
            Write-Verbose "Performing lookup on [$IP]..."
            New-Object -TypeName PSObject -Property @{
                'HostName' = (Resolve-DnsName -Name $IP -NoHostsFile).NameHost
                'IPAddress' = $IP
            }            
        }
    }
    End {}
}