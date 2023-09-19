<#
 .DESCRIPTION
    Setup Domain Controller
 .NOTES
    AUTHOR Jonas Henriksson
 .LINK
    https://github.com/J0N7E
#>

[cmdletbinding(SupportsShouldProcess=$true)]

Param
(
    # VM name
    [String]$VMName,
    # Computer name
    [String]$ComputerName,
    # Force
    [Switch]$Force,

    # Serializable parameters
    $Session,
    $Credential,

    # Type of DC
    #[Parameter(Mandatory=$true)]
    [ValidateSet('ADDSForest')]
    [String]$DCType = 'ADDSForest',

    # Name of domain to setup
    [Parameter(Mandatory=$true)]
    [String]$DomainName,

    # Netbios name of domain to setup
    [Parameter(Mandatory=$true)]
    [String]$DomainNetbiosName,

    # Network Id
    [Parameter(Mandatory=$true)]
    [String]$DomainNetworkId,

    # Local admin password on domain controller
    [Parameter(Mandatory=$true)]
    $DomainLocalPassword,

    # DNS
    [String]$DNSReverseLookupZone,
    [TimeSpan]$DNSRefreshInterval,
    [TimeSpan]$DNSNoRefreshInterval,
    [TimeSpan]$DNSScavengingInterval,
    [Bool]$DNSScavengingState,

    # DHCP
    [String]$DHCPScope,
    [String]$DHCPScopeStartRange,
    [String]$DHCPScopeEndRange,
    [String]$DHCPScopeSubnetMask,
    [String]$DHCPScopeDefaultGateway,
    [Array]$DHCPScopeDNSServer,
    [String]$DHCPScopeLeaseDuration,

    # Path to gpos
    [String]$BaselinePath,
    [String]$GPOPath,
    [String]$TemplatePath,

    # Switches
    [ValidateSet($true, $false, $null)]
    [Object]$RestrictDomain,
    [ValidateSet($true, $false, $null)]
    [Object]$EnableIPSec,

    [Switch]$BackupGpo,
    [Switch]$BackupTemplates,
    [Switch]$RemoveAuthenticatedUsersFromUserGpos
)

Begin
{
    # ██████╗ ███████╗ ██████╗ ██╗███╗   ██╗
    # ██╔══██╗██╔════╝██╔════╝ ██║████╗  ██║
    # ██████╔╝█████╗  ██║  ███╗██║██╔██╗ ██║
    # ██╔══██╗██╔══╝  ██║   ██║██║██║╚██╗██║
    # ██████╔╝███████╗╚██████╔╝██║██║ ╚████║
    # ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝

    ##############
    # Deserialize
    ##############

    $Serializable =
    @(
        @{ Name = 'Session';                                      },
        @{ Name = 'Credential';             Type = [PSCredential] },
        @{ Name = 'DomainLocalPassword';    Type = [SecureString] },
        @{ Name = 'DHCPScopeDNSServer';     Type = [Array]        }
    )

    #########
    # Invoke
    #########

    Invoke-Command -ScriptBlock `
    {
        try
        {
            . $PSScriptRoot\s_Begin.ps1
            . $PSScriptRoot\f_CheckContinue.ps1
            . $PSScriptRoot\f_ShouldProcess.ps1
        }
        catch [Exception]
        {
            throw "$_ $( $_.ScriptStackTrace)"
        }

    } -NoNewScope

    #################
    # Define presets
    #################

    $Preset =
    @{
        ADDSForest =
        @{
            # DNS
            DNSReverseLookupZone = (($DomainNetworkId -split '\.')[-1..-3] -join '.') + '.in-addr.arpa'
            DNSRefreshInterval = '7.00:00:00'
            DNSNoRefreshInterval = '7.00:00:00'
            DNSScavengingInterval = '0.01:00:00'
            DNSScavengingState = $true

            # DHCP
            DHCPScope = "$DomainNetworkId.0"
            DHCPScopeStartRange = "$DomainNetworkId.50"
            DHCPScopeEndRange = "$DomainNetworkId.254"
            DHCPScopeSubnetMask = '255.255.255.0'
            DHCPScopeDefaultGateway = "$DomainNetworkId.1"
            DHCPScopeDNSServer = @("$DomainNetworkId.10")
            DHCPScopeLeaseDuration = '14.00:00:00'
        }
    }

    # Set preset values for missing parameters
    foreach ($Var in $MyInvocation.MyCommand.Parameters.Keys)
    {
        if ($Preset.Item($DCType).ContainsKey($Var) -and
            -not (Get-Variable -Name $Var).Value)
        {
            Set-Variable -Name $Var -Value $Preset.Item($DCType).Item($Var)
        }
    }

    #######
    # Copy
    #######

    $Paths = @()

    if ($BaselinePath)
    {
        $Paths += @{ Name = 'MSFT Baselines';         Source = $BaselinePath;  Destination = 'Baseline' }
    }

    if ($GpoPath)
    {
        $Paths += @{ Name = 'Group Policy Objects';   Source = $GpoPath;       Destination = 'Gpo' }
    }

    if ($TemplatePath)
    {
        $Paths += @{ Name = 'Certificate Templates';  Source = $TemplatePath;  Destination = 'Templates' }
    }

    if ($Paths.Count -ne 0)
    {
        # Initialize
        $SessionSplat = @{}
        $ToSessionSplat = @{}

        # Check session
        if ($Session -and $Session.State -eq 'Opened')
        {
            # Set session splats
            $SessionSplat.Add('Session', $Session)
            $ToSessionSplat.Add('ToSession', $Session)
        }

        $DCTemp = Invoke-Command @SessionSplat -ScriptBlock {

            if ($Host.Name -eq 'ServerRemoteHost')
            {
                $UsingPaths = $Using:Paths
            }
            else
            {
                $UsingPaths = $Paths
            }

            foreach ($Path in $UsingPaths)
            {
                if ($Path.Source -and (Test-Path -Path "$env:TEMP\$($Path.Destination)"))
                {
                    Remove-Item -Path "$env:TEMP\$($Path.Destination)" -Recurse -Force
                }
            }

            Write-Output -InputObject $env:TEMP
        }

        foreach ($Path in $Paths)
        {
            # Check if source exist
            if ($Path.Source -and (Test-Path -Path $Path.Source) -and
                (ShouldProcess @WhatIfSplat -Message "Copying `"$($Path.Name)`" to `"$DCTemp\$($Path.Destination)`"." @VerboseSplat))
            {
                Copy-Item @ToSessionSplat -Path $Path.Source -Destination "$DCTemp\$($Path.Destination)" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # ███╗   ███╗ █████╗ ██╗███╗   ██╗
    # ████╗ ████║██╔══██╗██║████╗  ██║
    # ██╔████╔██║███████║██║██╔██╗ ██║
    # ██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    # ██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    # ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

    $MainScriptBlock =
    {
        # Initialize
        $Result = @()
        $UpdatedObjects = @{}

        # Get base DN
        $BaseDN = Get-BaseDn -DomainName $DomainName

        # Set friendly netbios name
        $DomainPrefix = $DomainNetbiosName.Substring(0, 1).ToUpper() + $DomainNetbiosName.Substring(1)

        ############
        # Fucntions
        ############

        function ConvertTo-CanonicalName
        {
            param
            (
                [Parameter(Mandatory=$true)]
                [ValidateNotNullOrEmpty()]
                [string]$DistinguishedName
            )

            $CN = [string]::Empty
            $DC = [string]::Empty

            foreach ($item in ($DistinguishedName.split(',')))
            {
                if ($item -match 'DC=')
                {
                    $DC += $item.Replace('DC=', '') + '.'
                }
                else
                {
                    $CN = '/' + $item.Substring(3) + $CN
                }
            }

            Write-Output -InputObject ($DC.Trim('.') + $CN)
        }

        # ██╗    ██╗██╗███╗   ██╗██╗   ██╗███████╗██████╗
        # ██║    ██║██║████╗  ██║██║   ██║██╔════╝██╔══██╗
        # ██║ █╗ ██║██║██╔██╗ ██║██║   ██║█████╗  ██████╔╝
        # ██║███╗██║██║██║╚██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
        # ╚███╔███╔╝██║██║ ╚████║ ╚████╔╝ ███████╗██║  ██║
        #  ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

        $WinBuilds =
        [ordered]@{
           # Build
            '20348' = # Windows Server 2022
            @{
                Version = '21H2'
                Server = 'Windows Server 2022 21H2'
                Baseline =
                @(
                    'MSFT Windows Server 2022 - Domain Security'
                    'MSFT Windows Server 2022 - Defender Antivirus'
                    'MSFT Internet Explorer 11 21H2 (Windows Server 2022) - Computer-'
                )
                UserBaseline =
                @(
                    'MSFT Internet Explorer 11 21H2 (Windows Server 2022) - User-'
                )
                ServerBaseline =
                @(
                    'MSFT Windows Server 2022 - Member Server'
                )
                DCBaseline =
                @(
                    'MSFT Windows Server 2022 - Domain Controller'
                )
            }
            '22000' = # Windows 11
            @{
                Version = '21H2'
                Workstation = 'Windows 11 21H2'
                Baseline =
                @(
                    'MSFT Windows 11 - Domain Security'
                    'MSFT Windows 11 - Defender Antivirus'
                    'MSFT Internet Explorer 11 21H2 - Computer-'
                )
                UserBaseline =
                @(
                    'MSFT Internet Explorer 11 21H2 - User-'
                    'MSFT Windows 11 - User'
                )
                ComputerBaseline =
                @(
                    'MSFT Windows 11 - Computer'
                )
            }
            '22621' = # Windows 11
            @{
                Version = '22H2'
                Workstation = 'Windows 11 22H2'

                # FIX
                # Add baselines
            }
        }

        # ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗
        # ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║
        # ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║
        # ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║
        # ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
        # ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

        # FIX Pswd length 10+
        # Fix Protect OU Domain Controllers

        # Check if DHCP windows feature is installed
        if (((Get-WindowsFeature -Name DHCP).InstallState -notmatch 'Install') -and
            (ShouldProcess @WhatIfSplat -Message "Installing DHCP Windows feature." @VerboseSplat))
        {
            Install-WindowsFeature -Name DHCP -IncludeManagementTools > $null
        }

        # Check if ADDS feature is installed
        if (((Get-WindowsFeature -Name AD-Domain-Services).InstallState -notmatch 'Install') -and
            (ShouldProcess @WhatIfSplat -Message "Installing AD-Domain-Services feature." @VerboseSplat))
        {
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools > $null
        }

        # Check if ADDS is installed
        if (-not (Test-Path -Path "$env:SystemRoot\SYSVOL" -ErrorAction SilentlyContinue) -and
           (ShouldProcess @WhatIfSplat -Message "Installing ADDS forest." @VerboseSplat))
        {
            Install-ADDSForest -DomainName $DomainName `
                               -DomainNetbiosName $DomainNetbiosName `
                               -SafeModeAdministratorPassword $DomainLocalPassword `
                               -NoRebootOnCompletion `
                               -Force > $null

            # Set result
            Write-Output -InputObject @{ WaitingForReboot = $true }

            # Restart message
            ShouldProcess @WhatIfSplat -Message "Rebooting $ENV:ComputerName, rerun this script to continue setup..." -WriteWarning > $null

            # Restart
            Restart-Computer -Force

            return
        }
        else
        {
            # ██████╗ ███╗   ██╗███████╗
            # ██╔══██╗████╗  ██║██╔════╝
            # ██║  ██║██╔██╗ ██║███████╗
            # ██║  ██║██║╚██╗██║╚════██║
            # ██████╔╝██║ ╚████║███████║
            # ╚═════╝ ╚═╝  ╚═══╝╚══════╝

            # Check if DNS server is installed and running
            if ((Get-Service -Name DNS -ErrorAction SilentlyContinue) -and (Get-Service -Name DNS).Status -eq 'Running')
            {
                #########
                # Server
                #########

                # Checking DNS server scavenging state
                if (((Get-DnsServerScavenging).ScavengingState -ne $DNSScavengingState) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DNS server scavenging state to $DNSScavengingState." @VerboseSplat))
                {
                    Set-DnsServerScavenging -ScavengingState $DNSScavengingState -ApplyOnAllZones
                }

                # Checking DNS server refresh interval
                if (((Get-DnsServerScavenging).RefreshInterval -ne $DNSRefreshInterval) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DNS server refresh interval to $DNSRefreshInterval." @VerboseSplat))
                {
                    Set-DnsServerScavenging -RefreshInterval $DNSRefreshInterval -ApplyOnAllZones
                }

                # Checking DNS server no refresh interval
                if (((Get-DnsServerScavenging).NoRefreshInterval -ne $DNSNoRefreshInterval) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DNS server no refresh interval to $DNSNoRefreshInterval." @VerboseSplat))
                {
                    Set-DnsServerScavenging -NoRefreshInterval $DNSNoRefreshInterval -ApplyOnAllZones
                }

                # Checking DNS server scavenging interval
                if (((Get-DnsServerScavenging).ScavengingInterval -ne $DNSScavengingInterval) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DNS server scavenging interval to $DNSScavengingInterval." @VerboseSplat))
                {
                    Set-DnsServerScavenging -ScavengingInterval $DNSScavengingInterval -ApplyOnAllZones
                }

                ##########
                # Reverse
                ##########

                # Checking reverse lookup zone
                if (-not (Get-DnsServerZone -Name $DNSReverseLookupZone -ErrorAction SilentlyContinue) -and
                   (ShouldProcess @WhatIfSplat -Message "Adding DNS server reverse lookup zone `"$DNSReverseLookupZone`"." @VerboseSplat))
                {
                    Add-DnsServerPrimaryZone -Name $DNSReverseLookupZone -ReplicationScope Domain -DynamicUpdate Secure
                }

                ######
                # CAA
                ######

                # FIX
                # Check if "\# Length" is needed
                # Array of allowed CAs
                # Replace = Clone and add : https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverresourcerecord?view=win10-ps

                # Get CAA record
                $CAA = Get-DnsServerResourceRecord -ZoneName $DomainName -Name $DomainName -Type 257

                # RData with flag = 0, tag length = 5, tag = issue and value = $DomainName
                # See https://tools.ietf.org/html/rfc6844#section-5
                $RData = "00056973737565$($DomainName.ToCharArray().ToInt32($null).ForEach({ '{0:X}' -f $_ }) -join '')"

                # Checking CAA record
                if ((-not $CAA -or $CAA.RecordData.Data -ne $RData) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting `"$RData`" to CAA record." @VerboseSplat))
                {
                    Add-DnsServerResourceRecord -ZoneName $DomainName -Name $DomainName -Type 257 -RecordData $RData
                }

                ##########
                # Records
                ##########

                # Initialize
                $DnsRecords =
                @(
                    @{ Name = 'pki';                     Type = 'A';      Data = "$DomainNetworkId.50" }
                    @{ Name = 'adfs';                    Type = 'A';      Data = "$DomainNetworkId.100" }
                    @{ Name = 'certauth.adfs';           Type = 'A';      Data = "$DomainNetworkId.100" }
                    @{ Name = 'enterpriseregistration';  Type = 'A';      Data = "$DomainNetworkId.100" }
                    @{ Name = 'wap';                     Type = 'A';      Data = "$DomainNetworkId.250" }
                )

                foreach($Rec in $DnsRecords)
                {
                    switch($Rec.Type)
                    {
                        'A'
                        {
                            $RecordType = @{ A = $true; IPv4Address = $Rec.Data; }
                        }
                        'CNAME'
                        {
                            $RecordType = @{ CName = $true; HostNameAlias = $Rec.Data; }
                        }
                    }

                    if (-not (Get-DnsServerResourceRecord -ZoneName $DomainName -Name $Rec.Name -RRType $Rec.Type -ErrorAction SilentlyContinue) -and
                        (ShouldProcess @WhatIfSplat -Message "Adding $($Rec.Type) `"$($Rec.Name)`" -> `"$($Rec.Data)`"." @VerboseSplat))
                    {
                        Add-DnsServerResourceRecord -ZoneName $DomainName @RecordType -Name $Rec.Name
                    }
                }
            }

            # ██████╗ ██╗  ██╗ ██████╗██████╗
            # ██╔══██╗██║  ██║██╔════╝██╔══██╗
            # ██║  ██║███████║██║     ██████╔╝
            # ██║  ██║██╔══██║██║     ██╔═══╝
            # ██████╔╝██║  ██║╚██████╗██║
            # ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝

            # Check if DHCP server is installed and running
            if ((Get-Service -Name DHCPServer).Status -eq 'Running')
            {
                # Authorize DHCP server
                if ((Get-DhcpServerSetting).IsAuthorized -eq $false -and
                    (ShouldProcess @WhatIfSplat -Message "Authorizing DHCP server." @VerboseSplat))
                {
                    Add-DhcpServerInDC -DnsName "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
                }

                # Set conflict detection attempts
                if ((Get-DhcpServerSetting).ConflictDetectionAttempts -ne 1 -and
                    (ShouldProcess @WhatIfSplat -Message "Setting DHCP server conflict detection attempts to 1." @VerboseSplat))
                {
                    Set-DhcpServerSetting -ConflictDetectionAttempts 1
                }

                # Dynamically update DNS
                if ((Get-DhcpServerv4DnsSetting).DynamicUpdates -ne 'Always' -and
                    (ShouldProcess @WhatIfSplat -Message "Enable DHCP always dynamically update DNS records." @VerboseSplat))
                {
                    Set-DhcpServerv4DnsSetting -DynamicUpdates Always
                }

                # Dynamically update DNS for older clients
                if ((Get-DhcpServerv4DnsSetting).UpdateDnsRRForOlderClients -ne $true -and
                    (ShouldProcess @WhatIfSplat -Message "Enable DHCP dynamically update DNS records for older clients." @VerboseSplat))
                {
                    Set-DhcpServerv4DnsSetting -UpdateDnsRRForOlderClients $true
                }

                # Scope
                if (-not (Get-DhcpServerv4Scope -ScopeId $DHCPScope -ErrorAction SilentlyContinue) -and
                    (ShouldProcess @WhatIfSplat -Message "Adding DHCP scope $DHCPScope ($DHCPScopeStartRange-$DHCPScopeEndRange/$DHCPScopeSubnetMask) with duration $DHCPScopeLeaseDuration" @VerboseSplat))
                {
                    Add-DhcpServerv4Scope -Name $DHCPScope -StartRange $DHCPScopeStartRange -EndRange $DHCPScopeEndRange -SubnetMask $DHCPScopeSubnetMask -LeaseDuration $DHCPScopeLeaseDuration
                }

                # Range
                if (((((Get-DhcpServerv4Scope).StartRange -ne $DHCPScopeStartRange) -or
                       (Get-DhcpServerv4Scope).EndRange -ne $DHCPScopeEndRange)) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DHCP scope range $DHCPScopeStartRange-$DHCPScopeEndRange" @VerboseSplat))
                {
                    Set-DhcpServerv4Scope -ScopeID $DHCPScope -StartRange $DHCPScopeStartRange -EndRange $DHCPScopeEndRange
                }

                # SubnetMask
                if (((Get-DhcpServerv4Scope).SubnetMask -ne $DHCPScopeSubnetMask) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DHCP scope subnet mask to $DHCPScopeSubnetMask" @VerboseSplat))
                {
                    Set-DhcpServerv4Scope -ScopeID $DHCPScope -SubnetMask $DHCPScopeSubnetMask
                }

                # Lease duration
                if (((Get-DhcpServerv4Scope).LeaseDuration -ne $DHCPScopeLeaseDuration) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DHCP scope lease duration to $DHCPScopeLeaseDuration" @VerboseSplat))
                {
                    Set-DhcpServerv4Scope -ScopeID $DHCPScope -LeaseDuration $DHCPScopeLeaseDuration
                }

                # DNS domain
                if (-not (Get-DhcpServerv4OptionValue -ScopeId $DHCPScope -OptionId 15 -ErrorAction SilentlyContinue) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DHCP scope DNS Domain to $env:USERDNSDOMAIN" @VerboseSplat))
                {
                    Set-DhcpServerv4OptionValue -ScopeID $DHCPScope -DNSDomain $env:USERDNSDOMAIN
                }

                # DNS server
                if ((-not (Get-DhcpServerv4OptionValue -ScopeId $DHCPScope -OptionId 6 -ErrorAction SilentlyContinue) -or
                    @(Compare-Object -ReferenceObject $DHCPScopeDNSServer -DifferenceObject (Get-DhcpServerv4OptionValue -ScopeId $DHCPScope -OptionId 6).Value -SyncWindow 0).Length -ne 0) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DHCP scope DNS to $DHCPScopeDNSServer" @VerboseSplat))
                {
                    Set-DhcpServerv4OptionValue -ScopeID $DHCPScope -DNSServer $DHCPScopeDNSServer
                }

                # Gateway
                if (-not (Get-DhcpServerv4OptionValue -ScopeId $DHCPScope -OptionId 3 -ErrorAction SilentlyContinue) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DHCP scope router to $DHCPScopeDefaultGateway" @VerboseSplat))
                {
                    Set-DhcpServerv4OptionValue -ScopeID $DHCPScope -Router $DHCPScopeDefaultGateway
                }

                # Disable netbios
                if (-not (Get-DhcpServerv4OptionValue -ScopeId $DHCPScope -OptionId 1 -VendorClass 'Microsoft Windows 2000 Options' -ErrorAction SilentlyContinue) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting DHCP scope option to disable netbios." @VerboseSplat))
                {
                    Set-DhcpServerv4OptionValue -ScopeId $DHCPScope -VendorClass 'Microsoft Windows 2000 Options' -OptionId 1 -Value 2
                }

                ###############
                # Reservations
                ###############

                $DhcpReservations =
                @(
                    @{ Host = 'AS01';    Name = "AS01.$DomainName";    IPAddress = "$DomainNetworkId.50"; }
                    @{ Host = 'ADFS01';  Name = "ADFS01.$DomainName";  IPAddress = "$DomainNetworkId.100"; }
                    @{ Host = 'WAP01';   Name = "WAP01.$DomainName";   IPAddress = "$DomainNetworkId.250"; }
                )

                foreach($Reservation in $DhcpReservations)
                {
                    # Get clientId from dhcp active leases
                    $ClientId = (Get-DhcpServerv4Lease -ScopeID $DHCPScope | Where-Object { $_.HostName -match $Reservation.Host -and $_.AddressState -eq 'Active' } | Sort-Object -Property LeaseExpiryTime | Select-Object -Last 1).ClientId

                    # Check if client id exist
                    if ($ClientId)
                    {
                        $CurrentReservation = Get-DhcpServerv4Reservation -ScopeId $DHCPScope | Where-Object { $_.Name -eq $Reservation.Name -and $_.IPAddress -eq $Reservation.IPAddress }

                        if ($CurrentReservation)
                        {
                            if ($CurrentReservation.ClientId -ne $ClientId -and
                               (ShouldProcess @WhatIfSplat -Message "Updating DHCP reservation `"$($Reservation.Name)`" -> $($Reservation.IPAddress) ($ClientID)." @VerboseSplat))
                            {
                                Set-DhcpServerv4Reservation -Name $Reservation.Name -IPAddress $Reservation.IPAddress -ClientId $ClientID

                                $UpdatedObjects.Add($Reservation.Host, $true)
                            }
                        }
                        elseif (ShouldProcess @WhatIfSplat -Message "Adding DHCP reservation `"$($Reservation.Name)`" -> $($Reservation.IPAddress) ($ClientId)." @VerboseSplat)
                        {
                            Add-DhcpServerv4Reservation -ScopeId $DHCPScope -Name $Reservation.Name -IPAddress $Reservation.IPAddress -ClientId $ClientID

                            $UpdatedObjects.Add($Reservation.Host, $true)
                        }
                    }
                }
            }

            #  ██████╗ ██╗   ██╗
            # ██╔═══██╗██║   ██║
            # ██║   ██║██║   ██║
            # ██║   ██║██║   ██║
            # ╚██████╔╝╚██████╔╝
            #  ╚═════╝  ╚═════╝

            $RedirUsr = 'Redirect Users'
            $RedirCmp = 'Redirect Computers'

            $OrganizationalUnits =
            @(
                @{ Name = $DomainName;                                                            Path = "$BaseDN"; }
                @{ Name = $RedirUsr;                                               Path = "OU=$DomainName,$BaseDN"; }
                @{ Name = $RedirCmp;                                               Path = "OU=$DomainName,$BaseDN"; }
            )

            ###########
            # Tier 0-2
            ###########

            foreach($Tier in @(0,1,2))
            {
                $OrganizationalUnits += @{ Name = "Tier $Tier";                                            Path = "OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{  Name = 'Administrators';                         Path = "OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{  Name = 'Groups';                                 Path = "OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{   Name = 'Access Control';              Path = "OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{   Name = 'Computers';                   Path = "OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{   Name = 'Local Administrators';        Path = "OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{   Name = 'Remote Desktop Access';       Path = "OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{   Name = 'Security Roles';              Path = "OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{  Name = 'Users';                                  Path = "OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
                $OrganizationalUnits += @{  Name = 'Computers';                              Path = "OU=Tier $Tier,OU=$DomainName,$BaseDN"; }
            }

            #########
            # Tier 0
            #########

            $OrganizationalUnits += @{ Name = 'Certificate Authority Templates';   Path = "OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"; }
            $OrganizationalUnits += @{ Name = 'Group Managed Service Accounts';    Path = "OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"; }
            $OrganizationalUnits += @{ Name = 'Service Accounts';                            Path = "OU=Tier 0,OU=$DomainName,$BaseDN"; }

            # Server builds
            foreach ($Build in $WinBuilds.GetEnumerator())
            {
                if ($Build.Value.Server)
                {
                    $ServerName = $Build.Value.Server

                    $OrganizationalUnits += @{ Name = $ServerName;                                Path = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Certificate Authorities';   Path = "OU=$ServerName,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Network Policy Server';     Path = "OU=$ServerName,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Federation Services';       Path = "OU=$ServerName,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Web Servers';               Path = "OU=$ServerName,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                }
            }

            #########
            # Tier 1
            #########

            $OrganizationalUnits += @{ Name = 'Group Managed Service Accounts';    Path = "OU=Groups,OU=Tier 1,OU=$DomainName,$BaseDN"; }
            $OrganizationalUnits += @{ Name = 'Service Accounts';                            Path = "OU=Tier 1,OU=$DomainName,$BaseDN"; }

            # Server builds
            foreach ($Build in $WinBuilds.GetEnumerator())
            {
                if ($Build.Value.Server)
                {
                    $ServerName = $Build.Value.Server

                    $OrganizationalUnits += @{ Name = $ServerName;                                Path = "OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Application Servers';       Path = "OU=$ServerName,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Web Application Proxy';     Path = "OU=$ServerName,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Remote Access Servers';     Path = "OU=$ServerName,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Web Servers';               Path = "OU=$ServerName,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"; }
                }
            }

            #########
            # Tier 2
            #########

            # Workstation builds
            foreach ($Build in $WinBuilds.GetEnumerator())
            {
                if ($Build.Value.Workstation)
                {
                    $OrganizationalUnits += @{ Name = $Build.Value.Workstation;    Path = "OU=Computers,OU=Tier 2,OU=$DomainName,$BaseDN"; }
                }
            }

            # Build ou
            foreach($Ou in $OrganizationalUnits)
            {
                # Check if OU exist
                if (-not (Get-ADOrganizationalUnit -SearchBase $Ou.Path -Filter "Name -like '$($Ou.Name)'" -SearchScope OneLevel -ErrorAction SilentlyContinue) -and
                    (ShouldProcess @WhatIfSplat -Message "Creating OU=$($Ou.Name)" @VerboseSplat))
                {
                    # Create OU
                    New-ADOrganizationalUnit -Name $Ou.Name -Path $Ou.Path

                    if ($Ou.Path -eq "OU=$DomainName,$BaseDN")
                    {
                        if ($Ou.Name -eq $RedirCmp)
                        {
                            ShouldProcess @WhatIfSplat -Message "Redirecting Computers to OU=$($Ou.Name),$($Ou.Path)" @VerboseSplat > $null
                            redircmp "OU=$($Ou.Name),$($Ou.Path)" > $null
                        }

                        if ($Ou.Name -eq $RedirUsr)
                        {
                            ShouldProcess @WhatIfSplat -Message "Redirecting Users to OU=$($Ou.Name),$($Ou.Path)" @VerboseSplat > $null
                            redirusr "OU=$($Ou.Name),$($Ou.Path)" > $null
                        }
                    }
                }
            }

            # ██╗   ██╗███████╗███████╗██████╗ ███████╗
            # ██║   ██║██╔════╝██╔════╝██╔══██╗██╔════╝
            # ██║   ██║███████╗█████╗  ██████╔╝███████╗
            # ██║   ██║╚════██║██╔══╝  ██╔══██╗╚════██║
            # ╚██████╔╝███████║███████╗██║  ██║███████║
            #  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝

            $Users =
            @(
                # Domain administrator
                @{
                    Name = 'Admin'
                    Description = 'Account for administering domain controllers/domain'
                    Password = 'P455w0rd'
                    NeverExpires = $true
                    AccountNotDelegated = $true
                    MemberOf = @('Domain Admins', 'Protected Users')
                }

                # Administrators
                @{
                    Name = 'Tier0Admin'
                    Password = 'P455w0rd'
                    NeverExpires = $true
                    AccountNotDelegated = $true
                    MemberOf = @()
                }
                @{
                    Name = 'Tier1Admin'
                    Password = 'P455w0rd'
                    NeverExpires = $true
                    AccountNotDelegated = $true
                    MemberOf = @()
                }
                @{
                    Name = 'Tier2Admin'
                    Password = 'P455w0rd'
                    NeverExpires = $true
                    AccountNotDelegated = $true
                    MemberOf = @()
                }

                # Service accounts
                <#
                @{
                    Name = 'AzADDSConnector'
                    Password = 'PHptNlPKHxL0K355QsXIJulLDqjAhmfABbsWZoHqc0nnOd6p'
                    NeverExpires = $true
                    AccountNotDelegated = $false
                    MemberOf = @()
                }
                #>

                # Join domain account
                @{
                    Name = 'JoinDomain'
                    Password = 'P455w0rd'
                    NeverExpires = $true
                    AccountNotDelegated = $true
                    MemberOf = @()
                }

                # Users
                @{
                    Name = 'Alice'
                    Password = 'P455w0rd'
                    NeverExpires = $false
                    AccountNotDelegated = $false
                    MemberOf = @()
                }
                @{
                    Name = 'Bob'
                    Password = 'P455w0rd'
                    NeverExpires = $false
                    AccountNotDelegated = $false
                    MemberOf = @()
                }
                @{
                    Name = 'Eve'
                    Password = 'P455w0rd'
                    NeverExpires = $false
                    AccountNotDelegated = $false
                    MemberOf = @()
                }
            )

            # Setup users
            foreach ($User in $Users)
            {
                if (-not (Get-ADUser -Filter "Name -eq '$($User.Name)'" -SearchBase "$BaseDN" -SearchScope Subtree -ErrorAction SilentlyContinue) -and
                   (ShouldProcess @WhatIfSplat -Message "Creating user `"$($User.Name)`"." @VerboseSplat))
                {
                    if ($User.Description)
                    {
                        $DescriptionSplat = @{ Description = $User.Description }
                    }

                    New-ADUser -Name $User.Name -DisplayName $User.Name @DescriptionSplat -SamAccountName $User.Name -UserPrincipalName "$($User.Name)@$DomainName" -AccountPassword (ConvertTo-SecureString -String $User.Password -AsPlainText -Force) -ChangePasswordAtLogon $false -PasswordNeverExpires $User.NeverExpires -AccountNotDelegated $User.AccountNotDelegated -Enabled $true

                    if ($User.MemberOf)
                    {
                        Add-ADPrincipalGroupMembership -Identity $User.Name -MemberOf $User.MemberOf
                    }
                }
            }

            # ███╗   ███╗ ██████╗ ██╗   ██╗███████╗
            # ████╗ ████║██╔═══██╗██║   ██║██╔════╝
            # ██╔████╔██║██║   ██║██║   ██║█████╗
            # ██║╚██╔╝██║██║   ██║╚██╗ ██╔╝██╔══╝
            # ██║ ╚═╝ ██║╚██████╔╝ ╚████╔╝ ███████╗
            # ╚═╝     ╚═╝ ╚═════╝   ╚═══╝  ╚══════╝

            $MoveObjects =
            @(
                # Domain controllers
                @{
                    Filter = "Name -like 'DC*' -and ObjectCategory -eq 'Computer'"
                    TargetPath = "OU=Domain Controllers,$BaseDN"
                }

                # Domain Admin
                @{
                    Filter = "Name -like 'Admin' -and ObjectCategory -eq 'Person'"
                    TargetPath = "CN=Users,$BaseDN"
                }

                # Join domain account
                @{
                    Filter = "Name -like 'JoinDomain' -and ObjectCategory -eq 'Person'"
                    TargetPath = "CN=Users,$BaseDN"
                }

                #########
                # Tier 0
                #########

                # Admin
                @{
                    Filter = "Name -like 'Tier0Admin' -and ObjectCategory -eq 'Person'"
                    TargetPath = "OU=Administrators,OU=Tier 0,OU=$DomainName,$BaseDN"
                }

                # Computers
                @{
                    Filter = "Name -like 'CA*' -and ObjectCategory -eq 'Computer'"
                    TargetPath = "OU=Certificate Authorities,%ServerPath%,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                }

                @{
                    Filter = "Name -like 'ADFS*' -and ObjectCategory -eq 'Computer'"
                    TargetPath = "OU=Federation Services,%ServerPath%,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                }

                @{
                    Filter = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                    TargetPath = "OU=Web Servers,%ServerPath%,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                }

                @{
                    Filter = "Name -like 'NPS*' -and ObjectCategory -eq 'Computer'"
                    TargetPath = "OU=Network Policy Server,%ServerPath%,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                }

                # Service accounts
                @{
                    Filter = "Name -like 'Az*' -and ObjectCategory -eq 'Person'"
                    TargetPath = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN"
                }

                @{
                    Filter = "Name -like 'Svc*' -and ObjectCategory -eq 'Person'"
                    TargetPath = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN"
                }

                #########
                # Tier 1
                #########

                # Admin
                @{
                    Filter = "Name -like 'Tier1Admin' -and ObjectCategory -eq 'Person'"
                    TargetPath = "OU=Administrators,OU=Tier 1,OU=$DomainName,$BaseDN"
                }

                # Computers
                @{
                    Filter = "Name -like 'WAP*' -and ObjectCategory -eq 'Computer'"
                    TargetPath = "OU=Web Application Proxy,%ServerPath%,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"
                }

                @{
                    Filter = "Name -like 'RAS*' -and ObjectCategory -eq 'Computer'"
                    TargetPath = "OU=Remote Access Servers,%ServerPath%,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"
                }

                #########
                # Tier 2
                #########

                # Admin
                @{
                    Filter = "Name -like 'Tier2Admin' -and ObjectCategory -eq 'Person'"
                    TargetPath = "OU=Administrators,OU=Tier 2,OU=$DomainName,$BaseDN"
                }

                # Computers
                @{
                    Filter = "Name -like 'WIN*' -and ObjectCategory -eq 'Computer'"
                    TargetPath = "%WorkstationPath%,OU=Computers,OU=Tier 2,OU=$DomainName,$BaseDN"
                }

                # Users
                @{
                    Filter = "(Name -eq 'Alice' -or Name -eq 'Bob' -or Name -eq 'Eve') -and ObjectCategory -eq 'Person'"
                    TargetPath = "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN"
                }
            )

            # Move objects
            foreach ($Obj in $MoveObjects)
            {
                # Set targetpath
                $TargetPath = $Obj.TargetPath

                # Get object
                $ADObjects = Get-ADObject -Filter $Obj.Filter -SearchBase "OU=$DomainName,$BaseDN" -SearchScope Subtree -Properties cn

                # Itterate if multiple
                foreach ($CurrentObj in $ADObjects)
                {
                    # Check if computer
                    if ($CurrentObj.ObjectClass -eq 'Computer')
                    {
                        # Get computer build
                        $Build = $CurrentObj | Get-ADComputer -Property OperatingSystemVersion | Select-Object -ExpandProperty OperatingSystemVersion | Where-Object {
                            $_ -match "\((\d+)\)"
                        } | ForEach-Object { $Matches[1] }

                        if (-not $Build)
                        {
                            ShouldProcess @WhatIfSplat -Message "Did'nt find build for $($CurrentObj.Name), skiping move." -WriteWarning > $null
                            continue
                        }

                        # Set targetpath with server version
                        if ($Obj.TargetPath -match '%ServerPath%')
                        {
                            if(-not $WinBuilds.Item($Build).Server)
                            {
                                ShouldProcess @WhatIfSplat -Message "Missing winver server entry for build $Build, skiping move." -WriteWarning > $null
                                continue
                            }

                            $TargetPath = $Obj.TargetPath.Replace('%ServerPath%', "OU=$($WinBuilds.Item($Build).Server)")
                        }

                        # Set targetpath with windows version
                        if ($Obj.TargetPath -match '%WorkstationPath%')
                        {
                            if(-not $WinBuilds.Item($Build).Workstation)
                            {
                                ShouldProcess @WhatIfSplat -Message "Missing winver workstation entry for build $Build, skiping move." -WriteWarning > $null
                                continue
                            }

                            $TargetPath = $Obj.TargetPath.Replace('%WorkstationPath%', "OU=$($WinBuilds.Item($Build).Workstation)")
                        }
                    }

                    # Check if object is in targetpath
                    if ($CurrentObj -and $CurrentObj.DistinguishedName -notlike "*$TargetPath" -and
                       (ShouldProcess @WhatIfSplat -Message "Moving object `"$($CurrentObj.Name)`" to `"$TargetPath`"." @VerboseSplat))
                    {
                        # Move object
                        $CurrentObj | Move-ADObject -TargetPath $TargetPath
                    }
                }
            }

            #  ██████╗ ██████╗  ██████╗ ██╗   ██╗██████╗ ███████╗
            # ██╔════╝ ██╔══██╗██╔═══██╗██║   ██║██╔══██╗██╔════╝
            # ██║  ███╗██████╔╝██║   ██║██║   ██║██████╔╝███████╗
            # ██║   ██║██╔══██╗██║   ██║██║   ██║██╔═══╝ ╚════██║
            # ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║     ███████║
            #  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝

            ##########
            # Kds Key
            ##########

            if (-not (Get-KdsRootKey) -and
                (ShouldProcess @WhatIfSplat -Message "Adding KDS root key." @VerboseSplat))
            {
                # DC computer object must not be moved from OU=Domain Controllers
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) > $null
            }

            ################
            # Global Groups
            ################

            # Initialize
            $DomainGroups = @()

            # Name              : Name & display name
            # Path              : OU location
            # Filter            : Filter to get members
            # SearchBase        : Where to look for members
            # SearchScope       : Base/OneLevel/Subtree to look for members
            # MemberOf          : Member of these groups

            #########
            # Tier 0
            #########

            # Administrators
            foreach($Tier in @(0, 1, 2))
            {
                # Administrators
                $DomainGroups +=
                @{
                    Name                = "Tier $Tier - Admins"
                    Scope               = 'Global'
                    Path                = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like '*' -and ObjectCategory -eq 'Person'"
                            SearchBase  = "OU=Administrators,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                    MemberOf          = @('Protected Users')
                }
            }

            #############
            # Tier 0 + 1
            #############

            # Servers, server by build
            foreach($Tier in @(0, 1))
            {
                $DomainGroups +=
                @{
                    Name                = "Tier $Tier - Computers"
                    Scope               = 'Global'
                    Path                = "OU=Computers,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like '*' -and ObjectCategory -eq 'Computer' -and OperatingSystem -like '*Server*'"
                            SearchBase  = "OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                    )
                }

                # Server by build
                foreach ($Build in $WinBuilds.GetEnumerator())
                {
                    if ($Build.Value.Server)
                    {
                        $DomainGroups +=
                        @{
                            Name                = "Tier $Tier - $($Build.Value.Server)"
                            Scope               = 'Global'
                            Path                = "OU=Computers,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                            Members             =
                            @(
                                @{
                                    Filter      = "Name -like '*' -and ObjectCategory -eq 'Computer' -and OperatingSystem -like '*Server*' -and OperatingSystemVersion -like '*$($Build.Key)*'"
                                    SearchBase  = "OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                                    SearchScope = 'Subtree'
                                }
                            )
                        }
                    }
                }
            }

            #################
            # Tier 0 + 1 + 2
            #################

            # Users
            foreach($Tier in @(0, 1, 2))
            {
                $DomainGroups +=
                @{
                    Name                = "Tier $Tier - Users"
                    Scope               = 'Global'
                    Path                = "OU=Security Roles,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like '*' -and ObjectCategory -eq 'Person'"
                            SearchBase  = "OU=Users,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }
            }

            # Local admins, rdp access
            foreach($Tier in @(0, 1, 2))
            {
                foreach($Computer in (Get-ADObject -Filter "Name -like '*' -and ObjectCategory -eq 'Computer'" -SearchBase "OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN" -SearchScope Subtree ))
                {

                    $DomainGroups +=
                    @{
                        Name              = "Tier $Tier - Local Admin - $($Computer.Name)"
                        Scope             = 'Global'
                        Path              = "OU=Local Administrators,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                        MemberOf          = @('Protected Users')
                    }

                    $DomainGroups +=
                    @{
                        Name                = "Tier $Tier - Rdp Access - $($Computer.Name)"
                        Scope               = 'Global'
                        Path                = "OU=Remote Desktop Access,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                        Members             =
                        @(
                            @{
                                Filter      = "Name -like '*' -and ObjectCategory -eq 'Person'"
                                SearchBase  = "OU=Users,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                                SearchScope = 'OneLevel'
                            }
                        )
                    }
                }
            }

            #########
            # Tier 2
            #########

            # Workstations
            $DomainGroups +=
            @{
                Name                = 'Tier 2 - Computers'
                Scope               = 'Global'
                Path                = "OU=Computers,OU=Groups,OU=Tier 2,OU=$DomainName,$BaseDN"
                Members             =
                @(
                    @{
                        Filter      = "Name -like '*' -and ObjectCategory -eq 'Computer' -and OperatingSystem -notlike '*Server*'"
                        SearchBase  = "OU=Computers,OU=Tier 2,OU=$DomainName,$BaseDN"
                        SearchScope = 'Subtree'
                    }
                )
            }

            # Workstation by build
            foreach ($Build in $WinBuilds.GetEnumerator())
            {
                if ($Build.Value.Workstation)
                {
                    $DomainGroups +=
                    @{
                        Name                = "Tier 2 - $($Build.Value.Workstation)"
                        Scope               = 'Global'
                        Path                = "OU=Computers,OU=Groups,OU=Tier 2,OU=$DomainName,$BaseDN"
                        Members             =
                        @(
                            @{
                                Filter      = "Name -like '*' -and ObjectCategory -eq 'Computer' -and OperatingSystem -notlike '*Server*' -and OperatingSystemVersion -like '*$($Build.Key)*'"
                                SearchBase  = "OU=Computers,OU=Tier 2,OU=$DomainName,$BaseDN"
                                SearchScope = 'Subtree'
                            }
                        )
                    }
                }
            }

            #######
            # GMSA
            #######

            $DomainGroups +=
            @(
                @{
                    Name                = 'Adfs'
                    Scope               = 'Global'
                    Path                = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'ADFS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                        @{
                            Filter      = "Name -like 'Tier0Admin' -and ObjectCategory -eq 'Person'"
                            SearchBase  = "OU=Administrators,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }

                @{
                    Name                = 'Ndes'
                    Scope               = 'Global'
                    Path                = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                    )
                }

                @{
                    Name                = 'CertSrv'
                    Scope               = 'Global'
                    Path                = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                    )
                }

                @{
                    Name                = 'AzADSyncSrv'
                    Scope               = 'Global'
                    Path                = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                    )
                }
            )

            ######################
            # Domain Local Groups
            ######################

            #########
            # Tier 0
            #########

            foreach($Tier in @(0, 1, 2))
            {
                #########
                # Admins
                #########

                $DomainGroups +=
                @(
                    @{
                        Name                = "Delegate Tier $Tier Admin Rights"
                        Scope               = 'DomainLocal'
                        Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                        Members             =
                        @(
                            @{
                                Filter      = "Name -eq 'Tier $Tier - Admins' -and ObjectCategory -eq 'group'"
                                SearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                                SearchScope = 'OneLevel'
                            }
                        )
                    }
                )

                #######
                # Laps
                #######

                $DomainGroups +=
                @(
                    @{
                        Name                = "Delegate Tier $Tier Laps Read Password"
                        Scope               = 'DomainLocal'
                        Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                        Members             =
                        @(
                            @{
                                Filter      = "Name -eq 'Tier $Tier - Admins' -and ObjectCategory -eq 'group'"
                                SearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                                SearchScope = 'OneLevel'
                            }
                        )
                    }

                    @{
                        Name                = "Delegate Tier $Tier Laps Reset Password"
                        Scope               = 'DomainLocal'
                        Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                        Members             =
                        @(
                            @{
                                Filter      = "Name -eq 'Tier $Tier - Admins' -and ObjectCategory -eq 'group'"
                                SearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                                SearchScope = 'OneLevel'
                            }
                        )
                    }
                )
            }

            ##############
            # Join domain
            ##############

            $DomainGroups +=
            @(
                @{
                    Name                = 'Delegate Create Child Computer'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'JoinDomain' -and ObjectCategory -eq 'Person'"
                            SearchBase  = "CN=Users,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }
            )

            ######
            # Pki
            ######

            $DomainGroups +=
            @(
                @{
                    Name                = 'Delegate Install Certificate Authority'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'Tier 0 - Admins' -and ObjectCategory -eq 'Group'"
                            SearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }
            )

            #######
            # Adfs
            #######

            $DomainGroups +=
            @(
                @{
                    Name                = 'Delegate Adfs Container Generic Read'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'Tier 0 - Admins' -and ObjectCategory -eq 'Group'"
                            SearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }

                @{
                    Name                = 'Delegate Adfs Dkm Container Permissions'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'ADFS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                        @{
                            Filter      = "Name -eq 'Tier 0 - Admins' -and ObjectCategory -eq 'Group'"
                            SearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }
            )

            #########
            # Adsync
            #########

            $DomainGroups +=
            @(
                @{
                    Name                = 'Delegate AdSync Basic Read Permissions'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'AzADDSConnector' -and ObjectCategory -eq 'Person'"
                            SearchBase  = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }

                @{
                    Name                = 'Delegate AdSync Password Hash Sync Permissions'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'AzADDSConnector' -and ObjectCategory -eq 'Person'"
                            SearchBase  = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }

                @{
                    Name                = 'Delegate AdSync msDS Consistency Guid Permissions'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'AzADDSConnector' -and ObjectCategory -eq 'Person'"
                            SearchBase  = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }
            )

            ###############
            # CA Templates
            ###############

            $DomainGroups +=
            @(
                @{
                    Name                = 'Template ADFS Service Communication'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'ADFS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                    )
                }

                @{
                    Name                = 'Template CEP Encryption'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                    )
                }

                @{
                    Name                = 'Template NDES'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'MsaNdes' -and ObjectClass -eq 'msDS-GroupManagedServiceAccount'"
                            SearchBase  = "CN=Managed Service Accounts,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }

                @{
                    Name                = 'Template OCSP Response Signing'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                    )
                }

                @{
                    Name                = 'Template SSL'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                            SearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'Subtree'
                        }
                    )
                }

                @{
                    Name                = 'Template WHFB Enrollment Agent'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'MsaAdfs' -and ObjectClass -eq 'msDS-GroupManagedServiceAccount'"
                            SearchBase  = "CN=Managed Service Accounts,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }

                @{
                    Name                = 'Template WHFB Authentication'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'MsaAdfs' -and ObjectClass -eq 'msDS-GroupManagedServiceAccount'"
                            SearchBase  = "CN=Managed Service Accounts,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }

                @{
                    Name                = 'Template WHFB Authentication'
                    Scope               = 'DomainLocal'
                    Path                = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -eq 'Domain Users' -and ObjectCategory -eq 'Group'"
                            SearchBase  = "CN=Users,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }
            )

            ###############
            # Build groups
            ###############

            foreach($Group in $DomainGroups)
            {
                # Check if group managed service account
                $IsGmsa = ($Group.Path -match 'Group Managed Service Accounts')

                if ($IsGmsa)
                {
                    $GroupName = "Gmsa $($Group.Name)"
                }
                else
                {
                    $GroupName = $Group.Name
                }

                # Get group
                $ADGroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -Properties Member

                # Check if group exist
                if (-not $ADGroup -and
                    (ShouldProcess @WhatIfSplat -Message "Creating `"$GroupName`" group." @VerboseSplat))
                {
                    $ADGroup = New-ADGroup -Name $GroupName -DisplayName $GroupName -Path $Group.Path -GroupScope $Group.Scope -GroupCategory Security -PassThru
                }

                if ($ADGroup)
                {
                    # Gmsa
                    if ($IsGmsa)
                    {
                        $Msa = Get-ADServiceAccount -Filter "Name -eq 'Msa$($Group.Name)'" -Properties PrincipalsAllowedToRetrieveManagedPassword

                        # Check if service account exist
                        if (-not $Msa -and
                            (ShouldProcess @WhatIfSplat -Message "Creating managed service account `"Msa$($Group.Name)`$`"." @VerboseSplat))
                        {
                            $Msa = New-ADServiceAccount -Name "Msa$($Group.Name)" -SamAccountName "Msa$($Group.Name)" -DNSHostName "Msa$($Group.Name).$DomainName" -PrincipalsAllowedToRetrieveManagedPassword "$($ADGroup.DistinguishedName)" -KerberosEncryptionType AES128, AES256
                        }

                        if($Msa -and $ADGroup.DistinguishedName -notin $Msa.PrincipalsAllowedToRetrieveManagedPassword -and
                           (ShouldProcess @WhatIfSplat -Message "Allow `"$GroupName`" to retrieve `"Msa$($Group.Name)`" password. " @VerboseSplat))
                        {
                            Set-ADServiceAccount -Identity $Msa.DistinguishedName -PrincipalsAllowedToRetrieveManagedPassword @($Msa.PrincipalsAllowedToRetrieveManagedPassword + $ADGroup.DistinguishedName)
                        }
                    }

                    # Check if group should be member of other groups
                    if ($Group.MemberOf)
                    {
                        # Itterate other groups
                        foreach($OtherName in $Group.MemberOf)
                        {
                            # Get other group
                            $OtherGroup = Get-ADGroup -Filter "Name -eq '$OtherName'" -Properties Member

                            # Check if member of other group
                            if (($OtherGroup -and -not $OtherGroup.Member.Where({ $_ -match $ADGroup.Name })) -and
                                (ShouldProcess @WhatIfSplat -Message "Adding `"$($ADGroup.Name)`" to `"$OtherName`"." @VerboseSplat))
                            {
                                # Add group to other group
                                Add-ADPrincipalGroupMembership -Identity $ADGroup.Name -MemberOf @("$OtherName")
                            }
                        }
                    }

                    # Check if group should have members
                    if ($Group.Members)
                    {
                        foreach ($Members in $Group.Members)
                        {
                            # Check if filter exist
                            if ($Members.Filter)
                            {
                                $GetObjectSplat = @{ 'Filter' = $Members.Filter }

                                if ($Members.SearchScope)
                                {
                                    $GetObjectSplat.Add('SearchScope', $Members.SearchScope)
                                }

                                if ($Members.SearchBase)
                                {
                                    $GetObjectSplat.Add('SearchBase', $Members.SearchBase)
                                }

                                # Get members
                                foreach($NewMember in (Get-ADObject @GetObjectSplat))
                                {
                                    # Check if member is part of group
                                    if ((-not $ADGroup.Member.Where({ $_ -match $NewMember.Name })) -and
                                        (ShouldProcess @WhatIfSplat -Message "Adding `"$($NewMember.Name)`" to `"$($ADGroup.Name)`"." @VerboseSplat))
                                    {
                                        # Add new member
                                        Add-ADPrincipalGroupMembership -Identity $NewMember.DistinguishedName -MemberOf @("$($ADGroup.Name)")

                                        # Remember computer objects added to group
                                        if ($NewMember.ObjectClass -eq 'Computer' -and -not $UpdatedObjects.ContainsKey($NewMember.Name))
                                        {
                                            $UpdatedObjects.Add($NewMember.Name, $true)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            #  ██████╗ ██████╗  ██████╗
            # ██╔════╝ ██╔══██╗██╔═══██╗
            # ██║  ███╗██████╔╝██║   ██║
            # ██║   ██║██╔═══╝ ██║   ██║
            # ╚██████╔╝██║     ╚██████╔╝
            #  ╚═════╝ ╚═╝      ╚═════╝

            #########
            # Import
            #########

            #Initialize
            $GpoPaths = @()
            $GpoPaths += Get-Item -Path "$env:TEMP\Gpo" -ErrorAction SilentlyContinue
            $GPoPaths += Get-ChildItem -Path "$env:TEMP\Baseline" -Directory -ErrorAction SilentlyContinue

            # Itterate gpo paths
            foreach($GpoDir in $GpoPaths)
            {
                # Read gpos
                foreach($Gpo in (Get-ChildItem -Path "$($GpoDir.FullName)" -Directory))
                {
                    # Set gpreport filepath
                    $GpReportFile = "$($Gpo.FullName)\gpreport.xml"

                    # Get gpo name from xml
                    $GpReportName = (Select-Xml -Path $GpReportFile -XPath '/').Node.GPO.Name

                    if (-not $GpReportName.StartsWith('MSFT'))
                    {
                        if (-not $GpReportName.StartsWith($DomainPrefix))
                        {
                            $GpReportName = "$DomainPrefix - $($GpReportName.Remove(0, $GpReportName.IndexOf('-') + 2))"
                        }

                        # Set domain name in site to zone assignment list
                        if ($GpReportName -match 'Site to Zone Assignment List')
                        {
                            ((Get-Content -Path $GpReportFile -Raw) -replace '%domain_wildcard%', "*.$DomainName") | Set-Content -Path $GpReportFile
                        }

                        # Set sids in GptTempl.inf
                        if ($GpReportName -match '(Restrict User Rights Assignment)')
                        {
                            $GpFile = "$($Gpo.FullName)\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"

                            $GptContent = Get-Content -Path $GpFile -Raw

                            $GptContent = $GptContent -replace '%join_domain%', "*$((Get-ADUser -Identity 'JoinDomain').SID.Value)"
                            $GptContent = $GptContent -replace '%domain_admins%', "*$((Get-ADGroup -Identity 'Domain Admins').SID.Value)"
                            $GptContent = $GptContent -replace '%enterprise_admins%', "*$((Get-ADGroup -Identity 'Enterprise Admins').SID.Value)"
                            $GptContent = $GptContent -replace '%schema_admins%', "*$((Get-ADGroup -Identity 'Schema Admins').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_0_admins%', "*$((Get-ADGroup -Identity 'Tier 0 - Admins').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_0_computers%', "*$((Get-ADGroup -Identity 'Tier 0 - Computers').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_0_users%', "*$((Get-ADGroup -Identity 'Tier 0 - Users').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_1_admins%', "*$((Get-ADGroup -Identity 'Tier 1 - Admins').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_1_computers%', "*$((Get-ADGroup -Identity 'Tier 1 - Computers').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_1_users%', "*$((Get-ADGroup -Identity 'Tier 1 - Users').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_2_admins%', "*$((Get-ADGroup -Identity 'Tier 2 - Admins').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_2_computers%', "*$((Get-ADGroup -Identity 'Tier 2 - Computers').SID.Value)"
                            $GptContent = $GptContent -replace '%tier_2_users%', "*$((Get-ADGroup -Identity 'Tier 2 - Users').SID.Value)"

                            Set-Content -Path $GpFile -Value $GptContent
                        }
                    }

                    # Check if gpo exist
                    if (-not (Get-GPO -Name $GpReportName -ErrorAction SilentlyContinue) -and
                        (ShouldProcess @WhatIfSplat -Message "Importing $($Gpo.Name) `"$GpReportName`"." @VerboseSplat))
                    {
                        Import-GPO -Path "$($GpoDir.FullName)" -BackupId $Gpo.Name -TargetName $GpReportName -CreateIfNeeded > $null

                        Start-Sleep -Milliseconds 500

                        if ($GpReportName -match '- (.*?) - IPSec - Restrict')
                        {
                            switch($Matches[1])
                            {
                                { $_ -match 'Domain Controller' }
                                {
                                    $TierGroupUser = 'Domain Admins'
                                    $TierGroupComputer = 'Domain Controllers'
                                }

                                default
                                {
                                    $TierGroupUser = "$($Matches[1]) - Admins"
                                    $TierGroupComputer = "$($Matches[1]) - Computers"
                                }
                            }

                            foreach ($Item in (Get-GPRegistryValue -Name $GpReportName -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules' -ErrorAction SilentlyContinue))
                            {
                                $NewValue = $Item.Value -replace "RUAuth=O:LSD:\(A;;CC;;;.*?\)", "RUAuth=O:LSD:(A;;CC;;;$((Get-ADGroup -Identity $TierGroupUser).SID.Value))"
                                $NewValue = $NewValue -replace "RMauth=O:LSD:\(A;;CC;;;.*?\)", "RMauth=O:LSD:(A;;CC;;;$((Get-ADGroup -Identity $TierGroupComputer).SID.Value))"

                                if ($NewValue -ne $Item.Value -and
                                    (ShouldProcess @WhatIfSplat -Message "Setting `"$GpReportName`" group sids for `"$($Item.ValueName)`"." @VerboseSplat))
                                {
                                    Set-GPRegistryValue -Name $GpReportName -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules' -ValueName $Item.ValueName -Value $NewValue -Type $Item.Type > $null
                                }
                            }
                        }
                    }
                }
            }

            ########
            # Links
            ########

            # Get DC build
            $DCBuild = [System.Environment]::OSVersion.Version.Build.ToString()

            $GPOLinks =
            @{
                #######
                # Root
                #######

                # Enforced if ending with +
                # Disabled if ending with -

                $BaseDN =
                @(
                    "$DomainPrefix - Domain - Force Group Policy+"
                    "$DomainPrefix - Domain - Firewall - Settings+"
                    "$DomainPrefix - Domain - Firewall - Block Legacy Protocols+"
                    "$DomainPrefix - Domain - Remote Desktop+"
                    "$DomainPrefix - Domain - Windows Update+"
                    "$DomainPrefix - Domain - Display Settings+"
                    "$DomainPrefix - Domain - Certificate Services Client+"
                    "$DomainPrefix - Security - Enable Virtualization Based Security+"
                    "$DomainPrefix - Security - Enable LSA Protection & LSASS Audit+"
                    "$DomainPrefix - Security - Enable SMB Encryption+"
                    "$DomainPrefix - Security - Client Kerberos Armoring+"
                    "$DomainPrefix - Security - Require Client LDAP Signing+"
                    "$DomainPrefix - Security - Restrict PowerShell & Enable Logging+"
                    "$DomainPrefix - Security - Disable Net Session Enumeration+"
                    "$DomainPrefix - Security - Disable Telemetry+"
                    "$DomainPrefix - Security - Disable Netbios+"
                    "$DomainPrefix - Security - Disable LLMNR+"
                    "$DomainPrefix - Security - Disable TLS 1.x+"
                    "$DomainPrefix - Security - Disable WPAD+"
                    "$DomainPrefix - Security - Block Untrusted Fonts+"
                    'Default Domain Policy'
                )

                #####################
                # Domain controllers
                #####################

                "OU=Domain Controllers,$BaseDN" =
                @(
                    "$DomainPrefix - Security - KDC Kerberos Armoring+"
                    "$DomainPrefix - Security - Disable Spooler+"
                    "$DomainPrefix - Domain Controller - IPSec - Request"  # IPSec
                    "$DomainPrefix - Domain Controller - Firewall - Basic Rules+"
                    "$DomainPrefix - Domain Controller - Restrict User Rights Assignment"  # RestrictDomain
                    "$DomainPrefix - Domain Controller - Advanced Audit+"
                    "$DomainPrefix - Domain Controller - Time - PDC NTP+"
                ) +
                $WinBuilds.Item($DCBuild).DCBaseline +
                $WinBuilds.Item($DCBuild).BaseLine +
                @(
                    'Default Domain Controllers Policy'
                )

                ############
                # Domain OU
                ############

                "OU=$DomainName,$BaseDN" =
                @(
                    "$DomainPrefix - IPSec - Permit General Mgmt"  # IPSec
                    "$DomainPrefix - Firewall - Permit General Mgmt+"
                    "$DomainPrefix - Firewall - Block SMB In-"
                    "$DomainPrefix - Security - Enable LAPS"  # RestrictDomain
                )
            }

            ############
            # Computers
            # Tier 0-2
            ############

            foreach($Tier in @(0, 1, 2))
            {
                if ($Tier -eq 2)
                {
                    # Workstations
                    $ComputerPolicy = @("$DomainPrefix - Security - Disable Spooler Client Connections+")
                }
                else
                {
                    # Servers
                    $ComputerPolicy = @("$DomainPrefix - Security - Disable Spooler+")
                }

                # Link tier gpos
                $ComputerPolicy +=
                @(
                    "$DomainPrefix - Tier $Tier - IPSec - Restrict"  # IPSec
                    "$DomainPrefix - Tier $Tier - Local Users and Groups+"
                    "$DomainPrefix - Tier $Tier - Restrict User Rights Assignment"  # RestrictDomain
                )

                # Link computer policy
                $GPOLinks.Add("OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN", $ComputerPolicy)
            }

            ############
            # Computers
            # Tier 0
            ############

            foreach($Build in $WinBuilds.Values)
            {
                # Check if server build
                if ($Build.Server)
                {
                    # Link baseline & server baseline
                    $GPOLinks.Add("OU=$($Build.Server),OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN", $Build.Baseline + $Build.ServerBaseline)

                    # Certificate Authorities
                    $GPOLinks.Add("OU=Certificate Authorities,OU=$($Build.Server),OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - IPSec - Certificate Authority"  # IPSec
                            "$DomainPrefix - Certificate Authority+"
                        )
                    )

                    # Federation Services
                    $GPOLinks.Add("OU=Federation Services,OU=$($Build.Server),OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - IPSec - Web Server"  # IPSec
                            "$DomainPrefix - Web Server+"
                        )
                    )

                    # Network Policy Server
                    $GPOLinks.Add("OU=Network Policy Server,OU=$($Build.Server),OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - IPSec - Network Policy Server"  # IPSec
                            "$DomainPrefix - Network Policy Server+"
                        )
                    )

                    # Web Servers
                    $GPOLinks.Add("OU=Web Servers,OU=$($Build.Server),OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - IPSec - Crl Distribution Point"  # IPSec
                            "$DomainPrefix - IPSec - Web Server"  # IPSec
                            "$DomainPrefix - Firewall - Permit SMB In+"
                            "$DomainPrefix - Web Server+"
                        )
                    )
                }
            }

            ############
            # Computers
            # Tier 1
            ############

            foreach($Build in $WinBuilds.Values)
            {
                # Check if server build
                if ($Build.Server)
                {
                    # Linkd baseline & server baseline
                    $GPOLinks.Add("OU=$($Build.Server),OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN", (

                            $Build.Baseline +
                            $Build.ServerBaseline
                        )
                    )

                    # Remote Access Servers
                    $GPOLinks.Add("OU=Remote Access Servers,OU=$($Build.Server),OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - IPSec - Remote Access Server"  # IPSec
                            "$DomainPrefix - Remote Access Server+"
                        )
                    )

                    # Web Application Proxy
                    $GPOLinks.Add("OU=Web Application Proxy,OU=$($Build.Server),OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - IPSec - Web Application Proxy"  # IPSec
                            "$DomainPrefix - Web Server+"
                        )
                    )

                    # Web Servers
                    $GPOLinks.Add("OU=Web Servers,OU=$($Build.Server),OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - IPSec - Web Server"  # IPSec
                            "$DomainPrefix - Web Server+"
                        )
                    )
                }
            }

            ############
            # Computers
            # Tier 2
            ############

            foreach($Build in $WinBuilds.Values)
            {
                # Check if workstation build
                if ($Build.Workstation)
                {
                    # Link baseline & computer baseline
                    $GPOLinks.Add("OU=$($Build.Workstation),OU=Computers,OU=Tier 2,OU=$DomainName,$BaseDN", (

                            $Build.Baseline +
                            $Build.ComputerBaseline
                        )
                    )
                }
            }

            ###################
            # Service Accounts
            ###################

            foreach($Tier in @(0, 1))
            {
                # Link password policy
                $GPOLinks.Add("OU=Service Accounts,OU=Tier $Tier,OU=$DomainName,$BaseDN", (

                        "$DomainPrefix - Security - Service Password Policy+"
                    )
                )
            }

            ########
            # Users
            ########

            # Initialize
            $UserServerBaseline = @()
            $UserWorkstationBaseline = @()

            # Get baseline for all versions from winver
            foreach($Build in $WinBuilds.Values)
            {
                if ($Build.Server -and $Build.UserBaseline)
                {
                    $UserServerBaseline += $Build.UserBaseline
                }

                if ($Build.Workstation -and $Build.UserBaseline)
                {
                    $UserWorkstationBaseline += $Build.UserBaseline
                }
            }

            ###########
            # Users
            # Tier 0-2
            ###########

            foreach($Tier in @(0, 1, 2))
            {
                $UserPolicy =
                @(
                    # Empty
                )

                # Link administrators policy
                $GPOLinks.Add("OU=Administrators,OU=Tier $Tier,OU=$DomainName,$BaseDN", $UserPolicy)

                if ($Tier -eq 2)
                {
                    # Workstations
                    $UserPolicy +=
                    @(
                        "$DomainPrefix - User - Disable WPAD"
                        "$DomainPrefix - User - Disable WSH-"
                    )

                    $UserPolicy += $UserWorkstationBaseline
                }
                else
                {
                    # Servers
                    $UserPolicy +=  $UserServerBaseline
                }

                # Link users policy
                $GPOLinks.Add("OU=Users,OU=Tier $Tier,OU=$DomainName,$BaseDN", $UserPolicy)
            }

            ############
            # Link GPOs
            ############

            # Itterate targets
            foreach ($Target in $GPOLinks.Keys)
            {
                $Order = 1
                $TargetShort = $Target -match '((?:cn|ou|dc)=.*?,(?:cn|ou|dc)=.*?)(?:,|$)' | ForEach-Object { $Matches[1] }

                # Itterate GPOs
                foreach($GpoName in ($GPOLinks.Item($Target)))
                {
                    $LinkEnabled = 'Yes'
                    $LinkEnabledBool = $true
                    $LinkEnforce = 'No'
                    $LinkEnforceBool = $false

                    $IsRestrictingGpo = $GpoName -match 'Enable LAPS|Restrict User Rights Assignment'
                    $IsIPSecGpo = $GpoName -match 'IPSec'

                    if ($IsRestrictingGpo -or $IsIPSecGpo)
                    {
                        $LinkEnabled = 'No'
                        $LinkEnabledBool = $false
                        $LinkEnforce = 'Yes'
                        $LinkEnforceBool = $true

                        if ($RestrictDomain -eq $true -or $EnableIPSec -eq $True)
                        {
                            $LinkEnabled = 'Yes'
                            $LinkEnabledBool = $true
                        }
                    }
                    elseif ($GpoName.EndsWith('-'))
                    {
                        $LinkEnabled = 'No'
                        $LinkEnabledBool = $false
                        $GpoName = $GpoName.TrimEnd('-')
                    }
                    elseif ($GpoName.EndsWith('+'))
                    {
                        $LinkEnforce = 'Yes'
                        $LinkEnforceBool = $true
                        $GpoName = $GpoName.TrimEnd('+')
                    }

                    # Get gpo report
                    [xml]$GpoXml = Get-GPOReport -Name $GpoName -ReportType Xml -ErrorAction SilentlyContinue

                    if ($GpoXml)
                    {
                        $TargetCN = ConvertTo-CanonicalName -DistinguishedName $Target

                        # Check link
                        if (-not ($TargetCN -in $GpoXml.GPO.LinksTo.SOMPath) -and
                            (ShouldProcess @WhatIfSplat -Message "Link `"$GpoName`" ($Order) [Created=$Order] -> `"$TargetShort`"" @VerboseSplat))
                        {
                            New-GPLink -Name $GpoName -Target $Target -Order $Order -LinkEnabled $LinkEnabled -Enforced $LinkEnforce -ErrorAction Stop > $null
                        }
                        else
                        {
                            foreach ($Link in $GpoXml.GPO.LinksTo)
                            {
                                if ((($Link.Enabled -ne $LinkEnabledBool -and -not $IsRestrictingGpo -and -not $IsIPSecGpo) -or
                                     ($Link.Enabled -ne $LinkEnabledBool -and (($IsRestrictingGpo -and $RestrictDomain -notlike $null) -or ($IsIPSecGpo -and $EnableIPSec -notlike $null)))) -and
                                    (ShouldProcess @WhatIfSplat -Message "Link `"$GpoName`" ($Order) [Enabled=$LinkEnabled] -> `"$TargetShort`"" @VerboseSplat))
                                {
                                    Set-GPLink -Name $GpoName -Target $Target -LinkEnabled $LinkEnabled > $null
                                }

                                if ($Link.NoOverride -ne $LinkEnforceBool -and
                                    (ShouldProcess @WhatIfSplat -Message "Link `"$GpoName`" ($Order) [Enforced=$LinkEnforce] -> `"$TargetShort`"" @VerboseSplat))
                                {
                                    Set-GPLink -Name $GpoName -Target $Target -Enforced $LinkEnforce > $null
                                }

                                if ($Order -ne (Get-GPInheritance -Target $Target | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName } | Select-Object -ExpandProperty Order) -and
                                    (ShouldProcess @WhatIfSplat -Message "Link `"$GpoName`" ($Order) [Order=$Order] -> `"$TargetShort`" " @VerboseSplat))
                                {
                                    Set-GPLink -Name $GpoName -Target $Target -Order $Order > $null
                                }
                            }
                        }

                        $Order++;
                    }
                    else
                    {
                        ShouldProcess @WhatIfSplat -Message "Gpo not found, couldn't link `"$GpoName`" -> `"$TargetShort`"" -WriteWarning > $null
                    }
                }
            }

            ##############
            # Permissions
            ##############

            ########
            # Users
            ########

            foreach ($GpoName in (Get-GPInheritance -Target "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN").GpoLinks | Select-Object -ExpandProperty DisplayName)
            {
                $Build = ($WinBuilds.GetEnumerator() | Where-Object { $GpoName -in $_.Value.UserBaseline }).Key

                if ($Build)
                {
                    # Set groups
                    $GpoPermissionGroups = @('Domain Users')

                    # Add workstation
                    if ($WinBuilds.Item($Build).Workstation)
                    {
                        $GpoPermissionGroups += "Tier 2 - $($WinBuilds.Item($Build).Workstation)"
                    }

                    <# FIX

                    # Add server
                    if ($WinBuilds.Item($Build).Server -and $GpoName -match 'Internet Explorer')
                    {
                        $GpoPermissionGroups += $WinBuilds.Item($Build).Server
                    }
                    #>

                    # Itterate groups
                    foreach ($Group in $GpoPermissionGroups)
                    {
                        # Set permission
                        if ((Get-GPPermission -Name $GpoName -TargetName $Group -TargetType Group -ErrorAction SilentlyContinue ).Permission -ne 'GpoApply' -and
                            (ShouldProcess @WhatIfSplat -Message "Setting `"$Group`" GpoApply to `"$GpoName`" gpo." @VerboseSplat))
                        {
                            Set-GPPermission -Name $GpoName -TargetName $Group -TargetType Group -PermissionLevel GpoApply > $null
                        }
                    }

                    if ($RemoveAuthenticatedUsersFromUserGpos.IsPresent)
                    {
                        # Remove authenticated user
                        if ((Get-GPPermission -Name $GpoName -TargetName 'Authenticated Users' -TargetType Group -ErrorAction SilentlyContinue) -and
                            (ShouldProcess @WhatIfSplat -Message "Removing `"Authenticated Users`" from `"$GpoName`" gpo." @VerboseSplat))
                        {
                            Set-GPPermission -Name $GpoName -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel None -Confirm:$false > $nul
                        }
                    }
                }
            }

            #  █████╗ ██████╗ ███████╗███████╗
            # ██╔══██╗██╔══██╗██╔════╝██╔════╝
            # ███████║██║  ██║█████╗  ███████╗
            # ██╔══██║██║  ██║██╔══╝  ╚════██║
            # ██║  ██║██████╔╝██║     ███████║
            # ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚══════╝

            $Principals =
            @(
                (Get-ADComputer -Filter "Name -like 'ADFS*'" -SearchBase "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN" -SearchScope Subtree),
                (Get-ADUser -Filter "Name -eq 'tier0admin'" -SearchBase "OU=Administrators,OU=Tier 0,OU=$DomainName,$BaseDN" -SearchScope OneLevel)
            )

            # Setup service account
            foreach($Principal in $Principals)
            {
                if ($Principal)
                {
                    # Initialize
                    $PrincipalsAllowedToDelegateToAccount = @()
                    $PrincipalsAllowedToRetrieveManagedPassword = @()

                    # Get
                    $MsaAdfs = Get-ADServiceAccount -Identity 'MsaAdfs' -Properties PrincipalsAllowedToRetrieveManagedPassword, PrincipalsAllowedToDelegateToAccount

                    if ($MsaAdfs)
                    {
                        # Populate and strip old sids
                        if ($MsaAdfs.PrincipalsAllowedToDelegateToAccount)
                        {
                            $PrincipalsAllowedToDelegateToAccount += $MsaAdfs.PrincipalsAllowedToDelegateToAccount.Where({$_ -notmatch 'S-\d-\d-\d{2}-\d{10}-\d{9}-\d{10}-\d{4}'})
                        }

                        if ($MsaAdfs.PrincipalsAllowedToRetrieveManagedPassword)
                        {
                            $PrincipalsAllowedToRetrieveManagedPassword += $MsaAdfs.PrincipalsAllowedToRetrieveManagedPassword.Where({$_ -notmatch 'S-\d-\d-\d{2}-\d{10}-\d{9}-\d{10}-\d{4}'})
                        }

                        # Retrive password
                        if ($Principal.DistinguishedName -notin $MsaAdfs.PrincipalsAllowedToRetrieveManagedPassword -and
                            (ShouldProcess @WhatIfSplat -Message "Allow `"$($Principal.Name)`" to retrieve `"$($MsaAdfs.Name)`" password." @VerboseSplat))
                        {
                            Set-ADServiceAccount -Identity 'MsaAdfs' -PrincipalsAllowedToRetrieveManagedPassword @($PrincipalsAllowedToDelegateToAccount + $Principal.DistinguishedName)
                        }

                        # Delegate
                        if ($Principal.DistinguishedName -notin $MsaAdfs.PrincipalsAllowedToDelegateToAccount -and
                            (ShouldProcess @WhatIfSplat -Message "Allow `"$($Principal.Name)`" to delegate to `"$($MsaAdfs.Name)`"." @VerboseSplat))
                        {
                            Set-ADServiceAccount -Identity 'MsaAdfs' -PrincipalsAllowedToDelegateToAccount @($PrincipalsAllowedToRetrieveManagedPassword + $Principal.DistinguishedName)
                        }
                    }
                }
            }

            # Check spn
            if (((setspn -L MsaAdfs) -join '') -notmatch "host/adfs.$DomainName" -and
                (ShouldProcess @WhatIfSplat -Message "Setting SPN `"host/adfs.$DomainName`" for MsaAdfs." @VerboseSplat))
            {
                setspn -a host/adfs.$DomainName MsaAdfs > $null
            }


            # Check adfs container
            if (-not (Get-ADObject -Filter "Name -eq 'ADFS' -and ObjectCategory -eq 'Container'" -SearchBase "CN=Microsoft,CN=Program Data,$BaseDN" -SearchScope 'OneLevel') -and
                (ShouldProcess @WhatIfSplat -Message "Adding `"CN=ADFS,CN=Microsoft,CN=Program Data,$BaseDN`" container." @VerboseSplat))
            {
                New-ADObject -Name "ADFS" -Path "CN=Microsoft,CN=Program Data,$BaseDN" -Type Container
            }

            $AdfsDkmContainer = Get-ADObject -Filter "Name -like '*'" -SearchBase "CN=ADFS,CN=Microsoft,CN=Program Data,$BaseDN" -SearchScope OneLevel
            $AdfsDkmGuid = [Guid]::NewGuid().Guid

            # Check dkm container
            if (-not $AdfsDkmContainer -and
                (ShouldProcess @WhatIfSplat -Message "Adding `"CN=$AdfsDkmGuid,CN=ADFS`" container." @VerboseSplat))
            {
                $AdfsDkmContainer = New-ADObject -Name $AdfsDkmGuid -Path "CN=ADFS,CN=Microsoft,CN=Program Data,$BaseDN" -Type Container -PassThru
            }
            else
            {
                $AdfsDkmGuid = $AdfsDkmContainer.Name
            }

            $Result += @{ AdfsDkmGuid = $AdfsDkmGuid }

            # ██████╗ ███████╗██╗     ███████╗ ██████╗  █████╗ ████████╗███████╗
            # ██╔══██╗██╔════╝██║     ██╔════╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
            # ██║  ██║█████╗  ██║     █████╗  ██║  ███╗███████║   ██║   █████╗
            # ██║  ██║██╔══╝  ██║     ██╔══╝  ██║   ██║██╔══██║   ██║   ██╔══╝
            # ██████╔╝███████╗███████╗███████╗╚██████╔╝██║  ██║   ██║   ███████╗
            # ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

            # Check if AD drive is mapped
            if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue))
            {
                Import-Module -Name ActiveDirectory
            }

            $AccessRight = @{}
            Get-ADObject -SearchBase "CN=Configuration,$BaseDN" -LDAPFilter "(&(objectClass=controlAccessRight)(rightsguid=*))" -Properties displayName, rightsGuid | ForEach-Object { $AccessRight.Add($_.displayName, [System.GUID] $_.rightsGuid) }

            $SchemaID = @{}
            Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$BaseDN" -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName, schemaIDGUID | ForEach-Object { $SchemaID.Add($_.lDAPDisplayName, [System.GUID] $_.schemaIDGUID) }

            ########################
            # Create Child Computer
            ########################

            $CreateChildComputer =
            @(
                <#
                FIX
                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = $SchemaID['attributeCertificateAttribute'];
                    InheritedObjectType   = $SchemaID['Computer'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate Create Child Computer";
                }
                #>

                @{
                    ActiveDirectoryRights = 'CreateChild';
                    InheritanceType       = 'All';
                    ObjectType            = $SchemaID['Computer'];
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate Create Child Computer";
                }

                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = $SchemaID['Computer'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate Create Child Computer";
                }
            )

            Set-Ace -DistinguishedName "OU=$RedirCmp,OU=$DomainName,$BaseDN" -AceList $CreateChildComputer

            ################################
            # Install Certificate Authority
            ################################

            $InstallCertificateAuthority =
            @(
                @{
                    ActiveDirectoryRights = 'GenericAll';
                    InheritanceType       = 'All';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate Install Certificate Authority";
                }
            )

            Set-Ace -DistinguishedName "CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -AceList $InstallCertificateAuthority

            $AddToGroup =
            @(
                @{
                    ActiveDirectoryRights = 'ReadProperty, WriteProperty';
                    InheritanceType       = 'All';
                    ObjectType            = $SchemaID['member'];
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate Install Certificate Authority";
                }
            )

            # Set R/W on member object
            Set-Ace -DistinguishedName "CN=Cert Publishers,CN=Users,$BaseDN" -AceList $AddToGroup
            Set-Ace -DistinguishedName "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$BaseDN" -AceList $AddToGroup

            ####################
            # Deny Block SMB In
            ####################

            <#
            $DenySmbBlock =
            @(
                @{
                    ActiveDirectoryRights = 'ExtendedRight';
                    InheritanceType       = 'None';
                    ObjectType            = $AccessRight['Apply Group Policy'];
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                    AccessControlType     = 'Deny';
                    IdentityReference     = "$DomainNetbiosName\Delegate Gpo Deny Firewall Block SMB In";
                }
            )

            Set-Ace -DistinguishedName (Get-GPO -Name "$DomainPrefix - Firewall - Block SMB In" | Select-Object -ExpandProperty Path) -AceList $DenySmbBlock
            #>

            ##############################
            # Adfs Container Generic Read
            ##############################

            $AdfsContainerGenericRead =
            @(
                @{
                    ActiveDirectoryRights = 'GenericRead';
                    InheritanceType       = 'All';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate Adfs Container Generic Read";
                }
            )

            Set-Ace -DistinguishedName "CN=ADFS,CN=Microsoft,CN=Program Data,$BaseDN" -AceList $AdfsContainerGenericRead -Owner "$DomainNetbiosName\Delegate Adfs Container Generic Read"

            #################################
            # Adfs Dkm Container Permissions
            #################################

            $AdfsDkmContainerPermissions =
            @(
                @{
                    ActiveDirectoryRights = 'CreateChild, WriteProperty, DeleteTree, GenericRead, WriteDacl, WriteOwner';
                    InheritanceType       = 'All';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate Adfs Dkm Container Permissions";
                }
            )

            Set-Ace -DistinguishedName $AdfsDkmContainer.DistinguishedName -AceList $AdfsDkmContainerPermissions -Owner "$DomainNetbiosName\Delegate Adfs Dkm Container Permissions"

            ################################
            # AdSync Basic Read Permissions
            ################################

            $AdSyncBasicReadPermissions =
            @(
                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = $SchemaID['contact'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                }

                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = $SchemaID['user'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                }

                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = $SchemaID['group'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                }

                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = $SchemaID['device'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                }

                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = $SchemaID['computer'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                }

                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = $SchemaID['inetOrgPerson'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                }

                @{
                    ActiveDirectoryRights = 'ReadProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritedObjectType   = $SchemaID['foreignSecurityPrincipal'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                }
            )

            Set-Ace -DistinguishedName "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN" -AceList $AdSyncBasicReadPermissions

            ########################################
            # AdSync Password Hash Sync Permissions
            ########################################

            $AdSyncPasswordHashSyncPermissions =
            @(
                @{
                    ActiveDirectoryRights = 'ExtendedRight';
                    InheritanceType       = 'None';
                    ObjectType            = $AccessRight['Replicating Directory Changes All'];
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Password Hash Sync Permissions";
                }

                @{
                    ActiveDirectoryRights = 'ExtendedRight';
                    InheritanceType       = 'None';
                    ObjectType            = $AccessRight['Replicating Directory Changes'];
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Password Hash Sync Permissions";
                }
            )

            Set-Ace -DistinguishedName "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN" -AceList $AdSyncPasswordHashSyncPermissions

            ###########################################
            # AdSync MsDs Consistency Guid Permissions
            ###########################################

            $AdSyncMsDsConsistencyGuidPermissions =
            @(
                @{
                    ActiveDirectoryRights = 'ReadProperty, WriteProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = $SchemaID['mS-DS-ConsistencyGuid'];
                    InheritedObjectType   = $SchemaID['user'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync MsDs Consistency Guid Permissions";
                }

                @{
                    ActiveDirectoryRights = 'ReadProperty, WriteProperty';
                    InheritanceType       = 'Descendents';
                    ObjectType            = $SchemaID['mS-DS-ConsistencyGuid'];
                    InheritedObjectType   = $SchemaID['group'];
                    AccessControlType     = 'Allow';
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync MsDs Consistency Guid Permissions";
                }
            )

            Set-Ace -DistinguishedName "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN" -AceList $AdSyncMsDsConsistencyGuidPermissions
            Set-Ace -DistinguishedName "CN=AdminSDHolder,CN=System,$BaseDN" -AceList $AdSyncMsDsConsistencyGuidPermissions

            ############################
            # Remove Join Domain access
            ############################

            foreach ($Computer in (Get-ADComputer -Filter "Name -like '*'"))
            {
                $ComputerAcl = Get-Acl -Path "AD:$($Computer.DistinguishedName)"
                $ComputerAclChanged = $false

                if ($ComputerAcl.Owner -notmatch 'Domain Admins' -and
                    (ShouldProcess @WhatIfSplat -Message "Setting `"$DomainNetbiosName\Domain Admins`" as owner for $($Computer.Name)." @VerboseSplat))

                {
                    $ComputerAcl.SetOwner([System.Security.Principal.NTAccount] "$DomainNetbiosName\Domain Admins")
                    $ComputerAclChanged = $true
                }

                foreach ($AccessRule in $ComputerAcl.Access)
                {
                    if ($AccessRule.IdentityReference.Value -match 'JoinDomain' -and
                        ((ShouldProcess @WhatIfSplat -Message "Removing `"JoinDomain: $($AccessRule.ActiveDirectoryRights)`" from `"$($Computer.Name)`"." @VerboseSplat)))
                    {
                        $ComputerAcl.RemoveAccessRule($AccessRule) > $null
                        $ComputerAclChanged = $true
                    }
                }

                if ($ComputerAclChanged = $true)
                {
                    Set-Acl -Path "AD:$($Computer.DistinguishedName)" -AclObject $ComputerAcl
                }
            }

            # ████████╗███████╗███╗   ███╗██████╗ ██╗      █████╗ ████████╗███████╗███████╗
            # ╚══██╔══╝██╔════╝████╗ ████║██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝
            #    ██║   █████╗  ██╔████╔██║██████╔╝██║     ███████║   ██║   █████╗  ███████╗
            #    ██║   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║     ██╔══██║   ██║   ██╔══╝  ╚════██║
            #    ██║   ███████╗██║ ╚═╝ ██║██║     ███████╗██║  ██║   ██║   ███████╗███████║
            #    ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝

            # Set oid path
            $OidPath = "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN"

            # Get msPKI-Cert-Template-OID
            $msPKICertTemplateOid = Get-ADObject -Identity $OidPath -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID

            # Check if msPKI-Cert-Template-OID exist
            if (-not $msPKICertTemplateOid -and
                (ShouldProcess @WhatIfSplat -Message "Creating default certificate templates." @VerboseSplat))
            {
                # Install default templates
                TryCatch { certutil -InstallDefaultTemplates } > $null

                # Wait a bit
                Start-Sleep -Seconds 1

                # Reload msPKI-Cert-Template-OID
                $msPKICertTemplateOid = Get-ADObject -Identity $OidPath -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID
            }

            # Check if templates exist
            if ($msPKICertTemplateOid -and (Test-Path -Path "$env:TEMP\Templates"))
            {
                # Define empty acl
                $EmptyAcl = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity

                # https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection?view=dotnet-plat-ext-3.1
                $EmptyAcl.SetAccessRuleProtection($true, $false)

                # Set template path
                $CertificateTemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN"

                # Read templates
                foreach ($TemplateFile in (Get-ChildItem -Path "$env:TEMP\Templates" -Filter '*_tmpl.json'))
                {
                    # Read template file and convert from json
                    $SourceTemplate = $TemplateFile | Get-Content | ConvertFrom-Json

                    # Add domain prefix to template name
                    $NewTemplateName = "$DomainPrefix$($SourceTemplate.Name)"

                    # https://github.com/GoateePFE/ADCSTemplate/blob/master/ADCSTemplate.psm1
                    if (-not (Get-ADObject -SearchBase $CertificateTemplatesPath -Filter "Name -eq '$NewTemplateName' -and objectClass -eq 'pKICertificateTemplate'") -and
                        (ShouldProcess @WhatIfSplat -Message "Creating template `"$NewTemplateName`"." @VerboseSplat))
                    {
                        # Generate new template oid and cn
                        do
                        {
                           $Part2 = Get-Random -Minimum 10000000 -Maximum 99999999
                           $NewOid = "$msPKICertTemplateOid.$(Get-Random -Minimum 10000000 -Maximum 99999999).$Part2"
                           $NewOidCn = "$Part2.$((1..32 | % { '{0:X}' -f (Get-Random -Max 16) }) -join '')"
                        }
                        while (

                            # Check if oid exist
                            Get-ADObject -SearchBase $OidPath -Filter "cn -eq '$NewOidCn' -and msPKI-Cert-Template-OID -eq '$NewOID'"
                        )

                        # Add domain prefix to template display name
                        $NewTemplateDisplayName = "$DomainPrefix $($SourceTemplate.DisplayName)"

                        # Oid attributes
                        $NewOidAttributes =
                        @{
                            'DisplayName' = $NewTemplateDisplayName
                            'msPKI-Cert-Template-OID' = $NewOid
                            'flags' = [System.Int32] '1'
                        }

                        # Create oid
                        New-ADObject -Name $NewOidCn -Path $OidPath -Type 'msPKI-Enterprise-OID' -OtherAttributes $NewOidAttributes

                        # Template attributes
                        $NewTemplateAttributes =
                        @{
                            'DisplayName' = $NewTemplateDisplayName
                            'msPKI-Cert-Template-OID' = $NewOid
                        }

                        # Import attributes
                        foreach ($Property in ($SourceTemplate | Get-Member -MemberType NoteProperty))
                        {
                            Switch ($Property.Name)
                            {
                                { $_ -in @('flags',
                                           'revision',
                                           'msPKI-Certificate-Name-Flag',
                                           'msPKI-Enrollment-Flag',
                                           'msPKI-Minimal-Key-Size',
                                           'msPKI-Private-Key-Flag',
                                           'msPKI-RA-Signature',
                                           'msPKI-Template-Minor-Revision',
                                           'msPKI-Template-Schema-Version',
                                           'pKIDefaultKeySpec',
                                           'pKIMaxIssuingDepth')}
                                {
                                    $NewTemplateAttributes.Add($_, [System.Int32]$SourceTemplate.$_)
                                    break
                                }

                                { $_ -in @('msPKI-Certificate-Application-Policy',
                                           'msPKI-RA-Application-Policies',
                                           'msPKI-Supersede-Templates',
                                           'pKICriticalExtensions',
                                           'pKIDefaultCSPs',
                                           'pKIExtendedKeyUsage')}
                                {
                                    $NewTemplateAttributes.Add($_, [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]$SourceTemplate.$_)
                                    break
                                }

                                { $_ -in @('pKIExpirationPeriod',
                                           'pKIKeyUsage',
                                           'pKIOverlapPeriod')}
                                {
                                    $NewTemplateAttributes.Add($_, [System.Byte[]]$SourceTemplate.$_)
                                    break
                                }

                                { $_ -in @('Name',
                                           'DisplayName')}
                                {
                                    break
                                }

                                default
                                {
                                    ShouldProcess @WhatIfSplat -Message "Missing template property handler for `"$($Property.Name)`"." -WriteWarning > $null
                                }
                            }
                        }

                        # Create template
                        $NewADObj = New-ADObject -Name $NewTemplateName -Path $CertificateTemplatesPath -Type 'pKICertificateTemplate' -OtherAttributes $NewTemplateAttributes -PassThru

                        # Empty acl
                        Set-Acl -AclObject $EmptyAcl -Path "AD:$($NewADObj.DistinguishedName)"
                    }
                }

                # Read acl files
                foreach ($AclFile in (Get-ChildItem -Path "$env:TEMP\Templates" -Filter '*_acl.json'))
                {
                    # Read acl file and convert from json
                    $SourceAcl = $AclFile | Get-Content | ConvertFrom-Json

                    foreach ($Ace in $SourceAcl)
                    {
                        Set-Ace -DistinguishedName "CN=$DomainPrefix$($AclFile.BaseName.Replace('_acl', '')),$CertificateTemplatesPath" -AceList ($Ace | Select-Object -Property AccessControlType, ActiveDirectoryRights, InheritanceType, @{ n = 'IdentityReference'; e = { $_.IdentityReference.Replace('%domain%', $DomainNetbiosName) }}, ObjectType, InheritedObjectType)
                    }
                }

                Start-Sleep -Seconds 1
                Remove-Item -Path "$($env:TEMP)\Templates" -Recurse -Force
            }

            #  █████╗ ██╗   ██╗████████╗██╗  ██╗███╗   ██╗    ██████╗  ██████╗ ██╗     ██╗ ██████╗██╗   ██╗
            # ██╔══██╗██║   ██║╚══██╔══╝██║  ██║████╗  ██║    ██╔══██╗██╔═══██╗██║     ██║██╔════╝╚██╗ ██╔╝
            # ███████║██║   ██║   ██║   ███████║██╔██╗ ██║    ██████╔╝██║   ██║██║     ██║██║      ╚████╔╝
            # ██╔══██║██║   ██║   ██║   ██╔══██║██║╚██╗██║    ██╔═══╝ ██║   ██║██║     ██║██║       ╚██╔╝
            # ██║  ██║╚██████╔╝   ██║   ██║  ██║██║ ╚████║    ██║     ╚██████╔╝███████╗██║╚██████╗   ██║
            # ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝   ╚═╝

            $AuthenticationTires =
            @(
                @{ Name = 'Domain Controllers';  Liftime = 45; }
                @{ Name = 'Tier 0';              Liftime = 45; }
                @{ Name = 'Tier 1';              Liftime = 45; }
                @{ Name = 'Tier 2';              Liftime = 45; }
                @{ Name = 'Lockdown';            Liftime = 45; }
            )

            foreach ($Tier in $AuthenticationTires)
            {
                ##############
                # Get members
                ##############

                switch ($Tier.Name)
                {
                    'Domain Controllers'
                    {
                        $PolicyUsers   = @(Get-ADGroup -Identity "Domain Admins" -Properties Members | Select-Object -ExpandProperty Members)
                        $SiloComputers = @(Get-ADDomainController -Filter '*' | Select-Object -ExpandProperty ComputerObjectDN)
                        $Condition     = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo== "Domain Controllers Silo"))'
                    }

                    'Lockdown'
                    {
                        $PolicyUsers   = @(Get-ADUser -Filter "Name -like '*'" -SearchScope 'OneLevel' -SearchBase "OU=Redirect Users,OU=$DomainName,$BaseDN" | Select-Object -ExpandProperty DistinguishedName)
                        $SiloComputers = $null
                        $Condition     = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo== "Lockdown"))'
                    }
                    default
                    {
                        $PolicyUsers =
                        @(
                            @(Get-ADGroup -Identity "$($Tier.Name) - Admins" -Properties Members | Select-Object -ExpandProperty Members) +
                            @(Get-ADGroup -Identity "$($Tier.Name) - Users" -Properties Members | Select-Object -ExpandProperty Members)
                        )
                        $SiloComputers = @(Get-ADGroup -Identity "$($Tier.Name) - Computers" -Properties Members | Select-Object -ExpandProperty Members)
                        $Condition     = "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo== `"$($Tier.Name) Silo`"))"
                    }
                }

                ################
                # Create Policy
                ################

                # Get policy
                $AuthPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($Tier.Name) Policy'"

                if (-not $AuthPolicy -and
                    (ShouldProcess @WhatIfSplat -Message "Adding `"$($Tier.Name) Policy`"" @VerboseSplat))
                {
                    $Splat =
                    @{
                        Name = "$($Tier.Name) Policy"
                        Enforce = $false
                        ProtectedFromAccidentalDeletion = $false
                        UserTGTLifetimeMins = $Tier.Liftime
                        UserAllowedToAuthenticateFrom = $Condition
                    }

                    $AuthPolicy = New-ADAuthenticationPolicy @Splat -PassThru
                }

                ################
                # Add to Policy
                ################

                # Itterate all group members
                foreach ($UserDN in $PolicyUsers)
                {
                    # Get common name
                    $UserCN = $($UserDN -match 'CN=(.*?),' | ForEach-Object { $Matches[1] })

                    # Get assigned authentication policy
                    $AssignedPolicy = Get-ADObject -Identity $UserDN -Properties msDS-AssignedAuthNPolicy | Select-Object -ExpandProperty msDS-AssignedAuthNPolicy

                    if (-not $AssignedPolicy -or $AssignedPolicy -notmatch $AuthPolicy.DistinguishedName -and
                        (ShouldProcess -Message "Adding `"$UserCN`" to `"$($Tier.Name) Policy`"" @VerboseSplat))
                    {
                        Set-ADAccountAuthenticationPolicySilo -AuthenticationPolicy $AuthPolicy.DistinguishedName -Identity $UserDN
                    }
                }

                ##############
                # Create Silo
                ##############

                # Get silo
                $AuthSilo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$($Tier.Name) Silo'"

                if (-not $AuthSilo -and
                    (ShouldProcess @WhatIfSplat -Message "Adding `"$($Tier.Name) Silo`"" @VerboseSplat))
                {
                    $Splat =
                    @{
                        Name = "$($Tier.Name) Silo"
                        Enforce = $false
                        ProtectedFromAccidentalDeletion = $false
                        UserAuthenticationPolicy = "$($Tier.Name) Policy"
                        ServiceAuthenticationPolicy = "$($Tier.Name) Policy"
                        ComputerAuthenticationPolicy = "$($Tier.Name) Policy"
                    }

                    $AuthSilo = New-ADAuthenticationPolicySilo @Splat -PassThru
                }

                #####################
                # Add/Assign to Silo
                #####################

                # Itterate all group members
                foreach ($ComputerDN in $SiloComputers)
                {
                    # Get common name
                    $ComputerCN = $($ComputerDN -match 'CN=(.*?),' | ForEach-Object { $Matches[1] })

                    if ($ComputerDN -notin ($AuthSilo | Select-Object -ExpandProperty Members) -and
                        (ShouldProcess -Message "Adding $ComputerCN to `"$($Tier.Name) Silo`"" @VerboseSplat))
                    {
                        Grant-ADAuthenticationPolicySiloAccess -Identity "$($Tier.Name) Silo" -Account "$ComputerDN"
                    }

                    # Get assigned authentication policy silo
                    $AssignedPolicy = Get-ADObject -Identity $ComputerDN -Properties msDS-AssignedAuthNPolicySilo | Select-Object -ExpandProperty msDS-AssignedAuthNPolicySilo

                    if (-not $AssignedPolicy -or $AssignedPolicy -notmatch "CN=$($Tier.Name) Silo" -and
                        (ShouldProcess -Message "Assigning $ComputerCN with `"$($Tier.Name) Silo`"" @VerboseSplat))
                    {
                        Set-ADAccountAuthenticationPolicySilo -AuthenticationPolicySilo "$($Tier.Name) Silo" -Identity $ComputerDN
                    }
                }

                ######################
                # Restrict/Unrestrict
                ######################

                if ($RestrictDomain -notlike $null)
                {
                    $EnforceChanged = $false

                    switch ($RestrictDomain)
                    {
                        $true
                        {
                            # Auth policy enforced
                            if ($AuthPolicy.Enforce -ne $true -and
                                (ShouldProcess @WhatIfSplat -Message "Enforcing `"$($Tier.Name) Policy`"" @VerboseSplat))
                            {
                                Set-ADAuthenticationPolicy -Identity "$($Tier.Name) Policy" -Enforce $true
                                $EnforceChanged = $true
                            }

                            # Auth silo enforced
                            if ($AuthSilo.Enforce -ne $true -and
                                (ShouldProcess @WhatIfSplat -Message "Enforcing `"$($Tier.Name) Silo`"" @VerboseSplat))
                            {
                                Set-ADAuthenticationPolicySilo -Identity "$($Tier.Name) Silo" -Enforce $true
                                $EnforceChanged = $true
                            }
                        }
                        $false
                        {
                            # Auth policy NOT enforced
                            if ($AuthPolicy.Enforce -eq $true -and
                                (ShouldProcess @WhatIfSplat -Message "Removing enforce from `"$($Tier.Name) Policy`"" @VerboseSplat))
                            {
                                Set-ADAuthenticationPolicy -Identity "$($Tier.Name) Policy" -Enforce $false
                                $EnforceChanged = $true
                            }

                            # Auth silo NOT enforced
                            if ($AuthSilo.Enforce -eq $true -and
                                (ShouldProcess @WhatIfSplat -Message "Removing enforce from `"$($Tier.Name) Silo`"" @VerboseSplat))
                            {
                                Set-ADAuthenticationPolicySilo -Identity "$($Tier.Name) Silo" -Enforce $false
                                $EnforceChanged = $true
                            }
                        }
                    }
                }
            }

            # ██╗      █████╗ ██████╗ ███████╗
            # ██║     ██╔══██╗██╔══██╗██╔════╝
            # ██║     ███████║██████╔╝███████╗
            # ██║     ██╔══██║██╔═══╝ ╚════██║
            # ███████╗██║  ██║██║     ███████║
            # ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝

            # Check msLAPS-Password
            if (-not (TryCatch { Get-ADComputer -Filter "Name -eq '$ENV:ComputerName'" -SearchBase "OU=Domain Controllers,$BaseDN" -SearchScope OneLevel -Properties 'msLAPS-Password' } -Boolean -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Updating LAPS schema." @VerboseSplat))
            {
                # Update schema
                Update-LapsAdSchema -Confirm:$false

                # Set permission
                Set-LapsADComputerSelfPermission -Identity "OU=$DomainName,$BaseDN" > $null

                foreach ($Tier in @(0,1,2))
                {
                    Set-LapsADReadPasswordPermission -Identity "OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN" -AllowedPrincipals "$DomainNetbiosName\Delegate Tier $Tier Laps Read Password" > $null
                    Set-LapsADResetPasswordPermission -Identity "OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN" -AllowedPrincipals "$DomainNetbiosName\Delegate Tier $Tier Laps Reset Password" > $null
                }
            }

            # ██████╗  ██████╗ ███████╗████████╗
            # ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝
            # ██████╔╝██║   ██║███████╗   ██║
            # ██╔═══╝ ██║   ██║╚════██║   ██║
            # ██║     ╚██████╔╝███████║   ██║
            # ╚═╝      ╚═════╝ ╚══════╝   ╚═╝

            ###########
            # Accounts
            ###########

            $EmptyGroups =
            @(
                'Pre-Windows 2000 Compatible Access'
                'Schema Admins',
                'Enterprise Admins'
            )

            # Remove members
            foreach ($Group in $EmptyGroups)
            {
                foreach ($Member in (Get-ADGroupMember -Identity $Group))
                {
                    if ((ShouldProcess @WhatIfSplat -Message "Removing `"$($Member.Name)`" from `"$Group`"." @VerboseSplat))
                    {
                        if ($Group -eq 'Pre-Windows 2000 Compatible Access' -and
                            $Member.Name -eq 'Authenticated Users')
                        {
                            net localgroup "Pre-Windows 2000 Compatible Access" "Authenticated Users" /delete > $null
                        }
                        else
                        {
                            Remove-ADPrincipalGroupMembership -Identity $Member.DistinguishedName -MemberOf $Group -Confirm:$false
                        }
                    }
                }
            }

            $Administrator = Get-ADUser -Filter 'Name -eq "administrator"' -SearchBase "CN=Users,$BaseDN" -SearchScope OneLevel -Properties AccountNotDelegated

            # Set administrator account sensitive and cannot be delegated
            if (($Administrator | Select-Object -ExpandProperty AccountNotDelegated) -ne $true -and
                (ShouldProcess @WhatIfSplat -Message "Setting administrator account sensitive and cannot be delegated." @VerboseSplat))
            {
                $Administrator | Set-ADUser -AccountNotDelegated $true
            }

            #######
            # Misc
            #######

            # Protect Domain Controllers OU from accidental deletion
            if (-not (Get-ADObject "OU=Domain Controllers,$BaseDN" -Properties ProtectedFromAccidentalDeletion).ProtectedFromAccidentalDeletion -and
                (ShouldProcess @WhatIfSplat -Message "Protecting Domain Controllers OU from accidental deletion." @VerboseSplat))
            {
                Set-ADObject "OU=Domain Controllers,$BaseDN" -ProtectedFromAccidentalDeletion $true
            }

            # Default site subnet
            if (-not (Get-ADReplicationSubnet -Filter "Name -eq '$DomainNetworkId.0/24'") -and
                (ShouldProcess @WhatIfSplat -Message "Adding subnet `"$DomainNetworkId.0/24`" to `"Default-First-Site-Name`"." @VerboseSplat))
            {
                New-ADReplicationSubnet -Name "$DomainNetworkId.0/24" -Site 'Default-First-Site-Name'
            }

            # Join domain quota
            if ((Get-ADObject -Identity "$BaseDN" -Properties 'ms-DS-MachineAccountQuota' | Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota') -ne 0 -and
                (ShouldProcess @WhatIfSplat -Message "Setting ms-DS-MachineAccountQuota = 0" @VerboseSplat))
            {
                Set-ADObject -Identity $BaseDN -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
            }

            # Register schema mmc
            if (-not (Get-Item -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{333FE3FB-0A9D-11D1-BB10-00C04FC9A3A3}\InprocServer32" -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Registering schmmgmt.dll." @VerboseSplat))
            {
                regsvr32.exe /s schmmgmt.dll
            }

            # Recycle bin
            if (-not (Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" | Select-Object -ExpandProperty EnabledScopes) -and
                (ShouldProcess @WhatIfSplat -Message "Enabling Recycle Bin Feature." @VerboseSplat))
            {
                Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $DomainName -Confirm:$false > $null
            }

            # ██████╗  █████╗  ██████╗██╗  ██╗██╗   ██╗██████╗      ██████╗ ██████╗  ██████╗
            # ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██║   ██║██╔══██╗    ██╔════╝ ██╔══██╗██╔═══██╗
            # ██████╔╝███████║██║     █████╔╝ ██║   ██║██████╔╝    ██║  ███╗██████╔╝██║   ██║
            # ██╔══██╗██╔══██║██║     ██╔═██╗ ██║   ██║██╔═══╝     ██║   ██║██╔═══╝ ██║   ██║
            # ██████╔╝██║  ██║╚██████╗██║  ██╗╚██████╔╝██║         ╚██████╔╝██║     ╚██████╔╝
            # ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝          ╚═════╝ ╚═╝      ╚═════╝

            if ($BackupGpo.IsPresent -and
                (ShouldProcess @WhatIfSplat -Message "Backing up GPOs to `"$env:TEMP\GpoBackup`"" @VerboseSplat))
            {
                # Remove old directory
                Remove-Item -Recurse -Path "$env:TEMP\GpoBackup" -Force -ErrorAction SilentlyContinue

                # Create new directory
                New-Item -Path "$env:TEMP\GpoBackup" -ItemType Directory > $null

                # Export
                foreach($Gpo in (Get-GPO -All | Where-Object { $_.DisplayName.StartsWith($DomainPrefix) }))
                {
                    # Backup gpo
                    $Backup = Backup-GPO -Guid $Gpo.Id -Path "$env:TEMP\GpoBackup"

                    # Replace domain name in site to zone assignment list
                    if ($Backup.DisplayName -match 'Site to Zone Assignment List')
                    {
                        # Get backup filepath
                        $GpReportFile = "$env:TEMP\GpoBackup\{$($Backup.Id)}\gpreport.xml"

                        # Replace domain wildcard with placeholder
                        ((Get-Content -Path $GpReportFile -Raw) -replace "\*\.$($DomainName -replace '\.', '\.')", '%domain_wildcard%') | Set-Content -Path $GpReportFile
                    }

                    # Replace sids in GptTempl.inf
                    if ($Backup.DisplayName -match 'Restrict User Rights Assignment')
                    {
                        $GptTmplFile = "$env:TEMP\GpoBackup\{$($Backup.Id)}\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"

                        $GptContent = Get-Content -Path $GptTmplFile -Raw
                        $GptContent = $GptContent -replace "\*$((Get-ADUser  -Identity 'JoinDomain').SID.Value)", '%join_domain%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Domain Admins').SID.Value)", '%domain_admins%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Enterprise Admins').SID.Value)", '%enterprise_admins%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Schema Admins').SID.Value)", '%schema_admins%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 0 - Admins').SID.Value)", '%tier_0_admins%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 0 - Computers').SID.Value)", '%tier_0_computers%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 0 - Users').SID.Value)", '%tier_0_users%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 1 - Admins').SID.Value)", '%tier_1_admins%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 1 - Computers').SID.Value)", '%tier_1_computers%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 1 - Users').SID.Value)", '%tier_1_users%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 2 - Admins').SID.Value)", '%tier_2_admins%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 2 - Computers').SID.Value)", '%tier_2_computers%'
                        $GptContent = $GptContent -replace "\*$((Get-ADGroup -Identity 'Tier 2 - Users').SID.Value)", '%tier_2_users%'

                        Set-Content -Path $GptTmplFile -Value $GptContent
                    }
                }

                foreach($file in (Get-ChildItem -Recurse -Force -Path "$env:TEMP\GpoBackup"))
                {
                    if ($file.Attributes.ToString().Contains('Hidden'))
                    {
                        Set-ItemProperty -Path $file.FullName -Name Attributes -Value Normal
                    }
                }
            }

            # ██████╗  █████╗  ██████╗██╗  ██╗██╗   ██╗██████╗     ████████╗███████╗███╗   ███╗██████╗ ██╗      █████╗ ████████╗███████╗███████╗
            # ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██║   ██║██╔══██╗    ╚══██╔══╝██╔════╝████╗ ████║██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝
            # ██████╔╝███████║██║     █████╔╝ ██║   ██║██████╔╝       ██║   █████╗  ██╔████╔██║██████╔╝██║     ███████║   ██║   █████╗  ███████╗
            # ██╔══██╗██╔══██║██║     ██╔═██╗ ██║   ██║██╔═══╝        ██║   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║     ██╔══██║   ██║   ██╔══╝  ╚════██║
            # ██████╔╝██║  ██║╚██████╗██║  ██╗╚██████╔╝██║            ██║   ███████╗██║ ╚═╝ ██║██║     ███████╗██║  ██║   ██║   ███████╗███████║
            # ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝            ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝

            if ($BackupTemplates.IsPresent -and
                (ShouldProcess @WhatIfSplat -Message "Backing up certificate templates to `"$env:TEMP\TemplatesBackup`"" @VerboseSplat))
            {
                # Remove old directory
                Remove-Item -Path "$env:TEMP\TemplatesBackup" -Recurse -Force -ErrorAction SilentlyContinue

                # Create new directory
                New-Item -Path "$env:TEMP\TemplatesBackup" -ItemType Directory > $null

                # Export
                foreach($Template in (Get-ADObject -Filter "Name -like '$DomainPrefix*' -and objectClass -eq 'pKICertificateTemplate'" -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -SearchScope Subtree -Property *))
                {
                    # Remove domain prefix
                    $Name = $Template.Name.Replace($DomainPrefix, '')

                    # Export template to json files
                    $Template | Select-Object -Property @{ n = 'Name' ; e = { $Name }}, @{ n = 'DisplayName'; e = { $_.DisplayName.Replace("$DomainPrefix ", '') }}, flags, revision, *PKI*, @{ n = 'msPKI-Template-Minor-Revision' ; e = { 1 }} -ExcludeProperty 'msPKI-Template-Minor-Revision', 'msPKI-Cert-Template-OID' | ConvertTo-Json | Out-File -FilePath "$env:TEMP\TemplatesBackup\$($Name)_tmpl.json"

                    # Export acl to json files
                    # Note: Convert to/from csv for ToString on all enums
                    Get-Acl -Path "AD:$($Template.DistinguishedName)" | Select-Object -ExpandProperty Access | Select-Object -Property *, @{ n = 'IdentityReference'; e = { $_.IdentityReference.ToString().Replace($DomainNetbiosName, '%domain%') }} -ExcludeProperty 'IdentityReference' | ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json | Out-File -FilePath "$env:TEMP\TemplatesBackup\$($Name)_acl.json"
                }
            }
        }

        # ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███╗   ██╗
        # ██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║
        # ██████╔╝█████╗     ██║   ██║   ██║██████╔╝██╔██╗ ██║
        # ██╔══██╗██╔══╝     ██║   ██║   ██║██╔══██╗██║╚██╗██║
        # ██║  ██║███████╗   ██║   ╚██████╔╝██║  ██║██║ ╚████║
        # ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

        # Check size
        if ($UpdatedObjects.Count -gt 0)
        {
            $Result += @{ ComputersAddedToGroup = $UpdatedObjects }
        }

        if ($Result.Count -gt 0)
        {
            Write-Output -InputObject $Result
        }
    }
}

Process
{
    # ██████╗ ██████╗  ██████╗  ██████╗███████╗███████╗███████╗
    # ██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝██╔════╝
    # ██████╔╝██████╔╝██║   ██║██║     █████╗  ███████╗███████╗
    # ██╔═══╝ ██╔══██╗██║   ██║██║     ██╔══╝  ╚════██║╚════██║
    # ██║     ██║  ██║╚██████╔╝╚██████╗███████╗███████║███████║
    # ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝╚══════╝╚══════╝

    # Initialize
    $InvokeSplat = @{}

    # Setup remote
    if ($Session -and $Session.State -eq 'Opened')
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_GetBaseDN.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetAce.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            # Mandatory parameters
            $DomainName = $Using:DomainName
            $DomainNetbiosName = $Using:DomainNetbiosName
            $DomainLocalPassword = $Using:DomainLocalPassword
            $DomainNetworkId = $Using:DomainNetworkId

            # DNS
            $DNSReverseLookupZone = $Using:DNSReverseLookupZone
            $DNSRefreshInterval = $Using:DNSRefreshInterval
            $DNSNoRefreshInterval = $Using:DNSNoRefreshInterval
            $DNSScavengingInterval = $Using:DNSScavengingInterval
            $DNSScavengingState = $Using:DNSScavengingState

            # DHCP
            $DHCPScope = $Using:DHCPScope
            $DHCPScopeStartRange = $Using:DHCPScopeStartRange
            $DHCPScopeEndRange = $Using:DHCPScopeEndRange
            $DHCPScopeSubnetMask = $Using:DHCPScopeSubnetMask
            $DHCPScopeDefaultGateway = $Using:DHCPScopeDefaultGateway
            $DHCPScopeDNSServer = $Using:DHCPScopeDNSServer
            $DHCPScopeLeaseDuration = $Using:DHCPScopeLeaseDuration

            # Switches
            $RestrictDomain = $Using:RestrictDomain
            $EnableIPSec = $Using:EnableIPSec

            $BackupGpo = $Using:BackupGpo
            $BackupTemplates = $Using:BackupTemplates
            $RemoveAuthenticatedUsersFromUserGpos = $Using:RemoveAuthenticatedUsersFromUserGpos
        }

        # Set remote splat
        $InvokeSplat.Add('Session', $Session)
    }
    else # Setup locally
    {
        Check-Continue -Message "Invoke locally?"

        # Load functions
        Invoke-Command -ScriptBlock `
        {
            try
            {
                # f_ShouldProcess.ps1 loaded in Begin
                . $PSScriptRoot\f_TryCatch.ps1
                . $PSScriptRoot\f_GetBaseDN.ps1
                . $PSScriptRoot\f_SetAce.ps1
            }
            catch [Exception]
            {
                throw $_
            }

        } -NoNewScope

        # Set local splat
        $InvokeSplat.Add('NoNewScope', $true)
    }

    # Invoke
    try
    {
        # Run main
        $Result = Invoke-Command @InvokeSplat -ScriptBlock $MainScriptBlock -ErrorAction Stop
    }
    catch [Exception]
    {
        throw "$_ $( $_.ScriptStackTrace)"
    }

    # ██████╗ ███████╗███████╗██╗   ██╗██╗  ████████╗
    # ██╔══██╗██╔════╝██╔════╝██║   ██║██║  ╚══██╔══╝
    # ██████╔╝█████╗  ███████╗██║   ██║██║     ██║
    # ██╔══██╗██╔══╝  ╚════██║██║   ██║██║     ██║
    # ██║  ██║███████╗███████║╚██████╔╝███████╗██║
    # ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═╝

    if ($Result)
    {
        $ResultParsed = @{}

        foreach($Row in $Result)
        {
            if ($Row -is [Hashtable])
            {
                foreach($Item in $Row.GetEnumerator())
                {
                    switch ($Item.Key)
                    {
                        'Host'    { $Item.Value | Write-Host }
                        'Verbose' { $Item.Value | Write-Verbose @VerboseSplat }
                        'Warning' { $Item.Value | Write-Warning }
                        'Error'   { $Item.Value | Write-Error }

                        default
                        {
                            $ResultParsed.Add($Item.Key, $Item.Value)
                        }
                    }
                }
            }
            else
            {
                Write-Warning -Message 'Unexpected result:'
                Write-Host -Object $Row
            }
        }

        Write-Output -InputObject $ResultParsed
    }
}

End
{
}

# SIG # Begin signature block
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXdEl6J4obG++oUj0AB9BObuG
# c2ygghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMzA5MDcxODU5NDVaFw0yODA5MDcx
# OTA5NDRaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA0cNYCTtcJ6XUSG6laNYH7JzFfJMTiQafxQ1dV8cjdJ4ysJXAOs8r
# nYot9wKl2FlKI6eMT6F8wRpFbqKqmTpElxzM+fzknD933uEBLSAul/b0kLlr6PY2
# oodJC20VBAUxthFUYh7Fcni0dwz4EjXJGxieeDDLZYRT3IR6PzewaWhq1LXY3fhe
# fYQ1Q2nqHulVWD1WgucgIFEfUJCWcOvfmJBE+EvkNPVoKAqFxJ61Z54z8y6tIjdK
# 3Ujq4bgROQqLsFMK+mII1OqcLRKMgWkVIS9nHfFFy81VIMvfgaOpoSVLatboxAnO
# mn8dusJA2DMH6OL03SIBb/FwE7671sjtGuGRp+nlPnkvoVqFET9olZWDxlGOeeRd
# Tc3jlcEPb9XLpiGjlQfMfk4ycSwraJqn1cYDvSXh3K6lv0OeSLa/VQRlEpOmttKB
# EI/eFMK76DZpGxFvv1xOg1ph3+01hCboOXePu9qSNk5hnIrBEb9eqks3r5ZDfrlE
# wjFUhd9kLe2UKEaHK7HI9+3x1WhTgNRKWzKzqUcF9aVlpDQRplqbUMJEzMxzRUIk
# 01NDqw46gjUYet6VnIPqnQAe2bLWqDMeL3X6P7cAHxw05yONN51MqyBFdYC1MieY
# uU4MOoIfIN6M6vEGn7avjw9a4Xpfgchtty2eNgIRg+KuJ3Xxtd1RDjUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFFjQBHg94o+OtZeRxQoH0mKFzMApMA0G
# CSqGSIb3DQEBCwUAA4ICAQBSglLs0PCn7g36iGRvqXng/fq+6nL3ZSLeLUXSDoFX
# KhJ3K6wFSiHBJtBYtWc7OnHIbIg1FFFAi5GIP56MMwmN4NoY0DrBN0Glh4Jq/lhu
# iah5zs/9v/aUvtwvBD4NVX0G/wJuRuX697UQZrtkWninB46BMPU+gEg1ctn0V4zQ
# 3fazrcmJqD9xIwKlOXsvxOAO5OJ51ucdsubD6QkJa++4bGd5HhoC8/O18mxz6YYa
# gOnXWJObybkwdkDC9MUjy5wZNAv48DkUM+OArbfM3ZpfcAVTnDrfuzpoOKTkcdgb
# N+4VXJC/ly1D98f+IpEOw1UItX8Hg67WfU9sXcIY+fghzHPHF864vp2F/G75i02M
# oqeRpeO3guwum3DbKCkKts5S1QXnE7pmeqe4U595jCVhELeB6ifrvj0ulSlOU5GE
# twNY5VL0T3cHegBmtQXFfQoT6vboF6m9I7kVlKGT4WI8M/UQYCQ2ZP3HTjdSHt9U
# cJslGMqDxhbkGLH49ESP5ghbRddll24dsw0dF96lOIEmhB01UNIz40TonraK3cku
# Jdnrh/2fHYbycGHjkowiMUJQaihbZBRKvBHhrM7OuQ96M9g8Gk2RCIqdX0lO8n2y
# S8fnzEoWe8FVwE5bgA5Nwl6iYdoszubYgh+siVMe2EFaUh0DXXpbQ3JxjMGe5qVK
# 1zCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUu
# ySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8
# Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0M
# G+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldX
# n1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVq
# GDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFE
# mjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6
# SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXf
# SwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b23
# 5kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ
# 6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRp
# L5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADAN
# BgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVe
# qRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3vot
# Vs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum
# 6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJ
# aISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQIC
# EAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAw
# MDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQw
# OTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2
# EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuA
# hIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQ
# h0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7Le
# Sn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw5
# 4qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP2
# 9p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjF
# KfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHt
# Qr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpY
# PtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4J
# duyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2
# mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIB
# fmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb
# 122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+r
# T4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQ
# sl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsK
# RcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKn
# N36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSe
# reU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no
# 8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcW
# oWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInw
# AM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f
# 5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEz
# MjM1OTU5WjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# IDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAo1NFhx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6
# OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp
# 52n+W8PWKyAcwZeUtKVQgfLPywemMGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF
# 6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G4
# 5lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7p
# Be6q9iT1HbybHLK3X9/w7nZ9MZllR1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAs
# NJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU
# 6mIIE9NpHnxkTZ0P387RXoyqq1AVybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwK
# WEwAPoVpdceDZNZ1zY8SdlalJPrXxGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFx
# smxxrz64b5bV4RAT/mFHCoz+8LbH1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbR
# yV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+BmbTO77665E42FEHypS34lCh8zrTioPL
# QHsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4E
# FgQUpbbvE+fvzdBkodVWqWUxo97V40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1
# NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCp
# tZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX
# 4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoF
# eoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+nji
# kxp2oml101DkRBK+IA2eqUTQ+OVJdwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBB
# Jt3eWpdPM43UjXd9dUWhpVgmagNF3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJ
# A+rUkTfvTVLzyWAhxFZH7doRS4wyw4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcs
# QdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE
# 5jreODsHXjlY9HxzMVWggBHLFAx+rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS
# 2Dq4sUaGa7oX/cR3bBVsrquvczroSUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3
# CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUb
# c7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQQYoxggXpMIIF5QIBATAkMBAxDjAMBgNV
# BAMMBUowTjdFAhB0XMs0val9mEnBo5ekK6KYMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRxHbpq
# V2ruFtFW+kjeYn/Xh65ulzANBgkqhkiG9w0BAQEFAASCAgCVwCYof6+VgZSNE32J
# 18N6Mm0z1io3Jc6FlkGlyCIebOqStREakulW3GbwR27HUZ6LEa42RCfM6Iu5jv6b
# sVoHqHtUEvne0N/h4yZg6JO7/HyuCF5AN6Vie+XlXa6XnlCpj5TMCIisyQKqoWEb
# +kJoD9eBfylX7AvFCqMgKh9tUX5ZHS/1I0nKjalut+MSlwL2yHA0EdDzLikI+BJn
# 81OCUpkVw4JLsMAcO/XZ0Qcx5FiyG8RpFeAn4d2eYx5sqRATxIJDZAywiCc8SkBr
# BwqFWf99kBixo+Br3z1nHzU7/bjG63XXinnoaFi49N1pnfB9Z7EKN2RmYsiV+dDw
# DQjfy/DZdkvjE9gi6ZMyJjGWXWYn1Xg2VPsJ+c1LfvVWXe8EcrK9rLDJ3/0SJyD5
# RkWeYcTzRG08Jx32WbpFI6SiZMu4LQlPaJqff4eieSbFOzb1NtUYEMLaX0IPSD/e
# dVoHXaq1wMDCEqhw/Kz8ix5FDVoUxF7HHQ0nmQvAbIJaSeJy/TwgJgZYfWKAqs1C
# /GDifhlqSvtHqpUDGNQiiNavY0qFJIoSH8rV3qa+5MKDY5JeuopgZzQKEMMpIcDo
# LMJNYBJZ6LD9bLD1asQZatMQKaQmksxY+JM/i6OdXAcLHjQWiu7Ta+y8Wqi3DESt
# 93gy8w7APMJe5WhCHZfUHemkj6GCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA5MTkxNjAw
# MDNaMC8GCSqGSIb3DQEJBDEiBCAmijIkKW2PZGAeDc3Wqb5TnCO7QbojcuyyL3/C
# 8DVv3DANBgkqhkiG9w0BAQEFAASCAgAWj7hqUQrHKMV8Toop+UddeTCXWFklxuWS
# YPmZ/yXKYaQ2L5isIKPwWqSDJhVgSn6VrBOFdt+Su6Vt+AN3EgGosJcnHI3menLp
# YxWGAffR/kEdEHgnLj4RPXOLMpnx8Sashf8ckFtq5nOzRmYKA6KO8IyDTiLzOrib
# A6JBbpA3gj2wiLsh28o0ft9bt8eR4SEdL1gyZmx7dKXGNc6uBaDxSNrANzFps61t
# wtyTEzvBaIH9UQeOdRhq6gbPiFmOaBtuNb5NMyP/Edf6cxnf8B0KBJgFEXdKQyQy
# 9i97aLXEJkNNRJSBcJSkqQ7aMoD+cCoBQNndO7iA/YUEGaLuaT9PpRv81VHneL+O
# Wv+bDo51MrfLJmlGtGafaf6vebdt5KdWI49xnEwVIrgXQacCuxKFSLcqC1LAJeXg
# lKJo/OIUpUGlEjfLXWMTDs1j4JxqK3hz+M7hhzHR+KabY7CM0xIzEza3QaFGeiB1
# q1PwDlR/4ct47wHabrrGl2C1UwwXabBcatDdaaqdojG6yzHRITrL2HXSt3xIvJaw
# +ax+dazD5C/7wTRYBgSqtTiV/P8oO3xgEkXl2+DIZGMSrDw6gj4hjdtHIa4zvz5b
# w3Rk8edMDr/u3Qcjmb/1kNcqJ2uX1Runz2V0xVrg3ksil0vIb0aeapxCyAqjDC+v
# Jeq2EWmtwg==
# SIG # End signature block
