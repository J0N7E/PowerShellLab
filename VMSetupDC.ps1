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
    [ValidateSet($true, $false)]
    [String]$RestrictDomain,

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
            DHCPScopeStartRange = "$DomainNetworkId.154"
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
        $Result = @{}
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
                    'MSFT Internet Explorer 11 21H2 (Windows Server 2022) - Computer'
                )
                UserBaseline =
                @(
                    'MSFT Internet Explorer 11 21H2 (Windows Server 2022) - User'
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
                    'MSFT Internet Explorer 11 21H2 - Computer'
                )
                UserBaseline =
                @(
                    'MSFT Internet Explorer 11 21H2 - User'
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

        # Check if RSAT-ADCS-Mgmt is installed
        if (((Get-WindowsFeature -Name RSAT-ADCS-Mgmt).InstallState -notmatch 'Install') -and
            (ShouldProcess @WhatIfSplat -Message "Installing RSAT-ADCS-Mgmt feature." @VerboseSplat))
        {
            Install-WindowsFeature -Name RSAT-ADCS-Mgmt > $null
        }

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
            $Result.Add('WaitingForReboot', $true)

            # Output result
            Write-Output -InputObject $Result

            # Restart message
            Write-Warning -Message "Rebooting `"$ENV:ComputerName`", rerun this script to continue setup..."

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
                $Server = @{}

                # Define server records to get
                $ServerNames = @('ADFS', 'AS', 'WAP', 'curity')

                foreach ($Name in $ServerNames)
                {
                    # Get dns record
                    $ServerHostName = Get-DnsServerResourceRecord -ZoneName $DomainName -RRType A | Where-Object { $_.HostName -like "*$Name*" -and $_.Timestamp -notlike $null } | Select-Object -ExpandProperty HostName -First 1

                    if ($ServerHostName)
                    {
                        $Server.Add($Name, $ServerHostName)
                    }
                }

                # Initialize
                $DnsRecords = @()

                # Check if AS server exist
                if ($Server.AS)
                {
                    $DnsRecords += @{ Name = 'pki';                     Type = 'CNAME';  Data = "$($Server.AS).$DomainName." }
                }

                # Check if ADFS server exist
                if ($Server.ADFS)
                {
                    $DnsRecords += @{ Name = 'adfs';                    Type = 'A';      Data = "$DomainNetworkId.150" }
                    $DnsRecords += @{ Name = 'certauth.adfs';           Type = 'A';      Data = "$DomainNetworkId.150" }
                    $DnsRecords += @{ Name = 'enterpriseregistration';  Type = 'A';      Data = "$DomainNetworkId.150" }
                }

                # Check if WAP server exist
                if ($Server.WAP)
                {
                    $DnsRecords += @{ Name = 'wap';                     Type = 'A';      Data = "$DomainNetworkId.100" }
                }

                # Check if UBU server exist
                if ($Server.curity)
                {
                    $DnsRecords += @{ Name = 'curity';                  Type = 'CNAME';  Data = "$($Server.AS).$DomainName." }
                }

                foreach($Rec in $DnsRecords)
                {
                    $ResourceRecord = Get-DnsServerResourceRecord -ZoneName $DomainName -Name $Rec.Name -RRType $Rec.Type -ErrorAction SilentlyContinue

                    switch($Rec.Type)
                    {
                        'A'
                        {
                            $RecordType = @{ A = $true; IPv4Address = $Rec.Data; }
                            $RecordData = $ResourceRecord.RecordData.IPv4Address
                        }
                        'CNAME'
                        {
                            $RecordType = @{ CName = $true; HostNameAlias = $Rec.Data; }
                            $RecordData = $ResourceRecord.RecordData.HostnameAlias
                        }
                    }

                    if ($RecordData -ne $Rec.Data -and
                        (ShouldProcess @WhatIfSplat -Message "Adding $($Rec.Type) `"$($Rec.Name)`" -> `"$($Rec.Data)`"." @VerboseSplat))
                    {
                        Add-DnsServerResourceRecord -ZoneName $DomainName -Name $Rec.Name @RecordType
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
                    @{ Name = "WAP";    IPAddress = "$DomainNetworkId.100"; }
                    @{ Name = "ADFS";   IPAddress = "$DomainNetworkId.150"; }
                    @{ Name = "AS";     IPAddress = "$DomainNetworkId.200"; }
                    @{ Name = "curity"; IPAddress = "$DomainNetworkId.250"; }
                )

                foreach($Reservation in $DhcpReservations)
                {
                    # Set reservation name
                    $ReservationName = "$($Server.Item($Reservation.Name)).$DomainName"

                    # Get clientId from dhcp active leases
                    $ClientId = (Get-DhcpServerv4Lease -ScopeID $DHCPScope | Where-Object { $_.HostName -eq $ReservationName -and $_.AddressState -eq 'Active' } | Sort-Object -Property LeaseExpiryTime | Select-Object -Last 1).ClientId

                    # Check if client id exist
                    if ($ClientId)
                    {
                        $CurrentReservation = Get-DhcpServerv4Reservation -ScopeId $DHCPScope | Where-Object { $_.Name -eq $ReservationName -and $_.IPAddress -eq $Reservation.IPAddress }

                        if ($CurrentReservation)
                        {
                            if ($CurrentReservation.ClientId -ne $ClientId -and
                               (ShouldProcess @WhatIfSplat -Message "Updating DHCP reservation `"$($ReservationName)`" `"$($Reservation.IPAddress)`" to ($ClientID)." @VerboseSplat))
                            {
                                Set-DhcpServerv4Reservation -Name $ReservationName -IPAddress $Reservation.IPAddress -ClientId $ClientID

                                $UpdatedObjects.Add($Server.Item($Reservation.Name), $true)
                            }
                        }
                        elseif (ShouldProcess @WhatIfSplat -Message "Adding DHCP reservation `"$($ReservationName)`" `"$($Reservation.IPAddress)`" for ($ClientId)." @VerboseSplat)
                        {
                            Add-DhcpServerv4Reservation -ScopeId $DHCPScope -Name $ReservationName -IPAddress $Reservation.IPAddress -ClientId $ClientID

                            $UpdatedObjects.Add($Server.Item($Reservation.Name), $true)
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
                #  Name = Name of OU                                               Path = Location of OU

                @{ Name = $DomainName;                                                             Path = "$BaseDN"; }
                @{ Name = $RedirUsr;                                               Path = "OU=$DomainName,$BaseDN"; }
                @{ Name = $RedirCmp;                                               Path = "OU=$DomainName,$BaseDN"; }
            )

            # Tier 0-2 OUs
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

            $OrganizationalUnits += @{   Name = 'Certificate Authority Templates'; Path = "OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"; }
            $OrganizationalUnits += @{   Name = 'Group Managed Service Accounts';  Path = "OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"; }
            $OrganizationalUnits += @{  Name = 'Service Accounts';                 Path = "OU=Tier 0,OU=$DomainName,$BaseDN"; }

            # Server builds
            foreach ($Build in $WinBuilds.GetEnumerator())
            {
                if ($Build.Value.Server)
                {
                    $ServerName = $Build.Value.Server

                    $OrganizationalUnits += @{ Name = $ServerName;                                Path = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Certificate Authorities';   Path = "OU=$ServerName,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Federation Services';       Path = "OU=$ServerName,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Web Servers';               Path = "OU=$ServerName,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"; }
                }
            }

            #########
            # Tier 1
            #########

            $OrganizationalUnits += @{   Name = 'Group Managed Service Accounts';  Path = "OU=Groups,OU=Tier 1,OU=$DomainName,$BaseDN"; }
            $OrganizationalUnits += @{  Name = 'Service Accounts';                 Path = "OU=Tier 1,OU=$DomainName,$BaseDN"; }

            # Server builds
            foreach ($Build in $WinBuilds.GetEnumerator())
            {
                if ($Build.Value.Server)
                {
                    $ServerName = $Build.Value.Server

                    $OrganizationalUnits += @{ Name = $ServerName;                                Path = "OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Application Servers';       Path = "OU=$ServerName,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"; }
                    $OrganizationalUnits += @{ Name = 'Web Application Proxy';     Path = "OU=$ServerName,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN"; }
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
                            Write-Verbose -Message "Redirecting Computers to OU=$($Ou.Name),$($Ou.Path)" @VerboseSplat
                            redircmp "OU=$($Ou.Name),$($Ou.Path)" > $null
                        }

                        if ($Ou.Name -eq $RedirUsr)
                        {
                            Write-Verbose -Message "Redirecting Users to OU=$($Ou.Name),$($Ou.Path)" @VerboseSplat
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
                @{ Name = 'Admin';            AccountNotDelegated = $true;  Password = 'P455w0rd';  MemberOf = @('Domain Admins', 'Protected Users') }

                # Administrators
                @{ Name = 'Tier0Admin';       AccountNotDelegated = $true;  Password = 'P455w0rd';  MemberOf = @() }
                @{ Name = 'Tier1Admin';       AccountNotDelegated = $true;  Password = 'P455w0rd';  MemberOf = @() }
                @{ Name = 'Tier2Admin';       AccountNotDelegated = $true;  Password = 'P455w0rd';  MemberOf = @() }

                # Service accounts
                @{ Name = 'AzADDSConnector';  AccountNotDelegated = $false; Password = 'PHptNlPKHxL0K355QsXIJulLDqjAhmfABbsWZoHqc0nnOd6p';  MemberOf = @() }

                # Join domain account
                @{ Name = 'JoinDomain';       AccountNotDelegated = $true;  Password = 'P455w0rd';  MemberOf = @() }

                # Users
                @{ Name = 'Alice';            AccountNotDelegated = $true;  Password = 'P455w0rd';  MemberOf = @() }
                @{ Name = 'Bob';              AccountNotDelegated = $true;  Password = 'P455w0rd';  MemberOf = @() }
                @{ Name = 'Eve';              AccountNotDelegated = $true;  Password = 'P455w0rd';  MemberOf = @() }

            )

            foreach ($User in $Users)
            {
                if (-not (Get-ADUser -Filter "Name -eq '$($User.Name)'" -SearchBase "$BaseDN" -SearchScope Subtree -ErrorAction SilentlyContinue) -and
                   (ShouldProcess @WhatIfSplat -Message "Creating user `"$($User.Name)`"." @VerboseSplat))
                {
                    New-ADUser -Name $User.Name -DisplayName $User.Name -SamAccountName $User.Name -UserPrincipalName "$($User.Name)@$DomainName" -EmailAddress "$($User.Name)@$DomainName" -AccountPassword (ConvertTo-SecureString -String $User.Password -AsPlainText -Force) -ChangePasswordAtLogon $false -PasswordNeverExpires $true -Enabled $true -AccountNotDelegated $User.AccountNotDelegated

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
                @{ Filter = "Name -like 'DC*' -and ObjectCategory -eq 'Computer'";  TargetPath = "OU=Domain Controllers,$BaseDN" }

                # Domain Admin
                @{ Filter = "Name -like 'Admin' -and ObjectCategory -eq 'Person'";  TargetPath = "CN=Users,$BaseDN" }

                # Join domain account
                @{ Filter = "Name -like 'JoinDomain' -and ObjectCategory -eq 'Person'";  TargetPath = "CN=Users,$BaseDN" }

                #########
                # Tier 0
                #########

                # Admin
                @{ Filter = "Name -like 'Tier0Admin' -and ObjectCategory -eq 'Person'";  TargetPath = "OU=Administrators,OU=Tier 0,OU=$DomainName,$BaseDN" }

                # Computers
                @{ Filter = "Name -like 'CA*' -and ObjectCategory -eq 'Computer'";  TargetPath = "OU=Certificate Authorities,%ServerPath%,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN" }
                @{ Filter = "Name -like '*ADFS*' -and ObjectCategory -eq 'Computer'";  TargetPath = "OU=Federation Services,%ServerPath%,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN" }
                @{ Filter = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'";  TargetPath = "OU=Web Servers,%ServerPath%,OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN" }

                # Service accounts
                @{ Filter = "Name -like 'Az*' -and ObjectCategory -eq 'Person'";  TargetPath = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN" }
                @{ Filter = "Name -like 'Svc*' -and ObjectCategory -eq 'Person'";  TargetPath = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN" }

                #########
                # Tier 1
                #########

                # Admin
                @{ Filter = "Name -like 'Tier1Admin' -and ObjectCategory -eq 'Person'";  TargetPath = "OU=Administrators,OU=Tier 1,OU=$DomainName,$BaseDN" }

                # Computers
                @{ Filter = "Name -like '*WAP*' -and ObjectCategory -eq 'Computer'";  TargetPath = "OU=Web Application Proxy,%ServerPath%,OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN" }

                #########
                # Tier 2
                #########

                # Admin
                @{ Filter = "Name -like 'Tier2Admin' -and ObjectCategory -eq 'Person'";  TargetPath = "OU=Administrators,OU=Tier 2,OU=$DomainName,$BaseDN" }

                # Computers
                @{ Filter = "Name -like 'WIN*' -and ObjectCategory -eq 'Computer'";  TargetPath = "%WorkstationPath%,OU=Computers,OU=Tier 2,OU=$DomainName,$BaseDN" }

                # Users
                @{ Filter = "(Name -eq 'Alice' -or Name -eq 'Bob' -or Name -eq 'Eve') -and ObjectCategory -eq 'Person'";  TargetPath = "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN" }
            )

            foreach ($Obj in $MoveObjects)
            {
                # Set targetpath
                $TargetPath = $Obj.TargetPath

                # Get object
                $ADObjects = Get-ADObject -Filter $Obj.Filter -SearchBase "OU=$DomainName,$BaseDN" -SearchScope 'Subtree' -Properties cn

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
                            # Skip move
                            Write-Warning -Message "Did'nt find build for $($CurrentObj.Name), skiping move."
                            continue
                        }

                        # Set targetpath with server version
                        if ($Obj.TargetPath -match '%ServerPath%')
                        {
                            $TargetPath = $Obj.TargetPath.Replace('%ServerPath%', "OU=$($WinBuilds.Item($Build).Server)")
                        }

                        # Set targetpath with windows version
                        if ($Obj.TargetPath -match '%WorkstationPath%')
                        {
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
            # MemberFilter      : Filter to get members
            # MemberSearachBase : Where to look for members
            # MemberSearchScope : Base/OneLevel/Subtree to look for members
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
                    Name              = "Tier $Tier - Administrators"
                    Scope             = 'Global'
                    Path              = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like '*' -and ObjectCategory -eq 'Person'"
                    MemberSearchBase  = "OU=Administrators,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                    MemberOf          = @('Protected Users')
                }
            }
#
            # Group Managed Service Accounts
            $DomainGroups +=
            @(
                @{
                    Name                = 'Adfs'
                    Scope               = 'Global'
                    Path                = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members             =
                    @(
                        @{
                            Filter      = "Name -like '*ADFS*' -and ObjectCategory -eq 'Computer'"
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
                    Name              = 'PowerShell'
                    Scope             = 'Global'
                    Path              = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like '*' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                }

                @{
                    Name              = 'AzADSyncSrv'
                    Scope             = 'Global'
                    Path              = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                }

                @{
                    Name              = 'Ndes'
                    Scope             = 'Global'
                    Path              = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                }
            )

            #############
            # Tier 0 + 1
            #############

            foreach($Tier in @(0, 1))
            {
                # All servers
                $DomainGroups +=
                @{
                    Name              = "Tier $Tier - Computers"
                    Scope             = 'Global'
                    Path              = "OU=Computers,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like '*' -and ObjectCategory -eq 'Computer' -and OperatingSystem -like '*Server*'"
                    MemberSearchBase  = "OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                }

                # Server by build
                foreach ($Build in $WinBuilds.GetEnumerator())
                {
                    if ($Build.Value.Server)
                    {
                        $DomainGroups +=
                        @{
                            Name              = "Tier $Tier - $($Build.Value.Server)"
                            Scope             = 'Global'
                            Path              = "OU=Computers,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                            MemberFilter      = "Name -like '*' -and ObjectCategory -eq 'Computer' -and OperatingSystem -like '*Server*' -and OperatingSystemVersion -like '*$($Build.Key)*'"
                            MemberSearchBase  = "OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                            MemberSearchScope = 'Subtree'
                        }
                    }
                }
            }

            #################
            # Tier 0 + 1 + 2
            #################

            foreach($Tier in @(0, 1, 2))
            {
                # All users
                $DomainGroups +=
                @{
                    Name              = "Tier $Tier - Users"
                    Scope             = 'Global'
                    Path              = "OU=Security Roles,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like '*' -and ObjectCategory -eq 'Person'"
                    MemberSearchBase  = "OU=Users,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }
            }

            foreach($Tier in @(0, 1, 2))
            {
                foreach($Computer in (Get-ADObject -SearchBase "OU=Computers,OU=Tier $Tier,OU=$DomainName,$BaseDN" -SearchScope 'Subtree' -Filter "Name -like '*' -and ObjectCategory -eq 'Computer'"))
                {
                    # Local administrator
                    $DomainGroups +=
                    @{
                        Name              = "Tier $Tier - Local Admin - $($Computer.Name)"
                        Scope             = 'Global'
                        Path              = "OU=Local Administrators,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                        MemberOf          = @('Protected Users')
                    }

                    # Rdp access
                    $DomainGroups +=
                    @{
                        Name              = "Tier $Tier - Rdp Access - $($Computer.Name)"
                        Scope             = 'Global'
                        Path              = "OU=Remote Desktop Access,OU=Groups,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                        MemberFilter      = "Name -like '*' -and ObjectCategory -eq 'Person'"
                        MemberSearchBase  = "OU=Users,OU=Tier $Tier,OU=$DomainName,$BaseDN"
                        MemberSearchScope = 'OneLevel'
                    }
                }
            }

            #########
            # Tier 2
            #########

            # All workstations
            $DomainGroups +=
            @{
                Name              = 'Tier 2 - Computers'
                Scope             = 'Global'
                Path              = "OU=Computers,OU=Groups,OU=Tier 2,OU=$DomainName,$BaseDN"
                MemberFilter      = "Name -like '*' -and ObjectCategory -eq 'Computer' -and OperatingSystem -notlike '*Server*'"
                MemberSearchBase  = "OU=Computers,OU=Tier 2,OU=$DomainName,$BaseDN"
                MemberSearchScope = 'Subtree'
            }

            # Workstations by build
            foreach ($Build in $WinBuilds.GetEnumerator())
            {
                if ($Build.Value.Workstation)
                {
                    $DomainGroups +=
                    @{
                        Name              = "Tier 2 - $($Build.Value.Workstation)"
                        Scope             = 'Global'
                        Path              = "OU=Computers,OU=Groups,OU=Tier 2,OU=$DomainName,$BaseDN"
                        MemberFilter      = "Name -like '*' -and ObjectCategory -eq 'Computer' -and OperatingSystem -notlike '*Server*' -and OperatingSystemVersion -like '*$($Build.Key)*'"
                        MemberSearchBase  = "OU=Computers,OU=Tier 2,OU=$DomainName,$BaseDN"
                        MemberSearchScope = 'Subtree'
                    }
                }
            }

            ######################
            # Domain Local Groups
            ######################

            $DomainGroups +=
            @(
                #########
                # Tier 0
                #########

                # Access Control

                @{
                    Name              = 'Delegate Tier 0 Admin Rights'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'Tier 0 - Administrators' -and ObjectCategory -eq 'group'"
                    MemberSearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                @{
                    Name              = 'Delegate Tier 1 Admin Rights'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'Tier 1 - Administrators' -and ObjectCategory -eq 'group'"
                    MemberSearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                @{
                    Name              = 'Delegate Tier 2 Admin Rights'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'Tier 2 - Administrators' -and ObjectCategory -eq 'group'"
                    MemberSearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                # Join domain

                @{
                    Name              = 'Delegate Create Child Computer'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'JoinDomain' -and ObjectCategory -eq 'Person'"
                    MemberSearchBase  = "OU=Users,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                # PKI

                @{
                    Name              = 'Delegate Install Certificate Authority'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'Tier 0 - Administrators' -and ObjectCategory -eq 'Group'"
                    MemberSearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                @{
                    Name              = 'Delegate CRL Publishers'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like 'CA*' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'SubTree'
                }

                # Adfs

                @{
                    Name              = 'Delegate Adfs Container Generic Read'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    Members           =
                    @(
                        @{
                            Filter      = "Name -eq 'Tier 0 - Administrators' -and ObjectCategory -eq 'Group'"
                            SearchBase  = "OU=Security Roles,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                            SearchScope = 'OneLevel'
                        }
                    )
                }

                @{
                    Name              = 'Delegate Adfs Dkm Container Permissions'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'Gmsa Adfs' -and ObjectCategory -eq 'Group'"
                    MemberSearchBase  = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                # AdSync

                @{
                    Name              = 'Delegate AdSync Basic Read Permissions'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'AzADDSConnector' -and ObjectCategory -eq 'Person'"
                    MemberSearchBase  = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                @{
                    Name              = 'Delegate AdSync Password Hash Sync Permissions'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'AzADDSConnector' -and ObjectCategory -eq 'Person'"
                    MemberSearchBase  = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                @{
                    Name              = 'Delegate AdSync msDS Consistency Guid Permissions'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Access Control,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'AzADDSConnector' -and ObjectCategory -eq 'Person'"
                    MemberSearchBase  = "OU=Service Accounts,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                # Certificate Authority Templates

                @{
                    Name              = 'Template ADFS Service Communication'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like '*ADFS*' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                }

                @{
                    Name              = 'Template CEP Encryption'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                }

                @{
                    Name              = 'Template NDES'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'MsaNdes' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                @{
                    Name              = 'Template OCSP Response Signing'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                }

                @{
                    Name              = 'Template SSL'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -like 'AS*' -and ObjectCategory -eq 'Computer'"
                    MemberSearchBase  = "OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberSearchScope = 'Subtree'
                }

                @{
                    Name              = 'Template WHFB Enrollment Agent'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'MsaAdfs' -and ObjectClass -eq 'msDS-GroupManagedServiceAccount'"
                    MemberSearchBase  = "CN=Managed Service Accounts,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                @{
                    Name              = 'Template WHFB Authentication'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'MsaAdfs' -and ObjectClass -eq 'msDS-GroupManagedServiceAccount'"
                    MemberSearchBase  = "CN=Managed Service Accounts,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                @{
                    Name              = 'Template WHFB Authentication'
                    Scope             = 'DomainLocal'
                    Path              = "OU=Certificate Authority Templates,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN"
                    MemberFilter      = "Name -eq 'Domain Users' -and ObjectCategory -eq 'Group'"
                    MemberSearchBase  = "CN=Users,$BaseDN"
                    MemberSearchScope = 'OneLevel'
                }

                #########
                # Tier 1
                #########

                #########
                # Tier 2
                #########
            )

            ###############
            # Build groups
            ###############

            foreach($Group in $DomainGroups)
            {
                # Check if group managed service account
                $IsGmsa = ($Group.Path -match 'OU=Group Managed Service Accounts')

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
                    $ADGroup = TryCatch { New-ADGroup -Name $GroupName -DisplayName $GroupName -Path $Group.Path -GroupScope $Group.Scope -GroupCategory Security -PassThru }
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
                            $Msa = New-ADServiceAccount -Name "Msa$($Group.Name)" -SamAccountName "Msa$($Group.Name)" -DNSHostName "Msa$($Group.Name).$DomainName" -PrincipalsAllowedToRetrieveManagedPassword "$($ADGroup.DistinguishedName)"
                        }

                        if($Msa -and $ADGroup.DistinguishedName -notin $Msa.PrincipalsAllowedToRetrieveManagedPassword -and
                           (ShouldProcess @WhatIfSplat -Message "Allow `"$GroupName`" to retrieve `"Msa$($Group.Name)`" password. " @VerboseSplat))
                        {
                            Set-ADServiceAccount -Identity "$($Msa.Name)" -PrincipalsAllowedToRetrieveManagedPassword @($Msa.PrincipalsAllowedToRetrieveManagedPassword + $ADGroup.DistinguishedName)
                        }
                    }

                    # Check if group should be member of other groups
                    if ($Group.MemberOf)
                    {
                        # Itterate other groups
                        foreach($Name in $Group.MemberOf)
                        {
                            # Get other group
                            $OtherGroup = TryCatch { Get-ADGroup -Filter "Name -eq '$Name'" -Properties Member }

                            # Check if member of other group
                            if (($OtherGroup -and -not $OtherGroup.Member.Where({ $_ -match $ADGroup.Name })) -and
                                (ShouldProcess @WhatIfSplat -Message "Adding `"$($ADGroup.Name)`" to `"$Name`"." @VerboseSplat))
                            {
                                # Add group to othergroup
                                Add-ADPrincipalGroupMembership -Identity $ADGroup -MemberOf @("$Name")
                            }
                        }
                    }

                    # Check if group should have members
                    if ($Group.Members)
                    {
                        foreach ($Members in $Group.Members)
                        {
                            # Check if filters exist
                            if ($Members.Filter -and $Members.SearchScope -and $Members.SearchBase)
                            {
                                # Get members
                                foreach($NewMember in (TryCatch { Get-ADObject -Filter $Members.Filter -SearchScope $Members.SearchScope -SearchBase $Members.SearchBase }))
                                {
                                    # Check if member is part of group
                                    if ((-not $ADGroup.Member.Where({ $_ -match $NewMember.Name })) -and
                                        (ShouldProcess @WhatIfSplat -Message "Adding `"$($NewMember.Name)`" to `"$($ADGroup.Name)`"." @VerboseSplat))
                                    {
                                        # Add new member
                                        Add-ADPrincipalGroupMembership -Identity $NewMember -MemberOf @("$($ADGroup.Name)")

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

            #  █████╗ ██████╗ ███████╗███████╗
            # ██╔══██╗██╔══██╗██╔════╝██╔════╝
            # ███████║██║  ██║█████╗  ███████╗
            # ██╔══██║██║  ██║██╔══╝  ╚════██║
            # ██║  ██║██████╔╝██║     ███████║
            # ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚══════╝

            $MsaAdfs  = Get-ADServiceAccount -Identity 'MsaAdfs' -Properties PrincipalsAllowedToDelegateToAccount
            $GmsaAdfs = Get-ADGroup -Filter "Name -eq 'Gmsa Adfs'" -SearchBase "OU=Group Managed Service Accounts,OU=Groups,OU=Tier 0,OU=$DomainName,$BaseDN" -SearchScope OneLevel

            # PrincipalsAllowedToDelegateToAccount

            if ($GmsaAdfs.DistinguishedName -notin $MsaAdfs.PrincipalsAllowedToDelegateToAccount -and
                (ShouldProcess @WhatIfSplat -Message "Allow `"$($GmsaAdfs.Name)`" to delegate to MsaAdfs. " @VerboseSplat))
            {
                Set-ADServiceAccount -Identity 'MsaAdfs' -PrincipalsAllowedToDelegateToAccount @($MsaAdfs.PrincipalsAllowedToDelegateToAccount + $GmsaAdfs.DistinguishedName)
            }

            # Add containers

            if (-not (Get-ADObject -Filter "Name -eq 'ADFS' -and ObjectCategory -eq 'Container'" -SearchBase "CN=Microsoft,CN=Program Data,$BaseDN" -SearchScope 'OneLevel') -and
                (ShouldProcess @WhatIfSplat -Message "Adding Adfs Container." @VerboseSplat))
            {
                New-ADObject -Name "ADFS" -Path "CN=Microsoft,CN=Program Data,$BaseDN" -Type Container
            }

            $AdfsGuidContainer = Get-ADObject -Filter "Name -like '*'" -SearchBase "CN=ADFS,CN=Microsoft,CN=Program Data,$BaseDN" -SearchScope OneLevel

            if (-not $AdfsGuidContainer -and
                (ShouldProcess @WhatIfSplat -Message "Adding Adfs Guid Container." @VerboseSplat))
            {
                $AdfsGuidContainer = New-ADObject -Name ([Guid]::NewGuid().Guid) -Path "CN=ADFS,CN=Microsoft,CN=Program Data,$BaseDN" -Type Container -PassThru
            }

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
                @{
                   IdentityReference        = "$DomainNetbiosName\Delegate Create Child Computer";
                   ActiveDirectoryRights    = 'CreateChild';
                   AccessControlType        = 'Allow';
                   ObjectType               = $SchemaID['computer'];
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                }

                @{
                   IdentityReference        = "$DomainNetbiosName\Delegate Create Child Computer";
                   ActiveDirectoryRights    = 'CreateChild';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'Descendents';
                   InheritedObjectType      = $SchemaID['computer'];
                }
            )

            Set-Ace -DistinguishedName "OU=$RedirCmp,OU=$DomainName,$BaseDN" -AceList $CreateChildComputer

            ################################
            # Install Certificate Authority
            ################################

            $InstallCertificateAuthority =
            @(
                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate Install Certificate Authority";
                    ActiveDirectoryRights = 'GenericAll';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'All';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                }
            )

            Set-Ace -DistinguishedName "CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -AceList $InstallCertificateAuthority

            $AddToGroup =
            @(
                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate Install Certificate Authority";
                    ActiveDirectoryRights = 'ReadProperty, WriteProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = $SchemaID['member'];
                    InheritanceType       = 'All';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                }
            )

            # Set R/W on member object
            Set-Ace -DistinguishedName "CN=Cert Publishers,CN=Users,$BaseDN" -AceList $AddToGroup
            Set-Ace -DistinguishedName "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$BaseDN" -AceList $AddToGroup

            ##############################
            # Adfs Container Generic Read
            ##############################

            $AdfsContainerGenericRead =
            @(
                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate Adfs Container Generic Read";
                    ActiveDirectoryRights = 'GenericRead';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'All';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                }
            )

            Set-Ace -DistinguishedName "CN=ADFS,CN=Microsoft,CN=Program Data,$BaseDN" -AceList $AdfsContainerGenericRead -Owner "$DomainNetbiosName\Delegate Adfs Container Generic Read"

            #################################
            # Adfs Dkm Container Permissions
            #################################

            $AdfsDkmContainerPermissions =
            @(
                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate Adfs Dkm Container Permissions";
                    ActiveDirectoryRights = 'CreateChild, WriteProperty, DeleteTree, GenericRead, WriteDacl, WriteOwner';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'All';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                }
            )

            Set-Ace -DistinguishedName $AdfsGuidContainer.DistinguishedName -AceList $AdfsDkmContainerPermissions -Owner "$DomainNetbiosName\Delegate Adfs Dkm Container Permissions"

            ################################
            # AdSync Basic Read Permissions
            ################################

            $AdSyncBasicReadPermissions =
            @(
                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                    ActiveDirectoryRights = 'ReadProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['contact'];
                }

                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                    ActiveDirectoryRights = 'ReadProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['user'];
                }

                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                    ActiveDirectoryRights = 'ReadProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['group'];
                }

                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                    ActiveDirectoryRights = 'ReadProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['device'];
                }

                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                    ActiveDirectoryRights = 'ReadProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['computer'];
                }

                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                    ActiveDirectoryRights = 'ReadProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['inetOrgPerson'];
                }

                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Basic Read Permissions";
                    ActiveDirectoryRights = 'ReadProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = '00000000-0000-0000-0000-000000000000';
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['foreignSecurityPrincipal'];
                }
            )

            Set-Ace -DistinguishedName "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN" -AceList $AdSyncBasicReadPermissions

            ########################################
            # AdSync Password Hash Sync Permissions
            ########################################

            $AdSyncPasswordHashSyncPermissions =
            @(
                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Password Hash Sync Permissions";
                    ActiveDirectoryRights = 'ExtendedRight';
                    AccessControlType     = 'Allow';
                    ObjectType            = $AccessRight['Replicating Directory Changes All'];
                    InheritanceType       = 'None';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                }

                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync Password Hash Sync Permissions";
                    ActiveDirectoryRights = 'ExtendedRight';
                    AccessControlType     = 'Allow';
                    ObjectType            = $AccessRight['Replicating Directory Changes'];
                    InheritanceType       = 'None';
                    InheritedObjectType   = '00000000-0000-0000-0000-000000000000';
                }
            )

            Set-Ace -DistinguishedName "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN" -AceList $AdSyncPasswordHashSyncPermissions

            ###########################################
            # AdSync MsDs Consistency Guid Permissions
            ###########################################

            $AdSyncMsDsConsistencyGuidPermissions =
            @(
                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync MsDs Consistency Guid Permissions";
                    ActiveDirectoryRights = 'ReadProperty, WriteProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = $SchemaID['mS-DS-ConsistencyGuid'];
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['user'];
                }

                @{
                    IdentityReference     = "$DomainNetbiosName\Delegate AdSync MsDs Consistency Guid Permissions";
                    ActiveDirectoryRights = 'ReadProperty, WriteProperty';
                    AccessControlType     = 'Allow';
                    ObjectType            = $SchemaID['mS-DS-ConsistencyGuid'];
                    InheritanceType       = 'Descendents';
                    InheritedObjectType   = $SchemaID['group'];
                }
            )

            Set-Ace -DistinguishedName "OU=Users,OU=Tier 2,OU=$DomainName,$BaseDN" -AceList $AdSyncMsDsConsistencyGuidPermissions
            Set-Ace -DistinguishedName "CN=AdminSDHolder,CN=System,$BaseDN" -AceList $AdSyncMsDsConsistencyGuidPermissions

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
                    $GpReport = "$($Gpo.FullName)\gpreport.xml"

                    # Get gpo name from xml
                    $GpReportXmlName = (Select-Xml -Path $GpReport -XPath '/').Node.GPO.Name

                    if (-not $GpReportXmlName.StartsWith('MSFT'))
                    {
                        if (-not $GpReportXmlName.StartsWith($DomainPrefix))
                        {
                            $GpReportXmlName = "$DomainPrefix - $($GpReportXmlName.Remove(0, $GpReportXmlName.IndexOf('-') + 2))"
                        }

                        # Check if intranet gpo
                        if ($GpReportXmlName -match 'Computer - Internet Explorer Site to Zone Assignment List')
                        {
                            ((Get-Content -Path $GpReport -Raw) -replace '%domain_wildcard%', "*.$DomainName") | Set-Content -Path $GpReport
                        }
                    }

                    # Check if gpo exist
                    if (-not (Get-GPO -Name $GpReportXmlName -ErrorAction SilentlyContinue) -and
                        (ShouldProcess @WhatIfSplat -Message "Importing $($Gpo.Name) `"$GpReportXmlName`"." @VerboseSplat))
                    {
                        Import-GPO -Path "$($GpoDir.FullName)" -BackupId $Gpo.Name -TargetName $GpReportXmlName -CreateIfNeeded > $null
                    }
                }

                Start-Sleep -Seconds 1
            }

            ###########
            # Policies
            ###########

            # Enforced if ending with +
            # Disabled if ending with -

            $SecurityPolicy =
            @(
                "$DomainPrefix - Computer - Sec - Enable Virtualization Based Security+"
                "$DomainPrefix - Computer - Sec - Enable LSA Protection & LSASS Audit+"
                "$DomainPrefix - Computer - Sec - Enable SMB Encryption+"
                "$DomainPrefix - Computer - Sec - Require Client LDAP Signing+"
                "$DomainPrefix - Computer - Sec - Block Untrusted Fonts+"
                "$DomainPrefix - Computer - Sec - Disable Telemetry+"
                "$DomainPrefix - Computer - Sec - Disable Netbios+"
                "$DomainPrefix - Computer - Sec - Disable LLMNR+"
                "$DomainPrefix - Computer - Sec - Disable WPAD+"
            )

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

                $BaseDN =
                @(
                    "$DomainPrefix - Domain - Force Group Policy+"
                    "$DomainPrefix - Domain - Client Kerberos Armoring+"
                    "$DomainPrefix - Domain - Certificate Services Client+"
                    "$DomainPrefix - Domain - Firewall Rules+"
                    "$DomainPrefix - Domain - Remote Desktop+"
                    'Default Domain Policy'
                )

                #####################
                # Domain controllers
                #####################

                "OU=Domain Controllers,$BaseDN" =
                @(
                    "$DomainPrefix - Domain Controller - Firewall - IPSec - Any - Request-"
                    "$DomainPrefix - Domain Controller - Restrict User Rights Assignment"
                    "$DomainPrefix - Domain Controller - KDC Kerberos Armoring+"
                    "$DomainPrefix - Domain Controller - Time - PDC NTP+"
                ) +
                $SecurityPolicy +
                @(
                    "$DomainPrefix - Computer - Sec - Disable Spooler+"
                    "$DomainPrefix - Computer - Windows Update+"
                    "$DomainPrefix - Computer - Display Settings+"
                ) +
                $WinBuilds.Item($DCBuild).DCBaseline +
                $WinBuilds.Item($DCBuild).BaseLine +
                @(
                    'Default Domain Controllers Policy'
                )
            }

            ############
            # Computers
            # Tier 0-2
            ############

            foreach($Tier in @(0, 1, 2))
            {
                $ComputerPolicy =
                @(
                    "$DomainPrefix - Computer - Firewall - IPSec - Any - Require/Request-"
                )

                # Link tier gpos
                $ComputerPolicy +=
                @(
                    "$DomainPrefix - Computer - Tier $Tier - Local Users and Groups+"
                    "$DomainPrefix - Computer - Tier $Tier - Restrict User Rights Assignment"
                )

                # Link security policy
                $ComputerPolicy += $SecurityPolicy

                if ($Tier -eq 2)
                {
                    # Workstations
                    $ComputerPolicy += @("$DomainPrefix - Computer - Sec - Disable Spooler Client Connections+")
                }
                else
                {
                    # Servers
                    $ComputerPolicy +=  @("$DomainPrefix - Computer - Sec - Disable Spooler+")
                }

                $ComputerPolicy +=
                @(
                    "$DomainPrefix - Computer - Windows Update+"
                    "$DomainPrefix - Computer - Display Settings+"
                    "$DomainPrefix - Computer - Internet Explorer Site to Zone Assignment List+"
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

                            "$DomainPrefix - Computer - Certification Services - Auditing"
                        )
                    )

                    # Federation Services
                    $GPOLinks.Add("OU=Federation Services,OU=$($Build.Server),OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - Computer - Firewall - IPSec - 80 (TCP) - Request-"
                            "$DomainPrefix - Computer - Firewall - IPSec - 443 (TCP) - Request-"
                        )
                    )

                    # Web Servers
                    $GPOLinks.Add("OU=Web Servers,OU=$($Build.Server),OU=Computers,OU=Tier 0,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - Computer - Web Server - User Rights Assignment"
                            "$DomainPrefix - Computer - Firewall - Web Server"
                            "$DomainPrefix - Computer - Firewall - IPSec - 80 (TCP) - Request-"
                            "$DomainPrefix - Computer - Firewall - IPSec - 443 (TCP) - Request-"
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
                    $GPOLinks.Add("OU=$($Build.Server),OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN", $Build.Baseline + $Build.ServerBaseline)

                    # Web Application Proxy
                    $GPOLinks.Add("OU=Web Application Proxy,OU=$($Build.Server),OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - Computer - Firewall - IPSec - 80 (TCP) - Disable Private and Public-"
                            "$DomainPrefix - Computer - Firewall - IPSec - 443 (TCP) - Disable Private and Public-"
                        )
                    )

                    # Web Servers
                    $GPOLinks.Add("OU=Web Servers,OU=$($Build.Server),OU=Computers,OU=Tier 1,OU=$DomainName,$BaseDN", @(

                            "$DomainPrefix - Computer - Web Server - User Rights Assignment"
                            "$DomainPrefix - Computer - Firewall - Web Server"
                            "$DomainPrefix - Computer - Firewall - IPSec - 80 (TCP) - Request-"
                            "$DomainPrefix - Computer - Firewall - IPSec - 443 (TCP) - Request-"
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

            foreach($Tier in @(0, 1, 2))
            {
                $UserPolicy =
                @(
                    "$DomainPrefix - User - Display Settings"
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
                $TargetShort = $Target -match '((?:cn|ou)=.*?,(?:cn|ou)=.*?)(?:,|$)' | ForEach-Object { $Matches[1] }

                # Itterate GPOs
                foreach($GpoName in ($GPOLinks.Item($Target)))
                {
                    $LinkEnable = 'Yes'
                    $LinkEnableBool = $true
                    $LinkEnforce = 'No'
                    $LinkEnforceBool = $false

                    if ($GpoName -match 'Restrict User Rights Assignment')
                    {
                        $LinkEnable = 'No'
                        $LinkEnableBool = $false
                        $LinkEnforce = 'Yes'
                        $LinkEnforceBool = $true
                    }
                    elseif ($GpoName.EndsWith('-'))
                    {
                        $LinkEnable = 'No'
                        $LinkEnableBool = $false
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
                            (ShouldProcess @WhatIfSplat -Message "Created `"$GpoName`" ($Order) -> `"$TargetShort`"" @VerboseSplat))
                        {
                            New-GPLink -Name $GpoName -Target $Target -Order $Order -LinkEnabled $LinkEnable -Enforced $LinkEnforce -ErrorAction Stop > $null
                        }
                        else
                        {
                            foreach ($Link in $GpoXml.GPO.LinksTo)
                            {
                                if ($RestrictDomain -notlike $null -and
                                    $GpoName -match 'Restrict User Rights Assignment')
                                {
                                    switch ($RestrictDomain)
                                    {
                                        $true
                                        {
                                            $LinkEnable = 'Yes'
                                            $LinkEnableBool = $true
                                        }
                                        $false
                                        {
                                            $LinkEnable = 'No'
                                            $LinkEnableBool = $false
                                        }
                                    }
                                }

                                if ($Link.Enabled -ne $LinkEnableBool -and
                                    ($RestrictDomain -notlike $null -and
                                     $GpoName -match 'Restrict User Rights Assignment') -and
                                    (ShouldProcess @WhatIfSplat -Message "Set `"$GpoName`" ($Order) Enabled: $LinkEnable -> `"$TargetShort`"" @VerboseSplat))
                                {
                                    Set-GPLink -Name $GpoName -Target $Target -LinkEnabled $LinkEnable > $null
                                }

                                if ($Link.NoOverride -ne $LinkEnforceBool -and
                                    (ShouldProcess @WhatIfSplat -Message "Set `"$GpoName`" ($Order) Enforced: $LinkEnforce -> `"$TargetShort`"" @VerboseSplat))
                                {
                                    Set-GPLink -Name $GpoName -Target $Target -Enforced $LinkEnforce > $null
                                }

                                if ($Order -ne (Get-GPInheritance -Target $Target | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName } | Select-Object -ExpandProperty Order) -and
                                    (ShouldProcess @WhatIfSplat -Message "Set `"$GpoName`" ($Order) -> `"$TargetShort`" " @VerboseSplat))
                                {
                                    Set-GPLink -Name $GpoName -Target $Target -Order $Order > $null
                                }
                            }
                        }

                        $Order++;
                    }
                    else
                    {
                        Write-Warning -Message "Gpo not found, couldn't link `"$GpoName`" -> `"$TargetShort`""
                    }
                }
            }

            ##############
            # Permissions
            ##############

            # Set permissions on user policies
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
                            Set-GPPermission -Name $GpoName -TargetName $Group -TargetType Group -PermissionLevel GpoApply > $nul
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

            # ██████╗  ██████╗ ██╗     ██╗ ██████╗██╗███████╗███████╗    ██╗███████╗██╗██╗      ██████╗ ███████╗
            # ██╔══██╗██╔═══██╗██║     ██║██╔════╝██║██╔════╝██╔════╝   ██╔╝██╔════╝██║██║     ██╔═══██╗██╔════╝
            # ██████╔╝██║   ██║██║     ██║██║     ██║█████╗  ███████╗  ██╔╝ ███████╗██║██║     ██║   ██║███████╗
            # ██╔═══╝ ██║   ██║██║     ██║██║     ██║██╔══╝  ╚════██║ ██╔╝  ╚════██║██║██║     ██║   ██║╚════██║
            # ██║     ╚██████╔╝███████╗██║╚██████╗██║███████╗███████║██╔╝   ███████║██║███████╗╚██████╔╝███████║
            # ╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝╚═╝╚══════╝╚══════╝╚═╝    ╚══════╝╚═╝╚══════╝ ╚═════╝ ╚══════╝

            $AuthenticationTires =
            @(
                @{ Name = 'Domain Controller';  Liftime = 45; }
                @{ Name = 'Tier 0';             Liftime = 45; }
                @{ Name = 'Tier 1';             Liftime = 45; }
                @{ Name = 'Tier 2';             Liftime = 45; }
                @{ Name = 'Lockdown';           Liftime = 45; }
            )

            foreach ($Tier in $AuthenticationTires)
            {
                ##############
                # Get members
                ##############

                switch ($Tier.Name)
                {
                    'Domain Controller'
                    {
                        $Members   = @(Get-ADGroup -Identity "Domain Admins" -Properties Members | Select-Object -ExpandProperty Members)
                        $Condition = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(DD)}))'
                    }

                    'Lockdown'
                    {
                        $Members   = @(Get-ADUser -Filter "Name -like '*'" -SearchScope 'OneLevel' -SearchBase "OU=Redirect Users,OU=$DomainName,$BaseDN" | Select-Object -ExpandProperty DistinguishedName)
                        $Condition = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo== "Lockdown"))'
                    }
                    default
                    {
                        $Members =
                        @(
                            @(Get-ADGroup -Identity "$($Tier.Name) - Users" -Properties Members | Select-Object -ExpandProperty Members) +
                            @(Get-ADGroup -Identity "$($Tier.Name) - Administrators" -Properties Members | Select-Object -ExpandProperty Members)
                        )
                        $Condition = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($(Get-ADGroup -Identity "$($Tier.Name) - Computers" | Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value))}))"
                    }
                }

                # Get policy
                $AuthPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($Tier.Name) Policy'"

                if ($RestrictDomain -eq $true)
                {
                    ################
                    # Create Policy
                    ################

                    if (-not $AuthPolicy -and (ShouldProcess @WhatIfSplat -Message "Adding `"$($Tier.Name) Policy`"" @VerboseSplat))
                    {
                        $Splat =
                        @{
                            Name = "$($Tier.Name) Policy"
                            Enforce = $true
                            ProtectedFromAccidentalDeletion = $false
                            UserTGTLifetimeMins = $Tier.Liftime
                            UserAllowedToAuthenticateFrom = $Condition
                        }

                        $AuthPolicy = New-ADAuthenticationPolicy @Splat -PassThru
                    }

                    <#

                    ##############
                    # Create Silo
                    ##############

                    if (-not (Get-ADAuthenticationPolicySilo -Filter "Name -eq '$($Tier.Name) Silo'") -and
                        (ShouldProcess @WhatIfSplat -Message "Adding `"$($Tier.Name) Silo`"" @VerboseSplat))
                    {
                        $Splat =
                        @{
                            Name = "$($Tier.Name) Silo"
                            Enforce = $true
                            ProtectedFromAccidentalDeletion = $false
                            UserAuthenticationPolicy = "$($Tier.Name) Policy"
                            ServiceAuthenticationPolicy = "$($Tier.Name) Policy"
                            ComputerAuthenticationPolicy = "$($Tier.Name) Policy"
                        }

                        New-ADAuthenticationPolicySilo @Splat
                    }
                    #>
                }

                ################
                # Add to Policy
                ################

                if ($AuthPolicy)
                {
                    # Itterate all group members
                    foreach ($Member in $Members)
                    {
                        # Get common name
                        $MemberCN = $($Member -match 'CN=(.*?),' | ForEach-Object { $Matches[1] })

                        # Get assigned authentication policy
                        $AssignedPolicy = Get-ADObject -Identity $Member -Properties msDS-AssignedAuthNPolicy | Select-Object -ExpandProperty msDS-AssignedAuthNPolicy

                        if (-not $AssignedPolicy -or $AssignedPolicy -notmatch $AuthPolicy.DistinguishedName -and
                            (ShouldProcess -Message "Adding `"$MemberCN`" to `"$($Tier.Name) Policy`"" @VerboseSplat))
                        {
                            Set-ADAccountAuthenticationPolicySilo -AuthenticationPolicy $AuthPolicy.DistinguishedName -Identity $Member
                        }
                    }
                }

                <#
                #####################
                # Add/Assign to Silo
                #####################

                # Itterate all group members
                foreach ($Member in $Members)
                {
                    # Get common name
                    $MemberCN = $($Member -match 'CN=(.*?),' | ForEach-Object { $Matches[1] })

                    if ($Member -notin (Get-ADAuthenticationPolicySilo -Filter "Name -eq '$($Tier.Name) Silo'" | Select-Object -ExpandProperty Members) -and
                        (ShouldProcess -Message "Adding `"$MemberCN`" to `"$($Tier.Name) Silo`"" @VerboseSplat))
                    {
                        Grant-ADAuthenticationPolicySiloAccess -Identity "$($Tier.Name) Silo" -Account "$Member"
                    }

                    # Get assigned authentication policy silo
                    $AssignedPolicy = Get-ADObject -Identity $Member -Properties msDS-AssignedAuthNPolicySilo | Select-Object -ExpandProperty msDS-AssignedAuthNPolicySilo

                    if (-not $AssignedPolicy -or $AssignedPolicy -notmatch "CN=$($Tier.Name) Silo" -and
                        (ShouldProcess -Message "Assigning `"$MemberCN`" with `"$($Tier.Name) Silo`"" @VerboseSplat))
                    {
                        Set-ADAccountAuthenticationPolicySilo -AuthenticationPolicySilo "$($Tier.Name) Silo" -Identity $Member
                    }
                }
                #>

                if ($RestrictDomain -eq $false)
                {
                    if ((Get-ADAuthenticationPolicySilo -Filter "Name -eq '$($Tier.Name) Silo'") -and
                        (ShouldProcess @WhatIfSplat -Message "Removing `"$($Tier.Name) Silo`"" @VerboseSplat))
                    {
                        Remove-ADAuthenticationPolicySilo -Identity "$($Tier.Name) Silo" -Confirm:$false
                    }

                    if ((Get-ADAuthenticationPolicy -Filter "Name -eq '$($Tier.Name) Policy'") -and
                        (ShouldProcess @WhatIfSplat -Message "Removing `"$($Tier.Name) Policy`"" @VerboseSplat))
                    {
                        Remove-ADAuthenticationPolicy -Identity "$($Tier.Name) Policy" -Confirm:$false
                    }
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
                                    Write-Warning -Message "Missing handler for `"$($Property.Name)`"."
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

            # ██████╗  ██████╗ ███████╗████████╗
            # ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝
            # ██████╔╝██║   ██║███████╗   ██║
            # ██╔═══╝ ██║   ██║╚════██║   ██║
            # ██║     ╚██████╔╝███████║   ██║
            # ╚═╝      ╚═════╝ ╚══════╝   ╚═╝

            # Recycle bin
            if (-not (Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" | Select-Object -ExpandProperty EnabledScopes) -and
                (ShouldProcess @WhatIfSplat -Message "Enabling Recycle Bin Feature." @VerboseSplat))
            {
                Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $DomainName -Confirm:$false > $null
            }

            # Register schema mmc
            if (-not (Get-Item -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{333FE3FB-0A9D-11D1-BB10-00C04FC9A3A3}\InprocServer32" -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Registering schmmgmt.dll." @VerboseSplat))
            {
                regsvr32.exe /s schmmgmt.dll
            }

            # ██╗      █████╗ ██████╗ ███████╗
            # ██║     ██╔══██╗██╔══██╗██╔════╝
            # ██║     ███████║██████╔╝███████╗
            # ██║     ██╔══██║██╔═══╝ ╚════██║
            # ███████╗██║  ██║██║     ███████║
            # ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝

            $AdmPwdPS = 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\AdmPwd.PS.dll'

            <#

            if (-not (Import-Module -Name $AdmPwdPS -Force -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Installing LAPS." @VerboseSplat))
            {
                if (-not (Test-Path -Path "$env:temp\LAPS.x64.msi") -and
                    (ShouldProcess @WhatIfSplat -Message "Downloading LAPS." @VerboseSplat))
                {
                    # Download
                    try
                    {
                        (New-Object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi', "$env:temp\LAPS.x64.msi")
                    }
                    catch [Exception]
                    {
                        throw $_
                    }
                }

                # Start installation
                $LAPSInstallJob = Start-Job -ScriptBlock { msiexec.exe /i "$env:temp\LAPS.x64.msi" ADDLOCAL=ALL /quiet /qn /norestart }

                # Wait for installation to complete
                Wait-Job -Job $LAPSInstallJob > $null

                # Import module
                Import-Module -Name $AdmPwdPS -Force
            }

            #>

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

                    # Check if intranet gpo
                    if ($Backup.DisplayName -match 'Computer - Internet Explorer Site to Zone Assignment List')
                    {
                        # Get backup filepath
                        $GpReport = "$env:TEMP\GpoBackup\{$($Backup.Id)}\gpreport.xml"

                        # Replace domain wildcard with placeholder
                        ((Get-Content -Path $GpReport -Raw) -replace "\*\.$($DomainName -replace '\.', '\.')", '%domain_wildcard%') | Set-Content -Path $GpReport
                    }

                    <#
                    # Check if user rights assignment
                    if ($Backup.DisplayName -match 'Restrict User Rights Assignment')
                    {
                        # Get backup filepath
                        [xml]$GpReport = "$env:TEMP\GpoBackup\{$($Backup.Id)}\gpreport.xml"


                        #Set-Content -Value $GpReportContent -Path $GpReport
                    }

foreach ($File in Get-ChildItem -Path 'C:\Dropbox\Documents\WindowsPowerShell\PowerShellLab\Gpo')
{
    if ($File.Name -ne 'manifest.xml')
    {
        # Get content
        [xml]$GpReport = Get-Content -Path "C:\Dropbox\Documents\WindowsPowerShell\PowerShellLab\Gpo\$($File.Name)\gpreport.xml" -Raw

        foreach ($Item in $GpReport.GPO.Computer.Extensiondata.Extension.UserRightsAssignment)
        {
            foreach ($Member in $Item.Member)
            {
                switch ($Item.Name)
                {
                    { $_ -in @('SeDenyBatchLogonRight',
                                'SeDenyInteractiveLogonRight',
                                'SeDenyNetworkLogonRight',
                                'SeDenyRemoteInteractiveLogonRight',
                                'SeDenyServiceLogonRight')
                    }
                    {
                        if ($Member.SID.'#text' -notmatch 'S-1-5-1\d\d|-5\d\d$')
                        {
                            $Member.Name.'#text'
                            $Member.SID.'#text'
                        }
                    }
                }
            }
        }

        #$GpReport.GPO.Computer.Extensiondata.Extension.UserRightsAssignment.Member.SID

    }
}

                    #>
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
                foreach($Template in (Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -SearchScope Subtree -Filter "Name -like '$DomainPrefix*' -and objectClass -eq 'pKICertificateTemplate'" -Property *))
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

            # ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███╗   ██╗
            # ██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║
            # ██████╔╝█████╗     ██║   ██║   ██║██████╔╝██╔██╗ ██║
            # ██╔══██╗██╔══╝     ██║   ██║   ██║██╔══██╗██║╚██╗██║
            # ██║  ██║███████╗   ██║   ╚██████╔╝██║  ██║██║ ╚████║
            # ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

            # Check size
            if ($UpdatedObjects.Count -gt 0)
            {
                $Result.Add('ComputersAddedToGroup', $UpdatedObjects)
            }

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
        if ($Result.GetType().Name -eq 'Hashtable')
        {
            $ResultOutput = @{}

            foreach($item in $Result.GetEnumerator())
            {
                if ($item.Key.GetType().Name -eq 'String')
                {
                    $ResultOutput.Add($item.Key, $item.Value)
                }
            }

            Write-Output -InputObject $ResultOutput
        }
        else
        {
            Write-Warning -Message 'Unexpected result:'

            foreach($row in $Result)
            {
                Write-Host -Object $row
            }
        }
    }
}

End
{
}

# SIG # Begin signature block
# MIIetgYJKoZIhvcNAQcCoIIepzCCHqMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC33oLtraTRYdco
# kUYNDRNqkRolWcrpkepno8tKL8JXHqCCGBIwggUHMIIC76ADAgECAhAlNIx7cQRR
# lkABY7XM1R9ZMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBUowTjdFMB4XDTIx
# MDYwNzEyNTAzNloXDTIzMDYwNzEzMDAzM1owEDEOMAwGA1UEAwwFSjBON0UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDN0XPe0P03RV5vKbDFsHuz5gws
# Uor0uU9w7LIVsChGdgpW4XtDpmJ8UxYiimdFGr9i1qES2ZqTIs/UCY616w5IvQ1E
# TkNA0XLKToPTb8cWGkzQduD2oqm/97cMPfq6q/oObBXKTRSL1MJhlBswOGFr9K9P
# 4hLg8EPB3dFMbpUfvSMb/uVrACGYATv+CPcF3mmLuMydo9pEeySiBsAf+9EbNb6i
# 54bddX0Tk9ZZ5GqDVtNegiEEbVGhJYJcSlwd6QVVKdq0TUUbChkdMNhyo2dQ5AXH
# Ua6BkTumatmx0u+j/WBQJJ0wW9OhT5R66tkj1KV+E93prWNhP8FyCxl2CFZQ7Yzx
# IK5D9L826i0BneRkj/fLdPklCc32X3AxRqgigQzE0roGaxIWASSJB5B5TojRhPmq
# EO6QBkOgQQQcqXXvHRDq/GaIWvTjnVQ/FZnX2c8txxLeLf+QRCNVdzz2Pa9echbW
# vlQcZQHg1R2S1pDbmHFzpz79OzH3rxL4xyrEX1GZEyniDSQAWEEcqPtaFRW3Zn9t
# QtLJvvY4XgELngIJK3VDh4SWHQLUC52RmCP0JAoUjK95MEWyL6LaDoPlwimXl/JB
# CeoOH+P6E3lC4jwPumgt7cw80DmvlbVzrQHyeCsOwl3tecmtfoZ0l3bAg+HVGbMO
# WahTFVeuCcW2DN5NRQIDAQABo10wWzAOBgNVHQ8BAf8EBAMCBaAwKgYDVR0lBCMw
# IQYIKwYBBQUHAwMGCSsGAQQBgjdQAQYKKwYBBAGCNwoDBDAdBgNVHQ4EFgQUQ8Iu
# g1iDDJBUdGsFIj2XSdIzCcswDQYJKoZIhvcNAQELBQADggIBAGIxbxxJLgvU5W7h
# xGJo+uJqpB1S6SCRxPyJYZasActMU/OK8g8jn7uorDMgltqA4zd8mMbR7q2CFpII
# 99VT6w9a9cgoXeujlctR8m63qPmpSqhC3/M25akjXYPWCzU1E5acmCp7V12a+gA6
# fmlnIWqigLhKcPV9PtKuz4bweztB3aP/VdgCmFl8teiI4Wzu7ORAsluGaKSEQlAr
# MoTiLx1yyi5w2F7aW80N+0mpoaWgAvO7TjLUtymAINFu+NTRgNK1nApISP2O/Pz3
# GmXm0yuAZYgryCGNHMZ/SI+Gpv/EU4Vwo/aTjdf/BdZr1bs+U742EiVmZMz9b7CW
# CtF+CRrDLZYuk7xWin629XAt3KnmfhTFENcGFh3vwl+xxvR/CmxT4PM40uskTBeN
# 2Pdb690RmztgjACewIZ/w3Oddak30Ps7OpXQ9PZLORqjmESnedLp0553D/S4oDP6
# XmztYk5Mu0WMOFSTraDm8hm9UrYT1NYC5WI+ZSRW6Ce7iRXhzzvSLliBFnP2XiKH
# m8v1cyhzj/qCiEu1SBPgUPTEpedvC2X8tzOTMM728otvH3cgKY0m7MuP4rxLgACj
# yro9OAtnIaWjOZNZFrdKYZWpM0Sy5lHjWEY2mO020giLB1nhC4/xyPrhOKRQigZU
# 1sJmBw8MeuvPzhmMAWWbsf1J9MryMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKR
# N6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZz
# lm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1Oco
# LevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH
# 92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRA
# p8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+g
# GkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU
# 8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/
# FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwj
# jVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQ
# EgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUae
# tdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftw
# ig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalW
# zxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQm
# h2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScb
# qyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLaf
# zYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbD
# Qc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0K
# XzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm
# 8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9
# gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8a
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBsAwggSo
# oAMCAQICEAxNaXJLlPo8Kko9KQeAPVowDQYJKoZIhvcNAQELBQAwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0y
# MjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5NTlaMEYxCzAJBgNVBAYTAlVTMREwDwYD
# VQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIg
# LSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz+ylJjrGqfJru43B
# DZrboegUhXQzGias0BxVHh42bbySVQxh9J0Jdz0Vlggva2Sk/QaDFteRkjgcMQKW
# +3KxlzpVrzPsYYrppijbkGNcvYlT4DotjIdCriak5Lt4eLl6FuFWxsC6ZFO7Khbn
# UEi7iGkMiMbxvuAvfTuxylONQIMe58tySSgeTIAehVbnhe3yYbyqOgd99qtu5Wbd
# 4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+JvK0jM1MuWbIu6pQOA3ljJRdGVq/9XtA
# bm8WqJqclUeGhXk+DF5mjBoKJL6cqtKctvdPbnjEKD+jHA9QBje6CNk1prUe2nhY
# HTno+EyREJZ+TeHdwq2lfvgtGx/sK0YYoxn2Off1wU9xLokDEaJLu5i/+k/kezbv
# BkTkVf826uV8MefzwlLE5hZ7Wn6lJXPbwGqZIS1j5Vn1TS+QHye30qsU5Thmh1EI
# a/tTQznQZPpWz+D0CuYUbWR4u5j9lMNzIfMvwi4g14Gs0/EH1OG92V1LbjGUKYvm
# QaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqmgQ8JJVPxvzvpqwcOagc5YhnJ1oV/E9mN
# ec9ixezhe7nMZxMHmsF47caIyLBuMnnHC1mDjcbu9Sx8e47LZInxscS451NeX1XS
# fRkpWQNO+l3qRXMchH7XzuLUOncCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIH
# gDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2
# mi91jGogj57IbzAdBgNVHQ4EFgQUYore0GH8jzEU7ZcLzT0qlBTfUpwwWgYDVR0f
# BFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUH
# AQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBY
# BggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8deNP1oUj8fz5lTmbJeb3coqYw3fUZPwV
# +zbCSVEseIhjVQlGOQD8adTKmyn7oz/AyQCbEx2wmIncePLNfIXNU52vYuJhZqMU
# KkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ5ojOfRu4aqKbwVNgCeijuJ3XrR8cuOyY
# QfD2DoD75P/fnRCn6wC6X0qPGjpStOq/CUkVNTZZmg9U0rIbf35eCa12VIp0bcrS
# BWcrduv/mLImlTgZiEQU5QpZomvnIj5EIdI/HMCb7XxIstiSDJFPPGaUr10CU+ue
# 4p7k0x+GAWScAMLpWnR1DT3heYi/HAGXyRkjgNc2Wl+WFrFjDMZGQDvOXTXUWT5D
# mhiuw8nLw/ubE19qtcfg8wXDWd8nYiveQclTuf80EGf2JjKYe/5cQpSBlIKdrAqL
# xksVStOYkEVgM4DgI974A6T2RUflzrgDQkfoQTZxd639ouiXdE4u2h4djFrIHprV
# wvDGIqhPm73YHJpRxC+a9l+nJ5e6li6FV8Bg53hWf2rvwpWaSxECyIKcyRoFfLpx
# tU56mWz06J7UWpjIn7+NuxhcQ/XQKujiYu54BNu90ftbCqhwfvCXhHjjCANdRyxj
# qCU4lwHSPzra5eX25pvcfizM/xdMTQCi2NYBDriL7ubgclWJLCcZYfZ3AYwxggX6
# MIIF9gIBATAkMBAxDjAMBgNVBAMMBUowTjdFAhAlNIx7cQRRlkABY7XM1R9ZMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIGcFmljZ2QSuUAu9TCGg7/U/q3eRZb8kaCyqj/Ao
# uvInMA0GCSqGSIb3DQEBAQUABIICAL+2lt4NncD85C6WKXSVH3mPDVPCvVwl6oLr
# yVs6jT1VcXssLmPbUzuVw32EJYNHKQq5F+6bMmfrTQ5Rv5m7BXkIO7KHqjY8kTa9
# zfqnNafhxR5PyUFl5Ad1drGGUBdfbx6kFotuN2rBB5IfI7YlFIqAa4JLMzTnAr3u
# ueNpHmiNor0+dWTgF7/Q1OiyFJ+GCiVnvN3uM106R6194b5P4igtsfFnFFHbwlJ9
# bwuqR1uc4FJkaHAz67mzVRRxFNJbiPqeRh97YoGO06G24O21XL5hTmQS+NEeXI9d
# pci6QzC3IAL4QIwnQStArgw6U551Eg6hCDWRfizmbcEKzGFfrN3dMYr9FutIvG5I
# bIsf5bgU1fERPKd3G8h38SzGypr4tW1bCDfpbm0caLlzvjgVf0wtrGTZOexu03Ey
# oFEV9w6lAKWKJesqN4ZjBbF2SUtsg43zfsHLrxEUZb1Ypl6ubLsklp7OMxqCFQ5q
# aeobDOQq9zN7aPIUcm1Uf1A2veiyK9zAWDZer52oIGF0xBvb1hP84q23fwmy7QCf
# yeMCok5Ni5AI46byKi0j24BwDAuijm4RtQ8F18GNGd80Fvz7M6oAKwpV7tfciBZA
# o0INgkfPHAQolZEf/izbOWN6e6oo3BWa/W4I/U3GgVpBD1RiwPYq/XHZGYCr0/OI
# ZC2/LH7goYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQDE1p
# ckuU+jwqSj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMDQyMjE2MTQzN1owLwYJKoZIhvcN
# AQkEMSIEIG9CDVt4HprjoP+RIVTmxgYeJLq2Ci3fm3AE2mdVjwC0MA0GCSqGSIb3
# DQEBAQUABIICAHQiJd+8wxWXQSAehVRTqSkEWek4F/nuMRkIS8xyFFeFS8ot8/zF
# DJ0kAWmtlmAZiPUXG0YYhKmzx/QGZE+812b+XM/VPpo8538Y3tFhywlCsXa3XJOT
# GpEcZcTDqkDVqs6CTDitJzEHuKZtNNioG+ZHf3zu7q3odPfSB7lSzPa9Phi6+7DT
# won3MJOqOMIcMrgCm88uvJDHQxOyliW2NsY8GnA3pWlv4Q9SEHBa9iMSrOu5B6bu
# l7GJlAsLVVUaevD1jbzevAy1380JsanikINbyTQ70D4P9MAUbonj1kuRnBDrGQs8
# jZdskvgulMsYAh9fEO9acTdOSIMoD+tFPxX2n7c1ffDFSav9rcYwb8Oe9npWaEo2
# rlHj2gUmS+mF+Ae3H7vxkWWgSocwTwNEUIsovNkA5teTn5jxZguYRkV/PPIEmhT7
# fP5nTsMXyevDiL6RLhPrj2W5SlLfuTG3liipTaHVy+Kd6zBsaJHze5pkCiawM5X/
# igcV5Ffo6zxLrKdiW3MLmQoIbujCjszSHbG+oizSas8/Jfn8RDXOHF4s+7LN/89v
# 9xf7HtT8Ks7sYoqg2EvQliz580XOz1uFXsePGqcJ0VgzwaKv4fduj7ChK4XcdQ0h
# Dl8Nk5ePKdwYOKbH18ObOa6/VaiHhCp/aOvYF6wymu5SZzZ/XGjXbKha
# SIG # End signature block
