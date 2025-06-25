<#
 .DESCRIPTION
    Build Hyper-V lab
 .NOTES
    AUTHOR Jonas Henriksson
 .LINK
    https://github.com/J0N7E
#>

[cmdletbinding(SupportsShouldProcess=$true)]

Param
(
    # Hyper-V drive
    [String]$HvLab = "$env:SystemDrive\HvLab",

    # OSDBuilder path
    [String]$OsdPath = "$env:SystemDrive\OSDBuilder",

    # PowerShell lab path
    [String]$LabPath,

    [Int]$ThrottleLimit,

    [ValidateSet($true, $false, $null)]
    [Object]$RestrictDomain,

    [ValidateSet($true, $false, $null)]
    [Object]$SetupAdfs,

    [Array]$AddVMs
)

Begin
{
    #########
    # Invoke
    #########

    Invoke-Command -ScriptBlock `
    {
        try
        {
            . $PSScriptRoot\f_ShouldProcess.ps1
            . $PSScriptRoot\f_CopyDifferentItem.ps1 #### Depends on Should-Process ####
        }
        catch [Exception]
        {
            throw "$_ $( $_.ScriptStackTrace)"
        }
    } -NoNewScope

    #####################
    # Verbose Preference
    #####################

    # Initialize verbose
    $VerboseSplat = @{}

    # Check verbose
    if ($VerbosePreference -ne 'SilentlyContinue')
    {
        # Reset verbose preference
        $VerbosePreference = 'SilentlyContinue'

        # Set verbose splat
        $VerboseSplat.Add('Verbose', $true)
    }

    ########
    # Paths
    ########

    if (-not $LabPath)
    {
        $Paths = @(
           "$env:Documents\WindowsPowerShell\PowerShellLab",
           (Get-Location).Path
        )

        foreach ($Path in $Paths)
        {
            if (Test-Path -Path $Path)
            {
                $LabPath = Set-Location -Path $Path -ErrorAction SilentlyContinue -PassThru | Select-Object -ExpandProperty Path
                break
            }
        }
    }

    ###########
    # Settings
    ###########

    # Get domain name
    if (-not $DomainName)
    {
        do
        {
            $Global:DomainName = Read-Host -Prompt "Choose a domain name (FQDN)"
        }
        until($DomainName -match '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)')

        $Global:DomainNetbiosName = $DomainName.Substring(0, $DomainName.IndexOf('.'))
        $Global:DomainPrefix = $DomainNetBiosName.Substring(0, 1).ToUpper() + $DomainNetBiosName.Substring(1)
    }

    # Password
    $Settings = @{ Pswd = (ConvertTo-SecureString -String 'P455w0rd' -AsPlainText -Force) }

    # Get credentials
    $Settings +=
    @{
        Lac   = New-Object -ArgumentList ".\administrator", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
        Dac   = New-Object -ArgumentList "$($DomainNetbiosName + '\admin')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
        AcDc  = New-Object -ArgumentList "$($DomainNetbiosName + '\tdcadm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
        Ac0   = New-Object -ArgumentList "$($DomainNetbiosName + '\t0adm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
        Ac1   = New-Object -ArgumentList "$($DomainNetbiosName + '\t1adm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
        Ac2   = New-Object -ArgumentList "$($DomainNetbiosName + '\t2adm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    }

    $Settings +=
    @{
        Switches =
        @(
            @{ Name = 'Lab';     Type = 'Private';   NetworkId = '192.168.0';  GW = '192.168.0.1';  DNS = '192.168.0.10' }
        )
        VMs = [ordered]@{

            RootCA = @{ Name = 'CA01';    Domain = $false;  OSVersion = '*Experience x64 24H2*';     Switch = @();       Credential = $Settings.Lac; }
            DC     = @{ Name = 'DC01';    Domain = $false;  OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Dac; }
            SubCA  = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            AS     = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            ADFS   = @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            WIN    = @{ Name = 'WIN11';   Domain = $true;   OSVersion = '*11 Enterprise x64 24H2*';  Switch = @('Lab');  Credential = $Settings.Ac2; }
        }
    }

    if (-not $SetupAdfs)
    {
        $Settings.VMs.Remove('ADFS')
    }

    #############
    # Initialize
    #############

    $Global:NewVMs     = @{}
    $Global:StartedVMs = @{}

    [Ref]$TimeWaited = 0

    if(-not $ThrottleLimit)
    {
        $ThrottleLimit = $Settings.VMs.Count
    }

    if($AddVMs)
    {
        foreach($VM in $AddVMs)
        {
            $NewVMs.Add($VM, $true)
            $StartedVMs.Add($VM, $true)
        }
    }

    #########
    # Splats
    #########

    # Credentials
    $Settings.GetEnumerator() | Where-Object { $_.Value -is [PSCredential] } | ForEach-Object {

        New-Variable -Name $_.Name -Value @{ Credential = $_.Value } -Force
    }

    # Virtual machines
    $Settings.VMs.GetEnumerator() | ForEach-Object {

        New-Variable -Name $_.Name -Value @{ VMName = $_.Value.Name } -Force
    }

    # Restrict domain
    switch ($RestrictDomain)
    {
        $null  { $RestrictDomainSplat = @{} }
        $true  { $RestrictDomainSplat = @{ RestrictDomain = $true  } }
        $false { $RestrictDomainSplat = @{ RestrictDomain = $false } }
    }

    # Setup Adfs
    switch ($SetupAdfs)
    {
        $null  { $SetupAdfsSplat = @{} }
        $true  { $SetupAdfsSplat = @{ SetupAdfs = $true  } }
        $false { $SetupAdfsSplat = @{ SetupAdfs = $false } }
    }

    $StartedVMsSplat  = @{ WaitQueue = $StartedVMs }
    $TimeWaitedSplat  = @{ TimeWaited = $TimeWaited }
    $ThrottleSplat    = @{ ThrottleLimit = $ThrottleLimit }

    ############
    # Functions
    ############

    function Check-Heartbeat
    {
        param
        (
            [Parameter(Mandatory=$true)]
            [String]$VMName,
            [Switch]$Wait
        )

        # Get heartbeat
        $VmHeartBeat = Get-VMIntegrationService -VMName $VMName | Where-Object { $_.Name -eq 'Heartbeat' }

        if ((Get-VM -Name $VMName -ErrorAction SilentlyContinue).State -ne 'Running')
        {
            # VM not running
            Write-Output -InputObject $false
        }
        elseif ($VmHeartBeat -and $VmHeartBeat.Enabled -eq $true)
        {
            if ($Wait.IsPresent)
            {
                do
                {
                    Start-Sleep -Milliseconds 25
                }
                until ($VmHeartBeat.PrimaryStatusDescription -eq "OK")

                # Heartbeat after waiting
                Write-Output -InputObject $true
            }
            elseif ($VmHeartBeat.PrimaryStatusDescription -eq "OK")
            {
                # Heartbeat
                Write-Output -InputObject $true
            }
            else
            {
                # No Heartbeat
                Write-Output -InputObject $false
            }
        }
        else
        {
            # Hearbeat not enabled (but VM running)
            Write-Output -InputObject $true
        }
    }
    $CheckHeartbeat = ${function:Check-Heartbeat}.ToString()

    function Wait-For
    {
        [cmdletbinding(SupportsShouldProcess=$true)]

        param
        (
            [Parameter(Mandatory=$true)]
            [String]$VMName,

            [Parameter(Mandatory=$true)]
            [PSCredential]$Credential,

            [String]$DefaultThreshold = 5000,

            [Switch]$Force,

            [Hashtable]$WaitQueue = @{},
            [Ref]$TimeWaited
        )

        begin
        {
            #####################
            # Verbose Preference
            #####################

            # Initialize verbose
            $VerboseSplat = @{}

            # Check verbose
            if ($VerbosePreference -ne 'SilentlyContinue')
            {
                # Reset verbose preference
                $VerbosePreference = 'SilentlyContinue'

                # Set verbose splat
                $VerboseSplat.Add('Verbose', $true)
            }
        }

        process
        {
            # Fail if not running
            if ((Get-VM -Name $VMName -ErrorAction SilentlyContinue).State -ne 'Running')
            {
                # Return
                Write-Output -InputObject $false
            }
            # Wait if vm in queue or forced
            elseif ($WaitQueue.ContainsKey($VMName) -or $Force.IsPresent)
            {
                # Enable resource metering
                Enable-VMResourceMetering -VMName $VMName

                # Initialize total duration timer
                $TotalDuration = [System.Diagnostics.Stopwatch]::StartNew()

                Write-Verbose -Message "Waiting for $VMName..." @VerboseSplat

                do
                {
                    # Get measure
                    $MeasureVM = Measure-VM -VMName $VMName -ErrorAction SilentlyContinue

                    if ($MeasureVM -and $MeasureVM.AggregatedAverageLatency -ne 0)
                    {
                        $Threshold = $MeasureVM.AggregatedAverageLatency * 50
                    }
                    else
                    {
                        $Threshold = $DefaultThreshold
                    }

                    # Check if ready
                    try
                    {
                        Wait-VM -VMName $VMName -For Heartbeat -Timeout ($Threshold/10)
                        Wait-VM -VMName $VMName -For MemoryOperations -Timeout ($Threshold/10)

                        $VmReady = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock { $true } -ErrorAction Stop
                    }
                    catch [Exception]
                    {
                        switch -Regex ($_)
                        {
                            'The virtual machine .*? is not in running state.'
                            {
                                Write-Warning -Message $_
                                Write-Output -InputObject $false
                                return
                            }

                            Default
                            {
                                if ($TotalDuration.ElapsedMilliseconds - $LastError.ElapsedMilliseconds -gt 25)
                                {
                                    Write-Warning -Message "Invoke failed: $_" @VerboseSplat
                                }
                            }
                        }

                        $LastError = $TotalDuration
                        $VmReady = $false

                        #Start-Sleep -Milliseconds 25
                    }

                    if ($VmReady -and (Check-Heartbeat -VMName $VMName))
                    {
                        # Start threshold timer
                        if (-not $VmReadyDuration -or $VmReadyDuration.IsRunning -eq $false)
                        {
                            $VmReadyDuration = [System.Diagnostics.Stopwatch]::StartNew()
                            Write-Verbose -Message "$VMName responding, setting initial threshold timer to $Threshold ms..." @VerboseSplat
                        }
                    }
                    elseif ($VmReadyDuration -and $VmReadyDuration.IsRunning -eq $true)
                    {
                        # Stop threshold timer
                        $VmReadyDuration.Stop()

                        Write-Verbose -Message "$VMName not responding, stoped threshold timer after $($VmReadyDuration.ElapsedMilliseconds) ms." @VerboseSplat

                        $VmReadyDuration = $null
                    }
                }
                until($VmReady -and (Check-Heartbeat -VMName $VMName) -and $VmReadyDuration.ElapsedMilliseconds -gt $Threshold)

                # Stop timers
                $VmReadyDuration.Stop()
                $TotalDuration.Stop()

                # Remove VM from queue
                $WaitQueue.Remove($VMName)

                # Set time waited
                if ($TimeWaited)
                {
                    $TimeWaited.Value += $TotalDuration.ElapsedMilliseconds
                }

                Write-Verbose -Message "$VMName ready, met threshold at $Threshold ms. Waited total $($TotalDuration.ElapsedMilliseconds) ms." @VerboseSplat

                # Disable resource metering
                Disable-VMResourceMetering -VMName $VMName

                # Return
                Write-Output -InputObject $true
            }
            # If not in queue, continue
            else
            {
                # Return
                Write-Output -InputObject $true
            }
        }

        end
        {
            # Cleanup
            $TotalDuration = $null
            $VmReadyDuration = $null
        }
    }
    $WaitFor = ${function:Wait-For}.ToString()

    function Invoke-Wend
    {
        param
        (
            [Scriptblock]$Tryblock,
            [Scriptblock]$Wendblock = { $Wend = $false },
            [Scriptblock]$Catchblock = {

                    Write-Warning -Message $_
                    Read-Host -Prompt "Press <enter> to continue"
            },
            [Switch]$NoOutput
        )

        begin
        {
            $Result = $null
        }

        process
        {
            do
            {
                $Wend = $true

                try
                {
                    $Result = Invoke-Command -ScriptBlock $Tryblock -NoNewScope

                    Invoke-Command -ScriptBlock $Wendblock -NoNewScope
                }
                catch [Exception]
                {
                    Invoke-Command -ScriptBlock $Catchblock -NoNewScope
                }
            }
            while ($Wend)
        }

        end
        {
            if (-not $NoOutput.IsPresent)
            {
                Write-Output -InputObject $Result
            }
        }
    }
    $InvokeWend = ${function:Invoke-Wend}.ToString()

    ##########
    # Counter
    ##########

    $TotalTime = [System.Diagnostics.Stopwatch]::StartNew()
}

Process
{
    ##############
    # Check admin
    ##############

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw "Must be administrator to build lab."
    }

    #################
    # Setup switches
    #################

    foreach ($Switch in $Settings.Switches)
    {
        New-Variable -Name $Switch.Name -Value $Switch -Force

        if (-not (Get-VMSwitch -Name $Switch.Name -ErrorAction SilentlyContinue))
        {
            Write-Verbose -Message "Adding $($Switch.Type) switch $($Switch.Name)..." @VerboseSplat
            New-VMSwitch -Name $Switch.Name -SwitchType $Switch.Type > $null
            Get-NetAdapter -Name "vEthernet ($($Switch.Name))" -ErrorAction SilentlyContinue | Rename-NetAdapter -NewName $Switch.Name
        }
    }

    Write-Verbose -Message "Using ThrottleLimit $ThrottleLimit" @VerboseSplat

    ##############
    # Install VMs
    ##############

    if (-not (Test-Path -Path "$HvLab" -PathType Container))
    {
        New-Item -Path "$HvLab" -ItemType Directory > $null
    }

    $Settings.VMs.Values | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel {

        # Set variables
        $VM           = $_
        $OsdPath      = $Using:OsdPath
        $HvLab        = $Using:HvLab
        $VerboseSplat = $Using:VerboseSplat
        $Settings     = $Using:Settings
        $NewVMs       = $Using:NewVMs
        $StartedVMs   = $Using:StartedVMs

        # Set functions
        ${function:Check-Heartbeat} = $Using:CheckHeartbeat

        # Get latest os media
        $OSMedia = Get-Item -Path "$OsdPath\OSMedia\$($VM.OSVersion)" -ErrorAction SilentlyContinue | Select-Object -Last 1

        # Get latest vhdx
        $OSVhdx = Get-Item -Path "$OsdPath\OSMedia\$($OSMedia.Name)\VHD\OSDBuilder.vhdx" -ErrorAction SilentlyContinue | Select-Object -Last 1

        if (-not $OSVhdx)
        {
            Write-Warning -Message "No VHDX found for `"$($VM.Name)`""
        }
        else
        {
            $NewVMSplat =
            @{
                LabFolder = "$HvLab"
            }

            if ($VM.Switch.Length -gt 0)
            {
                $NewVMSplat +=
                @{
                    VMAdapters = $VM.Switch
                }
            }

            $Result = .\LabNewVM.ps1 @NewVMSplat -VMName $VM.Name -Vhdx $OSVhdx @VerboseSplat

            if ($Result.NewVM -and $Result.NewVM -notin @($Settings.VMs.RootCA.Name, $Settings.VMs.DC.Name))
            {
               $NewVMs.Add($Result.NewVM, $true)
            }

            if ($Result.StartedVM)
            {
               $StartedVMs.Add($Result.StartedVM, $true)
            }
        }
    }

    #########
    # DC
    # Step 1
    #########

    if (Wait-For @DC @Lac @VerboseSplat @TimeWaitedSplat @StartedVMsSplat)
    {
        # Rename
        $DCResult = .\VMRename.ps1 @DC @Lac @VerboseSplat -Restart

        if ($DCResult.Renamed)
        {
            # Wait for reboot
            Start-Sleep -Seconds 3

            # Make sure DC is up
            Wait-For @DC @Lac @VerboseSplat @TimeWaitedSplat -Force > $null

            # Setup network
            .\VMSetupNetwork.ps1 @DC @Lac @VerboseSplat `
                                 -AdapterName Lab `
                                 -IPAddress "$($Lab.DNS)" `
                                 -DefaultGateway "$($Lab.GW)" `
                                 -DNSServerAddresses @("$($LabDmz.DNS)")

            ###########
            # Setup DC
            # Step 1
            ###########

            $DCStep1Result = .\VMSetupDC.ps1 @DC @Lac @VerboseSplat `
                                             -DomainNetworkId $Lab.NetworkId `
                                             -DomainName $DomainName `
                                             -DomainNetbiosName $DomainNetbiosName `
                                             -DomainLocalPassword $Settings.Pswd
        }
    }

    ##########
    # Root CA
    ##########

    if (Wait-For @RootCA @Lac @VerboseSplat @TimeWaitedSplat @StartedVMsSplat)
    {
        $RootCAResult = .\VMRename.ps1 @RootCA @Lac @VerboseSplat -Restart

        if ($RootCAResult.Renamed)
        {
            # Wait for reboot
            Start-Sleep -Milliseconds 500

            # Make sure CA is up
            Wait-For @RootCA @Lac @VerboseSplat @TimeWaitedSplat -Force > $null
        }

        .\VMSetupCA.ps1 @RootCA @Lac @VerboseSplat `
                        -Force `
                        -StandaloneRootCA `
                        -KeyLength 256 `
                        -CryptoProviderName 'ECDSA_P256#Microsoft Software Key Storage Provider' `
                        -CACommonName "$DomainPrefix Root $($Settings.VMs.RootCA.Name)" `
                        -CADistinguishedNameSuffix "O=$DomainPrefix,C=SE" `
                        -DomainName $DomainName > $null
    }

    ################
    # Setup network
    ################

    $Settings.VMs.Values | Where-Object { $_.Name -in $NewVMs.Keys }
                         | Foreach-Object @VerboseSplat @ThrottleSplat -Parallel {
        # Set variables
        $Lac             = $Using:Lac
        $VerboseSplat    = $Using:VerboseSplat
        $TimeWaited      = $Using:TimeWaited
        $TimeWaitedSplat = $Using:TimeWaitedSplat
        $StartedVMs      = $Using:StartedVMs
        $StartedVMsSplat = $Using:StartedVMsSplat
        $Settings        = $Using:Settings

        # Get functions
        ${function:Check-Heartbeat} = $Using:CheckHeartbeat
        ${function:Wait-For} = $Using:WaitFor

        if (Wait-For -VMName $_.Name @Lac @VerboseSplat @TimeWaitedSplat @StartedVMsSplat)
        {
            foreach($Adapter in $_.Switch)
            {
                .\VMSetupNetwork.ps1 -VMName $_.Name @Lac @VerboseSplat `
                                     -AdapterName $Adapter `
                                     -DNSServerAddresses @("$($Settings.Switches.Where({ $_.Name -eq $Adapter}).DNS)")
            }
        }
    }

    #########
    # AS
    # Step 1
    #########

    # Root cdp
    if (Wait-For @AS @Lac @VerboseSplat @TimeWaitedSplat @StartedVMsSplat)
    {
        .\VMSetupCAConfigureWebServer.ps1 @AS @Lac @VerboseSplat `
                                          -Force `
                                          -CAConfig "$($Settings.VMs.RootCA.Name).$DomainName\$DomainPrefix Root $($Settings.VMs.RootCA.Name)" `
                                          -ConfigureIIS
    }

    #########
    # DC
    # Step 2
    #########

    if (Check-Heartbeat -VMName $Settings.VMs.DC.Name)
    {
        if ($DCStep1Result.WaitingForReboot)
        {
            $LastOutput = $null

            # Wait for group policy
            Invoke-Wend -NoOutput -TryBlock {

                Invoke-Command @DC @Lac -ScriptBlock {

                    # Get group policy
                    Get-GPO -Name 'Default Domain Policy' -ErrorAction SilentlyContinue

                } -ErrorAction SilentlyContinue

            } -WendBlock {

                $Wend = $false

                # Check group policy result
                if (-not ($Result -and $Result.GpoStatus -eq 'AllSettingsEnabled'))
                {
                    $Wend = $true

                    if (-not $LastOutput -or $LastOutput.AddMinutes(1) -lt (Get-Date))
                    {
                        Write-Verbose -Message 'Waiting for DC...' @VerboseSplat
                        $LastOutput = Get-Date
                    }
                }

            } -CatchBlock {

                if (-not $LastOutput -or $LastOutput.AddMinutes(1) -lt (Get-Date))
                {
                    Write-Warning -Message $_
                    $LastOutput = Get-Date
                }

            }

            # Setup network
            .\VMSetupNetwork.ps1 @DC @Lac @VerboseSplat `
                                 -AdapterName Lab `
                                 -IPAddress "$($Lab.DNS)" `
                                 -DefaultGateway "$($Lab.GW)" `
                                 -DNSServerAddresses @("$($Lab.DNS)", '127.0.0.1')

            ###########
            # Setup DC
            # Step 2
            ###########

            .\VMSetupDC.ps1 @DC @Lac @VerboseSplat `
                            -DomainNetworkId $Lab.NetworkId `
                            -DomainName $DomainName `
                            -DomainNetbiosName $DomainNetbiosName `
                            -DomainLocalPassword $Settings.Pswd `
                            -GPOPath "$LabPath\Gpo" `
                            -BaselinePath "$LabPath\Baseline" `
                            -TemplatePath "$LabPath\Templates" > $null
        }

        if ($NewVMs.Count)
        {
            # Initialize
            $DomainJoin = @()

            $NewVMs.Keys | ForEach-Object @VerboseSplat {

                # Set variables
                $VM = $_

                # Check if domain joined vm
                if ($Settings.VMs.Values | Where-Object { $_.Name -eq $VM -and $_.Domain })
                {
                    <#
                    # Remove old computer object
                    Invoke-Command @DC @Lac -ScriptBlock {

                        # Set variables
                        $VM           = $Args[0]
                        $VerboseSplat = $Args[1]

                        $ADComputer = Get-ADComputer -Filter "Name -eq '$VM'"

                        if ($ADComputer)
                        {
                            $ADComputer | Remove-ADObject -Recursive -Confirm:$false

                            Write-Verbose -Message "Removed $($ADComputer.Name) from domain." @VerboseSplat
                        }

                    } -ArgumentList $VM, $VerboseSplat
                    #>

                    # Add vm to join
                    $DomainJoin += $VM
                }
            }

            # Run DC setup to configure new ad objects
            .\VMSetupDC.ps1 @DC @Lac @VerboseSplat @RestrictDomainSplat @SetupAdfsSplat `
                            -DomainJoin $DomainJoin `
                            -DomainNetworkId $Lab.NetworkId `
                            -DomainName $DomainName `
                            -DomainNetbiosName $DomainNetbiosName `
                            -DomainLocalPassword $Settings.Pswd
        }

        # Publish root certificate to domain
        .\VMSetupCAConfigureAD.ps1 @DC @Lac @VerboseSplat `
                                   -CAType StandaloneRootCA `
                                   -CAServerName $Settings.VMs.RootCA.Name `
                                   -CACommonName "$DomainPrefix Root $($Settings.VMs.RootCA.Name)"
    }

    #################
    # Renew lease
    # Join domain
    # Reboot -> Wait
    #################

    $Global:JoinedDomain = @{}

    $NewVMs.Keys | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel {

        # Set variables
        $VM              = $_
        $Lac             = $Using:Lac
        $VerboseSplat    = $Using:VerboseSplat
        $Settings        = $Using:Settings
        $JoinedDomain    = $Using:JoinedDomain
        $TimeWaited      = $Using:TimeWaited
        $TimeWaitedSplat = $Using:TimeWaitedSplat

        # Set functions
        ${function:Check-Heartbeat} = $Using:CheckHeartbeat
        ${function:Wait-For}        = $Using:WaitFor

        Write-Verbose -Message "Renew IP-address $VM..." @VerboseSplat
        Invoke-Command -VMName $VM @Lac -ScriptBlock {

            ipconfig /renew Lab > $null
        }

        $JoinDomainSplat = @{}

        if ($Settings.VMs.Values.Where({$_.Name -eq $VM}).Domain)
        {
            $JoinDomainSplat.Add('JoinDomain', $true)
        }

        $Result = .\VMRename.ps1 -VMName $VM @Lac @JoinDomainSplat @VerboseSplat -Restart

        if ($Result.Joined -and
           (Wait-For -VMName $VM @Lac @VerboseSplat @TimeWaitedSplat -Force))
        {
           $JoinedDomain.Add($Result.Joined, $true)
        }
    }

    ###################
    # DC
    # Updating objects
    ###################

    if (Check-Heartbeat -VMName $Settings.VMs.DC.Name)
    {
        Write-Verbose -Message "Updating AD objects..." @VerboseSplat

        if ($Settings.VMs.ADFS.Name -in $NewVMs.Keys -or $SetupAdfs -eq $true)
        {
            $SetupAdfsSplat = @{ SetupADFS = $true }
        }
        else
        {
            $SetupAdfsSplat = @{ SetupADFS = $false }
        }

        $DcUpdateResult = @{}

        Invoke-Wend -NoOutput -TryBlock {

            # Run DC setup to configure new ad objects
            .\VMSetupDC.ps1 @DC @Lac @VerboseSplat @RestrictDomainSplat @SetupAdfsSplat `
                            -DomainNetworkId $Lab.NetworkId `
                            -DomainName $DomainName `
                            -DomainNetbiosName $DomainNetbiosName `
                            -DomainLocalPassword $Settings.Pswd
        } -WendBlock {

            $Wend = $false

            switch ($Result.Keys)
            {
                'BuildNotFound'
                {
                    $Result.BuildNotFound.Keys | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel {

                        # Set variables
                        $VM              = $_
                        $Lac             = $Using:Lac
                        $VerboseSplat    = $Using:VerboseSplat
                        $TimeWaited      = $Using:TimeWaited
                        $TimeWaitedSplat = $Using:TimeWaitedSplat

                        # Set functions
                        ${function:Check-Heartbeat} = $Using:CheckHeartbeat
                        ${function:Wait-For}        = $Using:WaitFor

                        if (Check-Heartbeat -VMName $VM)
                        {
                            Write-Verbose -Message "Refresh OperatingSystemVersion, restarting $VM ..." @VerboseSplat
                            Restart-VM -VMName $VM -Force
                        }

                        Wait-For -VMName $VM @Lac @VerboseSplat @TimeWaitedSplat -Force > $null
                    }

                    $Wend = $true
                }

                default
                {
                    if ($DcUpdateResult.ContainsKey($_))
                    {
                        $DcUpdateResult.Item($_) = $Result.Item($_)
                    }
                    else
                    {
                        $DcUpdateResult.Add($_, $Result.Item($_))
                    }
                }
            }
        }
    }

    # Check if restricting domain
    if ($DcUpdateResult.RestrictDomain)
    {
        # Add all domainjoined computers
        $Settings.VMs.Values | Where-Object { $_.Domain -and -not $DcUpdateResult.ComputersAddedToGroup.ContainsKey($_.Name) } | ForEach-Object { $DcUpdateResult.ComputersAddedToGroup.Add($_.Name, $true) }
    }

    #########
    # Reboot
    #########

    if ($DcUpdateResult.ComputersAddedToGroup)
    {
        $DcUpdateResult.ComputersAddedToGroup.Keys | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel {

            # Set variables
            $VM           = $_
            $VerboseSplat = $Using:VerboseSplat
            $StartedVMs   = $Using:StartedVMs

            # Set functions
            ${function:Check-Heartbeat} = $Using:CheckHeartbeat

            if (Check-Heartbeat -VMName $VM)
            {
                Write-Verbose -Message "Restarting $VM..." @VerboseSplat
                Restart-VM -VMName $VM -Force

                if (-not $StartedVMs.ContainsKey($VM))
                {
                    $StartedVMs.Add($VM, $true)
                }
            }
        }
    }

    #########
    # AS
    # Step 2
    #########

    # Issuing cdp
    if (Wait-For @AS @Ac0 @VerboseSplat @TimeWaitedSplat @StartedVMsSplat)
    {
        .\VMSetupCAConfigureWebServer.ps1 @AS @Ac0 @VerboseSplat `
                                          -Force `
                                          -CAConfig "$($Settings.VMs.RootCA.Name).$DomainName\$DomainPrefix Root $($Settings.VMs.RootCA.Name)" `
                                          -ShareAccess "Cert Publishers"
    }

    #########
    # Sub CA
    #########

    if (Wait-For @SubCA @Ac0 @VerboseSplat @TimeWaitedSplat @StartedVMsSplat)
    {
        $SubCaResult = Invoke-Wend -TryBlock {

            .\VMSetupCA.ps1 @SubCA @Ac0 @VerboseSplat `
                            -Force `
                            -EnterpriseSubordinateCA `
                            -KeyLength 256 `
                            -CryptoProviderName 'ECDSA_P256#Microsoft Software Key Storage Provider' `
                            -CACommonName "$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)" `
                            -CADistinguishedNameSuffix "O=$DomainPrefix,C=SE" `
                            -PublishAdditionalPaths @("\\$($Settings.VMs.AS.Name)\wwwroot$") `
                            -PublishTemplates `
                            -CRLPeriodUnits 180 `
                            -CRLPeriod Days `
                            -CRLOverlapUnits 90 `
                            -CRLOverlapPeriod Days
        } -WendBlock {

            $Wend = $false

            if ($Result.WaitingForResponse)
            {
                $Wend = $true

                if (Test-Path -Path "$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)-Response.cer")
                {
                    Write-Warning -Message "No root CA response match the sub CA request."
                    Read-Host -Prompt "Press <enter> to continue"
                }
                elseif (Check-Heartbeat @SubCA)
                {
                    # Issue sub ca certificate
                    .\VMSetupCAIssueCertificate.ps1 @RootCA @Lac @VerboseSplat `
                                                    -CertificateSigningRequest "$LabPath\$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)-Request.csr"
                }
            }
        }
    }

    # Cleanup
    if ($SubCaResult.CertificateInstalled)
    {
        Remove-Item -Path "$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)-Request.csr" -ErrorAction SilentlyContinue
        Remove-Item -Path "$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)-Response.cer" -ErrorAction SilentlyContinue
    }

    #########
    # AS
    # Step 3
    #########

    # Issuing ocsp
    if (Wait-For @AS @Ac0 @VerboseSplat @TimeWaitedSplat @StartedVMsSplat)
    {
        .\VMSetupCAConfigureWebServer.ps1 @AS @Ac0 @VerboseSplat `
                                          -Force `
                                          -CAConfig "$($Settings.VMs.SubCA.Name).$DomainName\$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)" `
                                          -ConfigureOCSP `
                                          -OCSPTemplate "$($DomainPrefix)OCSPResponseSigning"
    }

    #############
    # Autoenroll
    #############

    $Settings.VMs.Values | Where-Object { $_.Name -in $NewVMs.Keys -and $_.Domain }
                         | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel {

        # Set variables
        $VerboseSplat    = $Using:VerboseSplat
        $TimeWaited      = $Using:TimeWaited
        $TimeWaitedSplat = $Using:TimeWaitedSplat

        # Set functions
        ${function:Check-Heartbeat} = $Using:CheckHeartbeat
        ${function:Wait-For}        = $Using:WaitFor

        if (Wait-For -VMName $_.Name -Credential $_.Credential @VerboseSplat @TimeWaitedSplat -Force)
        {
            Write-Verbose -Message "Certutil pulse $($_.Name)..." @VerboseSplat
            Invoke-Command -VMName $_.Name -Credential $_.Credential -ScriptBlock {

                certutil -pulse > $null
            }
        }
    }

    #######
    # ADFS
    #######

    if ($SetupAdfs -and
       (Wait-For @ADFS @Ac0 @VerboseSplat @TimeWaitedSplat @StartedVMsSplat))
    {
        if ($DcUpdateResult.AdfsDkmGuid)
        {
            Write-Verbose -Message "ADFS Dkm Guid: $($DcUpdateResult.AdfsDkmGuid)" @VerboseSplat

            Invoke-Wend -NoOutput -TryBlock {

                .\VMSetupADFS.ps1 @ADFS @Ac0 @VerboseSplat `
                                  -CATemplate "$($DomainPrefix)ADFSServiceCommunication" `
                                  -AdminConfigurationGuid "$($DcUpdateResult.AdfsDkmGuid)" `
                                  -ExportCertificate
            } -WendBlock {

                $Wend = $false

                if ($Result.WaitingForResponse)
                {
                    $Wend = $true

                    if (Check-Heartbeat @SubCA)
                    {
                        Write-Verbose -Message "Issuing ADFS Certificate with RequestId $($Result.WaitingForResponse)" @VerboseSplat

                        Invoke-Command @SubCA @Ac0 -ScriptBlock {

                            Certutil -resubmit $Using:Result.WaitingForResponse > $null
                        }
                    }
                }
            }
        }
    }
}

End
{
    Write-Host "Totaltime: $($TotalTime.ElapsedMilliseconds/1000/60) min."
    Write-Host "Time waited: $($TimeWaited.Value/1000/60) min."

    $TotalTime.Stop()
    $TotalTime = $null
}

# SIG # Begin signature block
# MIIesgYJKoZIhvcNAQcCoIIeozCCHp8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAEBTKFy1/hkzaC
# H08P7RaXNpVQEHjO3lq8bPkSrHbEg6CCGA4wggUHMIIC76ADAgECAhB0XMs0val9
# mEnBo5ekK6KYMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBUowTjdFMB4XDTIz
# MDkwNzE4NTk0NVoXDTI4MDkwNzE5MDk0NFowEDEOMAwGA1UEAwwFSjBON0UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRw1gJO1wnpdRIbqVo1gfsnMV8
# kxOJBp/FDV1XxyN0njKwlcA6zyudii33AqXYWUojp4xPoXzBGkVuoqqZOkSXHMz5
# /OScP3fe4QEtIC6X9vSQuWvo9jaih0kLbRUEBTG2EVRiHsVyeLR3DPgSNckbGJ54
# MMtlhFPchHo/N7BpaGrUtdjd+F59hDVDaeoe6VVYPVaC5yAgUR9QkJZw69+YkET4
# S+Q09WgoCoXEnrVnnjPzLq0iN0rdSOrhuBE5CouwUwr6YgjU6pwtEoyBaRUhL2cd
# 8UXLzVUgy9+Bo6mhJUtq1ujECc6afx26wkDYMwfo4vTdIgFv8XATvrvWyO0a4ZGn
# 6eU+eS+hWoURP2iVlYPGUY555F1NzeOVwQ9v1cumIaOVB8x+TjJxLCtomqfVxgO9
# JeHcrqW/Q55Itr9VBGUSk6a20oEQj94UwrvoNmkbEW+/XE6DWmHf7TWEJug5d4+7
# 2pI2TmGcisERv16qSzevlkN+uUTCMVSF32Qt7ZQoRocrscj37fHVaFOA1EpbMrOp
# RwX1pWWkNBGmWptQwkTMzHNFQiTTU0OrDjqCNRh63pWcg+qdAB7ZstaoMx4vdfo/
# twAfHDTnI403nUyrIEV1gLUyJ5i5Tgw6gh8g3ozq8Qaftq+PD1rhel+ByG23LZ42
# AhGD4q4ndfG13VEONQIDAQABo10wWzAOBgNVHQ8BAf8EBAMCBaAwKgYDVR0lBCMw
# IQYIKwYBBQUHAwMGCSsGAQQBgjdQAQYKKwYBBAGCNwoDBDAdBgNVHQ4EFgQUWNAE
# eD3ij461l5HFCgfSYoXMwCkwDQYJKoZIhvcNAQELBQADggIBAFKCUuzQ8KfuDfqI
# ZG+peeD9+r7qcvdlIt4tRdIOgVcqEncrrAVKIcEm0Fi1Zzs6cchsiDUUUUCLkYg/
# nowzCY3g2hjQOsE3QaWHgmr+WG6JqHnOz/2/9pS+3C8EPg1VfQb/Am5G5fr3tRBm
# u2RaeKcHjoEw9T6ASDVy2fRXjNDd9rOtyYmoP3EjAqU5ey/E4A7k4nnW5x2y5sPp
# CQlr77hsZ3keGgLz87XybHPphhqA6ddYk5vJuTB2QML0xSPLnBk0C/jwORQz44Ct
# t8zdml9wBVOcOt+7Omg4pORx2Bs37hVckL+XLUP3x/4ikQ7DVQi1fweDrtZ9T2xd
# whj5+CHMc8cXzri+nYX8bvmLTYyip5Gl47eC7C6bcNsoKQq2zlLVBecTumZ6p7hT
# n3mMJWEQt4HqJ+u+PS6VKU5TkYS3A1jlUvRPdwd6AGa1BcV9ChPq9ugXqb0juRWU
# oZPhYjwz9RBgJDZk/cdON1Ie31RwmyUYyoPGFuQYsfj0RI/mCFtF12WXbh2zDR0X
# 3qU4gSaEHTVQ0jPjROietordyS4l2euH/Z8dhvJwYeOSjCIxQlBqKFtkFEq8EeGs
# zs65D3oz2DwaTZEIip1fSU7yfbJLx+fMShZ7wVXATluADk3CXqJh2izO5tiCH6yJ
# Ux7YQVpSHQNdeltDcnGMwZ7mpUrXMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
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
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrwwggSk
# oAMCAQICEAuuZrxaun+Vh8b56QTjMwQwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0y
# NDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5NTlaMEIxCzAJBgNVBAYTAlVTMREwDwYD
# VQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+anOf9pUhq5Ywultt5lmj
# tej9kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/i+utMeV5bUlYYSuuM4vQngvQepVH
# VzNLO9RDnEXvPghCaft0djvKKO+hDu6ObS7rJcXa/UKvNminKQPTv/1+kBPgHGlP
# 28mgmoCw/xi6FG9+Un1h4eN6zh926SxMe6We2r1Z6VFZj75MU/HNmtsgtFjKfITL
# utLWUdAoWle+jYZ49+wxGE1/UXjWfISDmHuI5e/6+NfQrxGFSKx+rDdNMsePW6FL
# rphfYtk/FLihp/feun0eV+pIF496OVh4R1TvjQYpAztJpVIfdNsEvxHofBf1BWka
# dc+Up0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZIqi6viEk3RIySho1XyHLIAOJfXG5
# PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj5KGg4YuiYx3e
# Ym33aebsyF6eD9MF5IDbPgjvwmnAalNEeJPvIeoGJXaeBQjIK13SlnzODdLtuThA
# LhGtyconcVuPI8AaiCaiJnfdzUcb3dWnqUnjXkRFwLtsVAxFvGqsxUA2Jq/WTjbn
# NjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi6n2PzP0nVepsFk8nlcuWfyZLzBaZ
# 0MucEdeBiXL+nUOGhCjl+QIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WM
# aiCPnshvMB0GA1UdDgQWBBSfVywDdw4oFZBmpWNe7k+SH3agWzBaBgNVHR8EUzBR
# ME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSB
# gzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsG
# AQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2EdubTggd0ShPz9Pce4FLJl6reNKLkZd5
# Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9NJxUl4JlKwyjUkKhk3aYx7D8vi2mpU1t
# KlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz57yFq6laICtKjPICYYf/qgxACHTv
# ypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlWjNlHlFFv/M93748YTeoXU/fFa9hW
# JQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZU1WM6nyw23vT6QSgwX5Pq2m0xQ2V
# 6FJHu8z4LXe/371k5QrN9FQBhLLISZi2yemW0P8ZZfx4zvSWzVXpAb9k4Hpvpi6b
# Ue8iK6WonUSV6yPlMwerwJZP/Gtbu3CKldMnn+LmmRTkTXpFIEB06nXZrDwhCGED
# +8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpPddOFkM2LlTbMcqFSzm4cd0boGhBq
# 7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwXu7nMpFu3mgrlgbAW+BzikRVQ3K2Y
# HcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2QwQ/l4Gxftt/8wY3grcc/nS//TVk
# ej9nmUYu83BDtccHHXKibMs/yXHhDXNkoPIdynhVAku7aRZOwqw6pDGCBfowggX2
# AgEBMCQwEDEOMAwGA1UEAwwFSjBON0UCEHRcyzS9qX2YScGjl6QropgwDQYJYIZI
# AWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgJdwZsTiF7hrjR2xXXqgmixu75kW/hfk8nE+JgQbbfnYw
# DQYJKoZIhvcNAQEBBQAEggIAuXn+2ixbIrpzWq4DcA0iQJlE0COKH/BPMgo79mWQ
# Z1D2T3yVLh1GqIDfG9dYJFRjhGffASvv9N5FstNJtHUJ2Ip6YRwYX0VFlREs9vip
# jIerWk6ee/uSZ6OPzQQ+u+bgzmq/C8kf6PCR+7vv6QNN66Qm8jtiSuSNJ9O7iByD
# 9KxDoo7fCoB9aPwQ+f6oyMJPcI5KncpCaChpOyqv4lE1yhoOWwhBnYOXl2X6zdMz
# I3RCl0jQQfP/PoNbrk+HCR0JdNxEoHYhs7Hziu6a+wNcPcwNk/hbyT38pYFGNUV4
# 2wTySoIJcqUagfd1wfTBj7AiOTs24G0BkpEESF80GFf5oRQ3XbhpYTvghPFmRFAh
# OGjZiF5ZdIIch9I6GaJ7TvG2zqL11LfxokzBNXgSgjoJrXtXGVF7huwIcnnryDpE
# hBFvhmSgAMEHC/s2TJJS+kCgARDFkIQlrRX+2Zd6Jown9xR3OuS/T57Dxtk4fIla
# LI4Z+klgx0d/D2yJFF4zC62P5RUgLOthfT9RYxXEBt6uv4OqNMlcQUNj1K8AslgY
# /v0POfUg/VEHGVzwKcgJi9KHPNEtM/x1pRDAqT/kYuzBh3ws8n7aJ92v2q4aZnW3
# t2oT6w1qONGTPkG2ncCwY191lWVzoUzvl4ZbGmbx5uwGnNrlUmLwhih2rNPhoy5Y
# STKhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhALrma8Wrp/
# lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwNjI1MDAxNjE2WjAvBgkqhkiG9w0BCQQx
# IgQg0oui814p9cSnFacBs3rXnMx3GyodE5QGumNs/ZDj/a4wDQYJKoZIhvcNAQEB
# BQAEggIAQAECybaOlst+5nA4ncFWxFlVVJohVRFhAbRi1lNkVOpfOWQVMKSEZ9VA
# Vyg72Bax5NtzhPxapQamLJjO5Kyb/7St1C/qB0qDmqAmj0Mb5wCWBxRnlqaJjBPo
# sZJog/W0EwnQoQt/NqFv1dVCsplndyn334fdGD6qNzsS4eFnmY2KEZ7a/BfMbH5i
# esddxk8v74HJHeFjlUkdNq/W7UAIAejYsDw6xX7WtODVRG/y6ZBU7uBFgffjofXr
# jhRLVX0qkmWXN+tzSVPjreelIJ6v6d9oibWNI3Jq8td2HAdDJAneRp5BD0suopca
# x+0HU2260mW3jt/f7HDA7PlWYAZLqyjRomegK5YEyvU1Tu9zrJ8SyUZpajqbbQoo
# sCiDSxuRXaUVADnSn33aWgjcwZ0Y4e1gizWh+grczjsUhT2vkN+WScetOMVH0v8n
# udvS8U0CKxlV+1aNweJsk5WaseKz4jWybFXaqQqMkUdDI9NKUxt1rP5HYULNG74O
# /y6C96v9rOpIEQWafjyMTrhaKsh1FXXsbKME7jf28MHx5Dg349A2iGi0sefg1jL7
# P2bIGMWOY8ZPIMIpC06uvMuDhmkGnyR0X3iEr6RBPWFkk8o9etDRl4B4sy37mNzU
# GMbXVck6sebupKrHUwPLPoMfgK1UTtV2MHLIFNI3WsIrRgVo0r0=
# SIG # End signature block
