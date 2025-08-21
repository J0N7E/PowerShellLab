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

            RootCA = @{ Name = 'CA01';    Domain = $false;  OSVersion = '*Experience x64 21H2*';     Switch = @();       Credential = $Settings.Lac; }
            DC     = @{ Name = 'DC01';    Domain = $false;  OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Dac; }
            SubCA  = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            AS     = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            ADFS   = @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            WIN    = @{ Name = 'WIN11';   Domain = $true;   OSVersion = '*11 Enterprise x64 23H2*';  Switch = @('Lab');  Credential = $Settings.Ac2; }
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
# MIIeygYJKoZIhvcNAQcCoIIeuzCCHrcCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUR2sAgcyLt9M9TV+jMosXUhz0
# d5SgghhFMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMCAQIC
# EA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAw
# MDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmW
# gyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzb
# NfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPs
# YfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBK
# S7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmU
# PAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7z
# L2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHK
# S+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4
# /6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogx
# G9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbV
# RSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNT
# AgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK
# 6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUH
# AQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYI
# KwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc
# /gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAz
# aoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q
# 8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntu
# jB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2
# rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z
# 0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVG
# yOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxO
# GLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB
# /8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3
# IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8
# EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43x
# BYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAw
# MDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRp
# bWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7
# C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281m
# HrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUue
# HTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw
# 44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBS
# ai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvh
# DU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5
# J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIU
# bWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJ
# RE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CID
# BbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOC
# AZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPP
# YYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQE
# AwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcw
# AoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYw
# VKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEc
# JwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz
# 9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7
# YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8l
# D8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42
# fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz
# +BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJ
# nzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7
# weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH
# 3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ue
# Iu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6I
# Ls84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIF7zCCBesCAQEwJDAQMQ4wDAYD
# VQQDDAVKME43RQIQdFzLNL2pfZhJwaOXpCuimDAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUNVvw
# x/2Sh80iqiCv96+1GWPx+4EwDQYJKoZIhvcNAQEBBQAEggIAs878I/JlXRscNhAI
# LIxwSq0rztp9PSvLbO7yvbJDohBBqgML92zv7siBW/kkTZboJ2OT2NT8SZiB2f5Y
# h1KTOiPAfoPAmcIvBt7A+rfleRTHqGLfoM5RJuGT/7KfV34JOdq5nN/BbM5g0rC4
# xLRlQ2bUG/Blc50I9s+hxnzUo7mNO+XYKUBenOWWVAJ9IlTtVyXehmEIquT3FMyz
# KQo2KtWFnnk8f57LcyQuGdoiaRCXcmzl/QSi2QE97VXXIQ2E6LX7pqpY/xOKqKwL
# 4N9enNunBKWVDULvPjVePDgFK7TuVL8cshhGgS+c1bC+W4MVgOaQTMO4YHDjGfD2
# 0Z0hU6TejjbbsAjIanphq28TvCpOHM2jo2zKfXhWBh5dAWOLzUh8FsPj49OKmOWt
# 9XSAyj/avhxT+pGhiuc6ncWoxp8MeESim1v2pMOttfINcZTKbIJS58D8dBIIzRDx
# g4mTkLcTmfEfZuFQW538dEYinX1nlTpWJ7Aim9pl+9DSEpR89SA4BiARSBV83HOP
# xk9rOsiRYV4tW4UNJPAREK4bTAlxfVj5YO5h/7wBB+c2qgegY+0mPj7j32np41Lp
# Bn1MXSElE/zW+X5XN6pcg1FaHigcqIVz36ZjJHeM25PHXR0c1TAhsUVyyanxkh/R
# 5baMD9yiNL5CyX5IGMWiD6qgmmqhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8C
# AQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYg
# U0hBMjU2IDIwMjUgQ0ExAhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUA
# oGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
# ODIxMTMwMDAxWjAvBgkqhkiG9w0BCQQxIgQgEL7riYUgrfAcg7XgUbzapMh6/yEi
# 48x/pL6x/bmF2ywwDQYJKoZIhvcNAQEBBQAEggIAyKgibUK+NpZRCCbzOqJ8xuQ9
# DCk7z5Hd98VPdWkJl+ygE3LNYWleH30TBs7u8I56cMlg+B8cdCI35ggmdcxrGqiE
# 7CZn46D6g/K9aShgWI2amdguRwodgjAUfRCdurNScv76bRIJ8eb7xqUJDbO2JFy/
# S0+JXa0XbOEtE0Gauyelyc4KggZfikBfzjpB9icLfWGIu1ekbzuG1mfKztfPxLHK
# z9lSek8mP4/Fa3PqNdcmaRcKFk87H/X7XgGUVoNZg4fih6bAOJ+aNJtz4OBUYbU5
# hiz8kK1/3YIyRqb3/gykPl+12CPeAFeWT4XVua9loB/eeVFX2RRhX1NSFBK7VFmN
# 1IuQfO6EslMnK5ugl3hJASRWhaL8KpJfQo6rvk+KZMGkEGsCu8wV0neT8kApfuEm
# r2dKJ4jPZm7gvpRaBqVgk7QV1PfIGJ7jBxKK8pRO6qJTWPTENjxEBoYLYdk23QJG
# xT/NFiG9xIpdOM0/bfbNdr+B6DcwJejs0kYu6OMR97nvxj3P0RMpoq2/icGcj/Ig
# DmUOY0CK8+DNBlUYong4Hs//PwmZmgOwULrVhBdHJrS9tREU1KkYX6ffo7Eh1CAu
# DxCaypyjzoLSR7SoaOUj/eDyFQCJldKQHHC7oo4c4U3YZFnqqscHS4u+Bj5a4qkF
# TjOpcW+sMUnQ5uSFLsI=
# SIG # End signature block
