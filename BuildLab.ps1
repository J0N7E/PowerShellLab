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
            DC3    = @{ Name = 'DC03';    Domain = $false;  OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Dac; }
            SubCA  = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            AS     = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            ADFS   = @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            WIN    = @{ Name = 'WIN11';   Domain = $true;   OSVersion = '*11 Enterprise x64 23H2*';  Switch = @('Lab');  Credential = $Settings.Ac2; }
            #NPS    = @{ Name = 'NPS01';   Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            #RAS    = @{ Name = 'RAS01';   Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac1; }
            #RATDC  = @{ Name = 'RATDC';   Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.AcDc; }
            #RAT0   = @{ Name = 'RAT0';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
            #RAT1   = @{ Name = 'RAT1';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac1; }
            #RAT2   = @{ Name = 'RAT2';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac2; }
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
# MIIejQYJKoZIhvcNAQcCoIIefjCCHnoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+8HDgf7rTeAIQnHSyrzPubUF
# xaSgghgOMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwgga8MIIEpKADAgECAhALrma8Wrp/lYfG+ekE
# 4zMEMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjQwOTI2MDAwMDAwWhcNMzUxMTI1
# MjM1OTU5WjBCMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxIDAeBgNV
# BAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDI0MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvmpzn/aVIauWMLpbbeZZo7Xo/ZEfGMSIO2qZ46XB/QowIEMS
# vgjEdEZ3v4vrrTHleW1JWGErrjOL0J4L0HqVR1czSzvUQ5xF7z4IQmn7dHY7yijv
# oQ7ujm0u6yXF2v1CrzZopykD07/9fpAT4BxpT9vJoJqAsP8YuhRvflJ9YeHjes4f
# duksTHulntq9WelRWY++TFPxzZrbILRYynyEy7rS1lHQKFpXvo2GePfsMRhNf1F4
# 1nyEg5h7iOXv+vjX0K8RhUisfqw3TTLHj1uhS66YX2LZPxS4oaf33rp9HlfqSBeP
# ejlYeEdU740GKQM7SaVSH3TbBL8R6HwX9QVpGnXPlKdE4fBIn5BBFnV+KwPxRNUN
# K6lYk2y1WSKour4hJN0SMkoaNV8hyyADiX1xuTxKaXN12HgR+8WulU2d6zhzXomJ
# 2PleI9V2yfmfXSPGYanGgxzqI+ShoOGLomMd3mJt92nm7Mheng/TBeSA2z4I78Jp
# wGpTRHiT7yHqBiV2ngUIyCtd0pZ8zg3S7bk4QC4RrcnKJ3FbjyPAGogmoiZ33c1H
# G93Vp6lJ415ERcC7bFQMRbxqrMVANiav1k425zYyFMyLNyE1QulQSgDpW9rtvVcI
# H7WvG9sqYup9j8z9J1XqbBZPJ5XLln8mS8wWmdDLnBHXgYly/p1DhoQo5fkCAwEA
# AaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUn1cs
# A3cOKBWQZqVjXu5Pkh92oFswWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRp
# bWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAPa0eH3aZW+M4hBJH
# 2UOR9hHbm04IHdEoT8/T3HuBSyZeq3jSi5GXeWP7xCKhVireKCnCs+8GZl2uVYFv
# Qe+pPTScVJeCZSsMo1JCoZN2mMew/L4tpqVNbSpWO9QGFwfMEy60HofN6V51sMLM
# XNTLfhVqs+e8haupWiArSozyAmGH/6oMQAh078qRh6wvJNU6gnh5OruCP1QUAvVS
# u4kqVOcJVozZR5RRb/zPd++PGE3qF1P3xWvYViUJLsxtvge/mzA75oBfFZSbdakH
# Je2BVDGIGVNVjOp8sNt70+kEoMF+T6tptMUNlehSR7vM+C13v9+9ZOUKzfRUAYSy
# yEmYtsnpltD/GWX8eM70ls1V6QG/ZOB6b6Yum1HvIiulqJ1Elesj5TMHq8CWT/xr
# W7twipXTJ5/i5pkU5E16RSBAdOp12aw8IQhhA/vEbFkEiF2abhuFixUDobZaA0Vh
# qAsMHOmaT3XThZDNi5U2zHKhUs5uHHdG6BoQau75KiNbh0c+hatSF+02kULkftAR
# jsyEpHKsF7u5zKRbt5oK5YGwFvgc4pEVUNytmB3BpIiowOIIuDgP5M9WArHYSAR1
# 6gc0dP2XdkMEP5eBsX7bf/MGN4K3HP50v/01ZHo/Z5lGLvNwQ7XHBx1yomzLP8lx
# 4Q1zZKDyHcp4VQJLu2kWTsKsOqQxggXpMIIF5QIBATAkMBAxDjAMBgNVBAMMBUow
# TjdFAhB0XMs0val9mEnBo5ekK6KYMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEM
# MQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRXHrMipBJ4mb9b
# DxhOQQWds6eZjTANBgkqhkiG9w0BAQEFAASCAgBoZJsMNZt3baoBFWEaOb0gaR/2
# 60SYq6gRICWryvwcLMPC/J2I1B7g4/8HiA/ihzUy705sYEQv2iDJuxx/LEw/bsCF
# //FgAzglkoFig8nMg7jBDwG1uTcK0+TrBe6bGU5SX14Dn0URBr+pWW+Bp9hM2gbH
# jighOBHz77QceFFryqfPpba+oDdLE0JDmw8kRKVVn+PzUGDtLP//x6wnKBFm5Peb
# d1XKO88CmFY6eeIfBiFf/2U1cgYEwlxOGkuGUdOQNISUnFMyFqSluD02lTRgRIrb
# BezIuMuTleN1D9fW4tKzeXmdHxD7JKJrJsYWz3rt4gwaNAWb5U52rF16bDnsDfCM
# lOaWN8LhePRuCe5puNHaXvk72Z3SvolLnSlDmtQJJ45pZz6bmTZwkG3xbBuZLuTJ
# E/LGnWtgi45Sgu9lNFZVpz9wpNDsTFSEeM08Qd8Ntlf24Euk+eZsGJwEByvXnxFY
# DjutA0WPBuoGsW9l41u2EbUzQ3uJRLKaTEQxJOEbm8RxnO0QSGj927qmhvhxOr9Y
# Ca754aniALguS226KjmpoH+SwGuxu30e78JuzlonsYS7tP+xjEN+YzpBGAVsyX3e
# HYMe52ZDxFdA4uoB9XpVz7649YrSH6R63W10C7UZ4TfEAR6PkzXOsTJks9d5x2SC
# qbsf44jhyy3gAmaPA6GCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0ECEAuuZrxaun+Vh8b56QTjMwQwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNDEwMjQxNTAwMDdaMC8G
# CSqGSIb3DQEJBDEiBCBi0aoOKGvdnYFZjUd3AoEHINMXfdNksjuKoDK4s3VUCTAN
# BgkqhkiG9w0BAQEFAASCAgAQf4+SqK/DAEWCNjhyJK/EM4HgFkvMREvGZQjBZAdp
# EAUxgmsoCh5zu2IFVF/VpYIYCd1+ldDqcao/YRbja/JY7WR3F6LRPJnEpBYs0WaI
# 4tXoyTHGZfb5A1WvbAXZIMJxqDYt10Su3VqmeC+AfoaJ+m76YU8KXTpOhlhEzcsz
# JyWCIuN3RkcvUPDZ4L13wJS+AnVGGEPWrQLLtjxxx5cIClzLo6rEArrf+WaOUz2t
# JHkG0fU9K1dTW70gID+jqnc4F7hsIuDLB48ku5fTWy/nHoHSUOek0xzVfoaJ283x
# IOa/gWPBgmcOMoF/A8zTVtBGlcE00KsVAaaWbyod1DJwgLU/42oo85MaJk6DfCcx
# dndy2ieevKEofeQAc/TrRmLtcZHiQ3zqcio9JVqG+kNNx+YYR3YIPwr4mOcSeYB+
# flqWm7I/mSw6YiAgf36SUK/U3UaOcIC9CU42tEvMifWN3n9wQmzBFRaCR3qqWm2T
# 3It7ZVbEsHcbrDoHNNTL+AMnXaWDjdkoHMHApV1aHhDlJ5tSxM3mUXO7lZmGOLNF
# xsBGRMx3fNqPatgfPldNn1ahP9rnKwlXU5B1IY9d+Zh37nOgMX+o0vD0QGFyLZ46
# mvw2habCM+9sdNgywFD2k+K6fHxZbx9cZQmrPECIUNc3CUrG1HmS6y0PxuIvDhPL
# HQ==
# SIG # End signature block
