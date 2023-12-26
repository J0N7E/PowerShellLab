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
    [String]$HvDrive = "$env:SystemDrive",

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
    }

    $DomainNetbiosName = $DomainName.Substring(0, $DomainName.IndexOf('.'))

    $Settings =
    @{
        DomainName = $DomainName
        DomainNetbiosName = $DomainNetbiosName
        DomainPrefix = $DomainNetBiosName.Substring(0, 1).ToUpper() + $DomainNetBiosName.Substring(1)
    }

    # Password
    $Settings += @{ Pswd = (ConvertTo-SecureString -String 'P455w0rd' -AsPlainText -Force) }

    # Get credentials
    $Settings +=
    @{
        Lac    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".\administrator", $Settings.Pswd
        Dac    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\Admin')", $Settings.Pswd
        Ac0    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\Tier0Admin')", $Settings.Pswd
        Ac1    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\Tier1Admin')", $Settings.Pswd
        Ac2    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\Tier2Admin')", $Settings.Pswd
    }

    $Settings +=
    @{
        Switches =
        @(
            @{ Name = 'Lab';     Type = 'Private';   NetworkId = '192.168.0';  GW = '192.168.0.1';  DNS = '192.168.0.10' }
            @{ Name = 'LabDmz';  Type = 'Internal';  NetworkId = '10.1.1';     GW = '10.1.1.1';     DNS = '10.1.1.1'     }
        )
        VMs =
        [ordered]@{
            RootCA     = @{ Name = 'CA01';    Domain = $false;  OSVersion = '*Desktop Experience x64 21H2*';  Switch = @();                 Credential = $Settings.Lac; }
            DC         = @{ Name = 'DC01';    Domain = $false;  OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab');            Credential = $Settings.Dac; }
            SubCA      = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab');            Credential = $Settings.Ac0; }
            AS         = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab');            Credential = $Settings.Ac0; }
            #NPS        = @{ Name = 'NPS01';   Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab');            Credential = $Settings.Ac0; }
            #RAS        = @{ Name = 'RAS01';   Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab', 'LabDmz');  Credential = $Settings.Ac0; }
            WIN        = @{ Name = 'WIN11';   Domain = $true;   OSVersion = '*Windows 11 Enterprise x64*';    Switch = @('Lab', 'LabDmz');  Credential = $Settings.Ac2; }
        }
    }

    if ($SetupAdfs -eq $true)
    {
        $Settings.VMs += @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab');            Credential = $Settings.Ac0; }
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

                    # Wait for VM
                    Wait-VM -VMName $VMName -For Heartbeat -Timeout ($Threshold/10)
                    Wait-VM -VMName $VMName -For MemoryOperations -Timeout ($Threshold/10)

                    # Check if ready
                    try
                    {
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

                        Start-Sleep -Milliseconds 25
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

                        Write-Warning -Message "$VMName not responding, stoped threshold timer after $($VmReadyDuration.ElapsedMilliseconds) ms." @VerboseSplat

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

    $Settings.VMs.Values | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel { $VM = $_

        # Set variables
        $OsdPath      = $Using:OsdPath
        $HvDrive      = $Using:HvDrive
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
                LabFolder = "$HvDrive\HvLab"
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
                                             -DomainName $Settings.DomainName `
                                             -DomainNetbiosName $Settings.DomainNetBiosName `
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
                        -CACommonName "$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)" `
                        -CADistinguishedNameSuffix "O=$($Settings.DomainPrefix),C=SE" `
                        -DomainName $Settings.DomainName > $null
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
                                          -CAConfig "$($Settings.VMs.RootCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)" `
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
                            -DomainName $Settings.DomainName `
                            -DomainNetbiosName $Settings.DomainNetBiosName `
                            -DomainLocalPassword $Settings.Pswd `
                            -GPOPath "$LabPath\Gpo" `
                            -BaselinePath "$LabPath\Baseline" `
                            -TemplatePath "$LabPath\Templates" > $null
        }

        # Initialize
        $DomainJoin = @()

        if ($NewVMs.Count)
        {
            $NewVMs.Keys | ForEach-Object @VerboseSplat { $VM = $_

                # Check if domain joined vm
                if ($Settings.VMs.Values | Where-Object { $_.Name -eq $VM -and $_.Domain })
                {
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

                    # Set to domainjoin vm
                    $DomainJoin += $VM
                }
            }

            # Add new computer object
            $Result = Invoke-Command @DC @Lac -ScriptBlock {

                # Set variables
                $DomainJoin      = $Using:DomainJoin
                $DomainName      = $Using:DomainName
                $VerboseSplat    = $Using:VerboseSplat
                $Result          = @()

                foreach ($Computer in $DomainJoin)
                {
                    if (-not (Get-ADComputer -Filter "Name -like '$Computer' -and ObjectCategory -eq 'Computer'" -ErrorAction SilentlyContinue))
                    {
                        # Set joinblob path
                        $JoinBlobFullName = "$env:TEMP\Join-$Computer.blob"

                        Write-Verbose -Message "Djoin $Computer to $DomainName..." @VerboseSplat

                        djoin.exe /PROVISION /DOMAIN $DomainName /MACHINE $Computer /SAVEFILE "$($JoinBlobFullName)" > $null

                        # Get blob
                        $JoinBlob = Get-Item -Path "$($JoinBlobFullName)"

                        # Return blob
                        $Result += @{ File = @{ FileObj = $JoinBlob; FileContent = (Get-Content -Raw -Encoding Byte -Path $JoinBlob.FullName); }}

                        # Cleanup
                        Remove-Item -Path "$($JoinBlob.FullName)"
                    }
                }

                Write-Output -InputObject $Result
            }

            # Handle result
            if ($Result)
            {
                foreach($Row in $Result)
                {
                    if ($Row -is [Hashtable])
                    {
                        foreach($Item in $Row.GetEnumerator())
                        {
                            # Save in temp
                            Set-Content -AsByteStream -Path "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -Value $Item.Value.Item('FileContent')

                            # Set original timestamps
                            Set-ItemProperty -Path "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -Name CreationTime -Value $Item.Value.Item('FileObj').CreationTime
                            Set-ItemProperty -Path "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -Name LastWriteTime -Value $Item.Value.Item('FileObj').LastWriteTime
                            Set-ItemProperty -Path "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -Name LastAccessTime -Value $Item.Value.Item('FileObj').LastAccessTime

                            # Move to script root if different
                            Copy-DifferentItem -SourcePath "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -RemoveSourceFile -TargetPath "$PSScriptRoot\$($Item.Value.Item('FileObj').Name)" @VerboseSplat
                        }
                    }
                    else
                    {
                        Write-Warning -Message 'Unexpected result:'
                        Write-Host -Object $Row
                    }
                }
            }
        }

        # Publish root certificate to domain
        .\VMSetupCAConfigureAD.ps1 @DC @Lac @VerboseSplat `
                                   -CAType StandaloneRootCA `
                                   -CAServerName $Settings.VMs.RootCA.Name `
                                   -CACommonName "$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)"
    }

    ##############
    # Renew lease
    # Join domain
    # Reboot
    ##############

    $Global:JoinedDomain = @{}

    $NewVMs.Keys | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel { $VM = $_

        # Set variables
        $VerboseSplat = $Using:VerboseSplat
        $Lac          = $Using:Lac
        $Settings     = $Using:Settings
        $JoinedDomain = $Using:JoinedDomain
        $StartedVMs   = $Using:StartedVMs

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

        if ($Result.Joined)
        {
           $JoinedDomain.Add($Result.Joined, $true)
           $StartedVMs.Add($Result.Joined, $true)
        }

        #FIX
        if ($Result.Renamed)
        {
            $StartedVMs.Add($Result.Renamed, $true)
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
                            -DomainName $Settings.DomainName `
                            -DomainNetbiosName $Settings.DomainNetBiosName `
                            -DomainLocalPassword $Settings.Pswd
        } -WendBlock {

            $Wend = $false

            switch ($Result.Keys)
            {
                'BuildNotFound'
                {
                    $Result.BuildNotFound.Keys | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel { $VM = $_

                        # Set variables
                        $Lac             = $Using:Lac
                        $VerboseSplat    = $Using:VerboseSplat
                        $TimeWaited      = $Using:TimeWaited
                        $TimeWaitedSplat = $Using:TimeWaitedSplat

                        # Set functions
                        ${function:Check-Heartbeat} = $Using:CheckHeartbeat
                        ${function:Wait-For}        = $Using:WaitFor

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
        $DcUpdateResult.ComputersAddedToGroup.Keys | ForEach-Object @VerboseSplat @ThrottleSplat -Parallel { $VM = $_

            # Set variables
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
                                          -CAConfig "$($Settings.VMs.RootCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)" `
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
                            -CACommonName "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)" `
                            -CADistinguishedNameSuffix "O=$($Settings.DomainPrefix),C=SE" `
                            -PublishAdditionalPaths @("\\$($Settings.VMs.AS.Name)\wwwroot$") `
                            -PublishTemplates `
                            -CRLPeriodUnits 180 `
                            -CRLPeriod Days `
                            -CRLOverlapUnits 14 `
                            -CRLOverlapPeriod Days
        } -WendBlock {

            $Wend = $false

            if ($Result.WaitingForResponse)
            {
                $Wend = $true

                if (Test-Path -Path "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)-Response.cer")
                {
                    Write-Warning -Message "No root CA response match the sub CA request."
                    Read-Host -Prompt "Press <enter> to continue"
                }
                elseif (Check-Heartbeat @SubCA)
                {
                    # Issue sub ca certificate
                    .\VMSetupCAIssueCertificate.ps1 @RootCA @Lac @VerboseSplat `
                                                    -CertificateSigningRequest "$LabPath\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)-Request.csr"
                }
            }
        }
    }

    # Cleanup
    if ($SubCaResult.CertificateInstalled)
    {
        Remove-Item -Path "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)-Request.csr" -ErrorAction SilentlyContinue
        Remove-Item -Path "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)-Response.cer" -ErrorAction SilentlyContinue
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
                                          -CAConfig "$($Settings.VMs.SubCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)" `
                                          -ConfigureOCSP `
                                          -OCSPTemplate "$($Settings.DomainPrefix)OCSPResponseSigning"
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

    if ($SetupAdfs -eq $true -and
       (Wait-For @ADFS @Ac0 @VerboseSplat @TimeWaitedSplat @StartedVMsSplat))
    {
        if ($DcUpdateResult.AdfsDkmGuid)
        {
            Write-Verbose -Message "ADFS Dkm Guid: $($DcUpdateResult.AdfsDkmGuid)" @VerboseSplat

            Invoke-Wend -NoOutput -TryBlock {

                .\VMSetupADFS.ps1 @ADFS @Ac0 @VerboseSplat `
                                  -CATemplate "$($Settings.DomainPrefix)ADFSServiceCommunication" `
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
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8OIs2C9uSGG6hPANL8Q3mvRp
# J1WgghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQyu9Ib
# SJNc09hw6zoHpg4LiLxFTTANBgkqhkiG9w0BAQEFAASCAgAcL3odSu0JAT1DedYj
# VnWjeZNMrzTatKQSjpKaLO95AknBiI/0fuyzwAjueSADmyP23hMJh17OFApUIDtM
# A8VmmYLipWz1FhoYOaAr6+L9r1u7XgPg/wMSJp+Hjoqpv0Aq+TySIsMvOxaewHg1
# rVXDrROoUxACW3QQlVsJ77BerrMwHYe/7bynVbnEDdgf/fzYTZ7jv+PZinosFnsA
# mZFg02w7xkXDU4gn4Y+4NClueYcuRiXCLu+Vbm8ayTGzh+wFvSAbzEz2trXimzW2
# VYQY7UuqsZ4HtUW9n5UOOGPI9l9a0d7YcT2zZYeoerFD8xchQdjsfwdzvghXij7s
# xkQu0z4a/B2ZeJSV5KWRhtECpK3VDlMsvw3Dcd/2rtr1ShOLEj5+D58bC57yoCYp
# zh4WEuB+3/J5dLPEm5v9FC1tO++TiT9xt0tN7b/YkpDMqN2CS0wBBkhCkpOnK4m6
# Czd6hg7i+OrcQwTOCpWzQovSOIze4SsYeqazDpAPcgMpXOBwWJn3GHmFDFLeLl7y
# oyKQApt0UOfHnjpEMr3BIkrsSLBLa7/VHjD13Pa6pF8uxJqYEXdSzJ2mU2jlNHQK
# TKLH6jyJChTkivoMFJA4orJbzPzIWAZbCig+VQEq/QVe6ol7drnrpbAJH3Er1/ds
# cvw4E/sQJsnV/LjGsdXVX+fI66GCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzEyMjYyMDU5
# NTlaMC8GCSqGSIb3DQEJBDEiBCBzEq5K7xqT1IzqDi47isRiPAErB/WFilAks/rp
# V2LJXzANBgkqhkiG9w0BAQEFAASCAgAmIHrsQOzZQOEeASL6AR79d/0TRtjGkbjW
# /VFUtG/5JeBZoSIm3MhTM8DG1VSHN8IteqK7sw8xRiZG2MrJqDONd2h6S7x2oep6
# XNypJW90X4wbP4+DCzx1cSACaCMUIwu12l7BRV3LJtJ1c9J2YG2lP1Roe7mpxM19
# CP0uh8ZBL10qTsmc4alEQMFqDnDzqlVGwCkSwpHhkbTDBYx9Rx1ZGw95VstM3Jq0
# HUBMkFFIFRu27a09hStd2+GJqk/IzOeKq0gSJYJulfy5r4xxvvH3Jz+I5JVfqJM3
# ur8WMlATX/h/11Z9BASvu/L6wyolCRjof/ELZJ9FhOzkKAHb727vcaFTwBJaisRc
# n5Kz1pJIKtNunR040QpBAvRv8EkV1Kk7iXIhrcIahdcPDqk5xaOJRLAJ0D6PyjWH
# 0hcqM27BQhRYSxflwBt+RuFrdQm8MVTX/QdXOXzekRr081y5867KRVvdcEbfSU2w
# 7BblPuUS6BKiTUMVWWG3sWdQbimOq/VbeX2cogVeAWKntC42TDkjDygXnYFY6DvN
# EsUDfK603bJ3oiOIgeuhswIRE55xQGzgiAlHcgxTSqi0bwg9t4bgRiePhgNJrCZP
# Xf1cy6yxI4ujKZdjiDdbAIKsEKp/kB+L5PK1pDT/Wzc9pHXavhSw3dD+Xj6aHoA1
# /nqkqys5pw==
# SIG # End signature block
