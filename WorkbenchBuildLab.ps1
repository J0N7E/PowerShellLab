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
    [String]$LabPath = "$env:Documents\WindowsPowerShell\PowerShellLab"
)

Begin
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

    ########
    # Paths
    ########

    if (-not (Test-Path -Path $LabPath))
    {
        $LabPath = "$env:USERPROFILE\Documents\WindowsPowerShell\PowerShellLab"
    }

    Set-Location -Path $LabPath

    ###########
    # Settings
    ###########

    $Settings =
    @{
        DomainNetworkId   = '192.168.0'
        DmzNetworkId      = '10.1.1'
        Admin             = 'admin'
        Join              = 'joindomain'
        Pswd              = (ConvertTo-SecureString -String 'P455w0rd' -AsPlainText -Force)
        VMs               =
        [ordered]@{
            ADFS   = @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';   Switch = @('Lab');           }
            AS     = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';   Switch = @('Lab');           }
            ROOTCA = @{ Name = 'CA01';    Domain = $false;  OSVersion = '*Desktop Experience x64 21H2*';   Switch = @();                }
            SUBCA  = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*x64 21H2*';                      Switch = @('Lab');           }
            DC     = @{ Name = 'DC01';    Domain = $false;  OSVersion = '*Desktop Experience x64 21H2*';   Switch = @('Lab');           }
            WAP    = @{ Name = 'WAP02';   Domain = $true;   OSVersion = '*x64 21H2*';                      Switch = @('LabDmz', 'Lab'); }
            WIN11  = @{ Name = 'WIN11';   Domain = $true;   OSVersion = 'Windows 11*';                     Switch = @('Lab');           }
        }
    }

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

    $Settings +=
    @{
        DomainName = $DomainName
        DomainNetbiosName = $DomainNetbiosName
        DomainPrefix = $DomainNetBiosName.Substring(0, 1).ToUpper() + $DomainNetBiosName.Substring(1)
    }

    # Get credentials
    $Settings +=
    @{
        Lac    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".\administrator", $Settings.Pswd
        Ac     = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\administrator')", $Settings.Pswd
        Dac    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\' + $Settings.Admin)", $Settings.Pswd
        Jc     = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\' + $Settings.Join)", $Settings.Pswd
    }

    ############
    # Functions
    ############

    function Wait-For
    {
        [cmdletbinding(SupportsShouldProcess=$true)]

        param
        (
            [Parameter(Mandatory=$true)]
            [String]$VMName,

            [Parameter(Mandatory=$true)]
            [PSCredential]$Credential,

            [Hashtable]$Queue = @{},
            [ref]$History,
            [Switch]$Force
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
            # Wait if forced or vm in queue
            if ($Force.IsPresent -or $Queue.ContainsKey($VMName))
            {
                # Enable resource metering
                Enable-VMResourceMetering -VMName $VMName

                # Initialize total duration timer
                $TotalDuration = [System.Diagnostics.Stopwatch]::StartNew()

                Write-Verbose @VerboseSplat -Message "Waiting for $VMName..."

                do
                {
                    # Get measure
                    $MeasureVM = Measure-VM -VMName $VMName -ErrorAction SilentlyContinue

                    if ($MeasureVM -and $MeasureVM.AggregatedAverageLatency -ne 0)
                    {
                        $Threshold = $MeasureVM.AggregatedAverageLatency * 25
                    }
                    else
                    {
                        $Threshold = 5000
                    }

                    # Initialize
                    $Invoke = $false

                    # Get invoke
                    try
                    {
                        $Invoke = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock { $true } -ErrorAction Stop
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

                            #'An error has occurred which Windows PowerShell cannot handle.' {}

                            Default
                            {
                                if ($TotalDuration.ElapsedMilliseconds - $LastError.ElapsedMilliseconds -gt 25)
                                {
                                    Write-Verbose @VerboseSplat -Message $_
                                }
                            }
                        }

                        $LastError = $TotalDuration
                    }

                    # Check invoke
                    if ($Invoke)
                    {
                        # Start timer
                        if (-not $VmReadyDuration -or $VmReadyDuration.IsRunning -eq $false)
                        {
                            $VmReadyDuration = [System.Diagnostics.Stopwatch]::StartNew()
                            Write-Verbose @VerboseSplat -Message "$VMName up, setting initial threshold timer to $Threshold ms..."
                        }
                    }
                    else
                    {
                        # Stop timer
                        if ($VmReadyDuration -and $VmReadyDuration.IsRunning -eq $true)
                        {
                            $VmReadyDuration.Stop()

                            Write-Verbose @VerboseSplat -Message "Invoke failed, stoped threshold timer after $($VmReadyDuration.ElapsedMilliseconds) ms."
                        }

                    }
                }
                until($Invoke -and $VmReadyDuration.ElapsedMilliseconds -gt $Threshold)

                # Stop timers
                $VmReadyDuration.Stop()
                $TotalDuration.Stop()

                Write-Verbose @VerboseSplat -Message "$VMName ready, met threshold at $Threshold ms. Waited total $($TotalDuration.ElapsedMilliseconds) ms."

                # Set history
                if ($History)
                {
                    $History.Value += $TotalDuration.ElapsedMilliseconds
                }

                # Remove VM from queue
                $Queue.Remove($VMName)

                # Disable resource metering
                Disable-VMResourceMetering -VMName $VMName

                # Return
                Write-Output -InputObject $true
            }
            # Fail if not running
            elseif ((Get-VM -Name $VMName -ErrorAction SilentlyContinue).State -ne 'Running')
            {
                # Return
                Write-Output -InputObject $false
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
            $PSReadyDuration = $null
        }
    }

    function Invoke-Wend
    {
        param
        (
            [String]$Message,
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
            if ($Message)
            {
                Write-Verbose @VerboseSplat -Message $Message
            }

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

    #############
    # Initialize
    #############

    $Global:VMsInstalled = @{}
    $Global:VMsRenamed = @{}
    $TotalTimeWaited = 0

    $WaitSplat =
    @{
        Credential = $Settings.Lac
        History    = ([ref]$TotalTimeWaited)
    }
}

Process
{
    ##############
    # Install VMs
    ##############

    foreach($VM in $Settings.VMs.GetEnumerator())
    {
        # Get latest os media
        $OSMedia = Get-Item -Path "$OsdPath\OSMedia\$($VM.Value.OSVersion)" -ErrorAction SilentlyContinue | Select-Object -Last 1

        # Get latest vhdx
        $OSVhdx = Get-Item -Path "$OsdPath\OSMedia\$($OSMedia.Name)\VHD\OSDBuilder.vhdx" -ErrorAction SilentlyContinue | Select-Object -Last 1

        if (-not $OSVhdx)
        {
            Write-Warning -Message "No VHDX found for `"$($VM.Value.Name)`""
        }
        else
        {
            $NewVMSplat =
            @{
                LabFolder = "$HvDrive\HvLab"
            }

            if ($VM.Value.Switch.Length -gt 0)
            {
                $NewVMSplat +=
                @{
                    VMAdapters = $VM.Value.Switch
                }
            }

            $Result = .\LabNewVM.ps1 @NewVMSplat -Verbose -Start -VMName $VM.Value.Name -Vhdx $OSVhdx

            if ($Result.StartedVM)
            {
               $VMsInstalled.Add($Result.StartedVM, $true)
            }
        }
    }

    ##########
    # Root CA
    ##########

    if (Wait-For @WaitSplat @VerboseSplat  -VMName $Settings.VMs.ROOTCA.Name -Queue $VMsInstalled)
    {
        .\VMRename.ps1 -Restart -Verbose -VMName $Settings.VMs.ROOTCA.Name -Credential $Settings.Lac > $null
    }

    #########
    # DC
    # Step 1
    #########

    if (Wait-For @WaitSplat @VerboseSplat  -VMName $Settings.VMs.DC.Name -Queue $VMsInstalled)
    {
        # Rename
        $Result = .\VMRename.ps1 -Restart -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Lac

        if ($Result.Renamed)
        {
            # Wait for reboot
            Start-Sleep -Seconds 3

            # Make sure DC is up
            Wait-For @WaitSplat @VerboseSplat -VMName $Settings.VMs.DC.Name -Force > $null

            # Setup network
            .\VMSetupNetwork.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Lac `
                                 -AdapterName Lab `
                                 -IPAddress "$($Settings.DomainNetworkId).10" `
                                 -DefaultGateway "$($Settings.DomainNetworkId).1" `
                                 -DNSServerAddresses @("$($Settings.DmzNetworkId).1")

            ###########
            # Setup DC
            # Step 1
            ###########

            $ResultDCStep1 = .\VMSetupDC.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Lac `
                                             -DomainNetworkId $Settings.DomainNetworkId `
                                             -DomainName $Settings.DomainName `
                                             -DomainNetbiosName $Settings.DomainNetBiosName `
                                             -DomainLocalPassword $Settings.Pswd
            <# Backup
             # Get session
             $Session = New-PSSession -VMName $Settings.VMs.DC.Name -Credential $Settings.Lac

             # Remove gpo backups (run multiple times)
             Remove-Item -Path "$LabPath\Gpo" -Recurse -Force

             # Copy gpo backups
             Copy-Item -FromSession $Session -Path "C:\Users\Administrator\AppData\Local\Temp\GpoBackup" -Recurse -Destination "$LabPath\Gpo"

             # Remove templates
             Remove-Item -Path "$LabPath\Templates" -Recurse -Force

             # Copy template backups
             Copy-Item -FromSession $Session -Path "C:\Users\Administrator\AppData\Local\Temp\TemplatesBackup" -Recurse -Destination "$LabPath\Templates"

             # Remove session
             $Session | Remove-PSSession
            #>
        }
    }

    ##########
    # Root CA
    ##########

    if (Wait-For @WaitSplat @VerboseSplat -VMName $Settings.VMs.ROOTCA.Name -Force)
    {
        # Install root ca
        .\VMSetupCA.ps1 -Verbose -VMName $Settings.VMs.ROOTCA.Name -Credential $Settings.Lac `
                        -Force `
                        -StandaloneRootCA `
                        -CACommonName "$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)" `
                        -CADistinguishedNameSuffix "O=$($Settings.DomainPrefix),C=SE" `
                        -DomainName $Settings.DomainName > $null

        <# Remove root CA
            .\VMRemoveCA.ps1 -Verbose -VMName $($Settings.VMs.ROOTCA.Name) -Credential $Settings.Lac `
                             -CACommonName "$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)"
        #>
    }

    #########
    # DC
    # Step 2
    #########

    if ((Get-VM -Name $Settings.VMs.DC.Name -ErrorAction SilentlyContinue).State -eq 'Running')
    {
        if ($ResultDCStep1.WaitingForReboot)
        {
            # Make sure DC is up
            Wait-For @VerboseSplat -VMName $Settings.VMs.DC.Name -Credential $Settings.Ac -History ([ref]$TotalTimeWaited) -Force > $null

            # Wait for group policy
            Invoke-Wend -TryBlock {

                Invoke-Command -VMName $Settings.VMs.DC.Name -Credential $Settings.Ac -ScriptBlock {

                    # Get group policy
                    Get-GPO -Name 'Default Domain Policy' -ErrorAction SilentlyContinue

                } -ErrorAction SilentlyContinue

            } -WendBlock {

                $Wend = $false

                # Check group policy
                if (-not ($Result -and $Result.GpoStatus -eq 'AllSettingsEnabled'))
                {
                    $Wend = $true

                    Write-Verbose @VerboseSplat -Message 'Waiting for DC...'
                    Start-Sleep -Seconds 60
                }

            } -CatchBlock {

                # Debug all
                Write-Warning -Message $_
                Start-Sleep -Seconds 60

            } -NoOutput

            # Setup network
            .\VMSetupNetwork.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Lac `
                                 -AdapterName Lab `
                                 -IPAddress "$($Settings.DomainNetworkId).10" `
                                 -DefaultGateway "$($Settings.DomainNetworkId).1" `
                                 -DNSServerAddresses @("$($Settings.DomainNetworkId).10", '127.0.0.1')

            ###########
            # Setup DC
            # Step 2
            ###########

            .\VMSetupDC.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Lac `
                            -DomainNetworkId $Settings.DomainNetworkId `
                            -DomainName $Settings.DomainName `
                            -DomainNetbiosName $Settings.DomainNetBiosName `
                            -DomainLocalPassword $Settings.Pswd `
                            -GPOPath "$LabPath\Gpo" `
                            -BaselinePath "$LabPath\Baseline" `
                            -TemplatePath "$LabPath\Templates"
        }

        # Publish root certificate to domain
        .\VMSetupCAConfigureAD.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Dac `
                                   -CAType StandaloneRootCA `
                                   -CAServerName $Settings.VMs.ROOTCA.Name `
                                   -CACommonName "$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)"

        <# Remove root certificate from domain
        .\VMRemoveCAFromAD.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Dac `
                               -CAServerName $Settings.VMs.ROOTCA.Name `
                               -CACommonName "$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)"
        #>
    }

    ##################
    # Set DNS, Rename
    # & Join domain
    ##################

    foreach($VM in $Settings.VMs.GetEnumerator())
    {
        if ($VM.Value.Domain)
        {
            $JoinDomainSplat = @{}

            if (Wait-For @WaitSplat @VerboseSplat  -VMName $VM.Value.Name -Queue $VMsInstalled)
            {
                Write-Verbose @VerboseSplat -Message "Configuring $($VM.Value.Name) network adapter..."

                # Setup network adapter
                .\VMSetupNetwork.ps1 -Verbose -VMName $VM.Value.Name -Credential $Settings.Lac `
                                     -AdapterName Lab `
                                     -DNSServerAddresses @("$($Settings.DomainNetworkId).10")

                $JoinDomainSplat +=
                @{
                    JoinDomain = $Settings.DomainName
                    DomainCredential = $Settings.Jc
                }

                $Result = Invoke-Wend -TryBlock {

                    .\VMRename.ps1 @JoinDomainSplat -Verbose -VMName $VM.Value.Name -Credential $Settings.Lac

                } -CatchBlock {

                    $MsgStr = 'The specified domain either does not exist or could not be contacted.'

                    if ($_ -match $MsgStr)
                    {
                        Write-Warning -Message "$MsgStr Retrying..."
                        Start-Sleep -Seconds 5
                    }
                    else
                    {
                        Write-Warning -Message $_
                        Read-Host -Prompt "Press <enter> to continue"
                    }
                }

                if ($Result.Renamed)
                {
                    $VMsRenamed.Add($Result.Renamed, $true)
                }
            }
        }
    }

    ###############
    # DC
    # Configure AD
    # objects
    ###############

    if ((Get-VM -Name $Settings.VMs.DC.Name -ErrorAction SilentlyContinue).State -eq 'Running')
    {
        # Run DC setup to configure new ad objects
        .\VMSetupDC.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Dac `
                        -DomainNetworkId $Settings.DomainNetworkId `
                        -DomainName $Settings.DomainName `
                        -DomainNetbiosName $Settings.DomainNetBiosName `
                        -DomainLocalPassword $Settings.Pswd > $null
    }

    #########
    # Reboot
    #########

    foreach($VM in $VMsRenamed.GetEnumerator())
    {
        Invoke-Command -VMName $VM.Name -Credential $Settings.Dac -ScriptBlock {

            $VerboseSplat = $Using:VerboseSplat
            Write-Verbose @VerboseSplat -Message "Rebooting $($Using:VM.Name)..."

            # Reboot vms for rename, group membership & dhcp lease
            Restart-Computer -Force
        }
    }

    # Remove sessions after reboot
    Get-PSSession | Remove-PSSession

    #########
    # AS
    # Step 1
    #########

    if (Wait-For @WaitSplat @VerboseSplat  -VMName $Settings.VMs.AS.Name -Queue $VMsRenamed)
    {
        # Setup webserver
        .\VMSetupCAConfigureWebServer.ps1 -Verbose -VMName $Settings.VMs.AS.Name -Credential $Settings.Dac `
                                          -Force `
                                          -CAConfig "$($Settings.VMs.ROOTCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)" `
                                          -ConfigureIIS `
                                          -ShareAccess "Delegate CRL Publishers"
    }

    #########
    # Sub CA
    #########

    if (Wait-For @WaitSplat @VerboseSplat  -VMName $Settings.VMs.SUBCA.Name -Queue $VMsRenamed)
    {
        $Result = Invoke-Wend -TryBlock {

            .\VMSetupCA.ps1 -Verbose -VMName $Settings.VMs.SUBCA.Name -Credential $Settings.Dac `
                            -Force `
                            -EnterpriseSubordinateCA `
                            -CACommonName "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)" `
                            -CADistinguishedNameSuffix "O=$($Settings.DomainPrefix),C=SE" `
                            -CRLPublishAdditionalPaths @("\\$($Settings.VMs.AS.Name)\wwwroot$") `
                            -PublishTemplates `
                            -CRLPeriodUnits 180 `
                            -CRLPeriod Days `
                            -CRLOverlapUnits 14 `
                            -CRLOverlapPeriod Days

            <# Remove sub CA
            .\VMRemoveCA.ps1 -Verbose -VMName $Settings.VMs.SUBCA.Name -Credential $Settings.Dac `
                             -ParentCACommonName "$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)" `
                             -CACommonName "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)"
            #>

            <# Remove sub CA certificate from domain
            .\VMRemoveCAFromAD.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Dac `
                                   -CAServerName $($Settings.VMs.SUBCA.Name) `
                                   -CACommonName "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)"
            #>

            <# Configure sub CA in AD
            .\VMSetupCAConfigureAD.ps1 -Verbose -VMName $Settings.VMs.DC.Name -Credential $Settings.Dac `
                                       -Force `
                                       -RemoveOld `
                                       -CAType EnterpriseSubordinateCA `
                                       -CAServerName $($Settings.VMs.SUBCA.Name) `
                                       -CACommonName "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)"
            #>

        } -WendBlock {

            $Wend = $false

            if ($Result.WaitingForResponse)
            {
                $Wend = $true

                if (Test-Path -Path "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)-Response.cer")
                {
                    Write-Warning -Message "No root CA response match the sub CA request."
                    Read-Host -Prompt "Press <enter> to continue"
                }
                elseif ((Get-VM -Name $Settings.VMs.ROOTCA.Name -ErrorAction SilentlyContinue).State -eq 'Running')
                {
                    # Issue sub ca certificate
                    .\VMSetupCAIssueCertificate.ps1 -Verbose -VMName $Settings.VMs.ROOTCA.Name -Credential $Settings.Lac `
                                                    -CertificateSigningRequest "$LabPath\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)-Request.csr"
                }
            }
        }
    }

    #########
    # AS
    # Step 2
    #########

    if ((Get-VM -Name $Settings.VMs.AS.Name -ErrorAction SilentlyContinue).State -eq 'Running')
    {
        # Setup webserver
        .\VMSetupCAConfigureWebServer.ps1 -Verbose -VMName $Settings.VMs.AS.Name -Credential $Settings.Dac `
                                          -Force `
                                          -CAConfig "$($Settings.VMs.SUBCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)" `
                                          -ConfigureOCSP `
                                          -OCSPTemplate "$($Settings.DomainPrefix)OCSPResponseSigning"
    }

    #############
    # Trigger
    # Autoenroll
    #############

    if ($Result.CertificateInstalled)
    {
        foreach($VM in $Settings.VMs.GetEnumerator())
        {
            if ($VM.Value.Switch.Contains('Lab') -and
               (Get-VM -Name $VM.Value.Name -ErrorAction SilentlyContinue).State -eq 'Running')
            {
                Write-Verbose @VerboseSplat -Message "Certutil -pulse $($VM.Value.Name)"

                Invoke-Command -VMName $VM.Value.Name -Credential $Settings.Lac -ScriptBlock {

                    Certutil -pulse > $null
                }
            }
        }

        # Cleanup
        Remove-Item -Path "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)-Request.csr" -ErrorAction SilentlyContinue
        Remove-Item -Path "$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)-Response.cer" -ErrorAction SilentlyContinue
    }

    #######
    # ADFS
    #######

    if (Wait-For @WaitSplat @VerboseSplat  -VMName $Settings.VMs.ADFS.Name -Queue $VMsRenamed)
    {
        Invoke-Wend -TryBlock {

            .\VMSetupADFS.ps1 -Verbose `
                              -VMName $Settings.VMs.ADFS.Name `
                              -Credential $Settings.Dac `
                              -CATemplate "$($Settings.DomainPrefix)ADFSServiceCommunication" `
                              -ExportCertificate
        } -WendBlock {

            $Wend = $false

            if ($Result.WaitingForResponse)
            {
                $Wend = $true

                if ((Get-VM -Name $Settings.VMs.SUBCA.Name -ErrorAction SilentlyContinue).State -eq 'Running')
                {
                    Write-Verbose @VerboseSplat -Message "Issuing ADFS Certificate with RequestId $($Result.WaitingForResponse)"

                    Invoke-Command -VMName $Settings.VMs.SUBCA.Name -Credential $Settings.Dac -ScriptBlock {

                        Certutil -resubmit $Using:Result.WaitingForResponse > $null
                    }
                }
            }
        }
    }

    ######
    # WAP
    ######

    if (Wait-For @WaitSplat @VerboseSplat  -VMName $Settings.VMs.WAP.Name -Queue $VMsRenamed)
    {
        .\VMSetupNetwork.ps1 -Verbose -VMName $Settings.VMs.WAP.Name -Credential $Settings.Dac `
                             -AdapterName Lab `
                             -IPAddress "$($Settings.DomainNetworkId).100" `
                             -DNSServerAddresses @("$($Settings.DomainNetworkId).10")

        .\VMSetupNetwork.ps1 -Verbose -VMName $Settings.VMs.WAP.Name -Credential $Settings.Dac `
                             -AdapterName LabDmz `
                             -IPAddress "$($Settings.DmzNetworkId).100" `
                             -DefaultGateway "$($Settings.DmzNetworkId).1"`
                             -DNSServerAddresses @("$($Settings.DmzNetworkId).1")

        .\VMSetupWAP.ps1 -Verbose -VMName $Settings.VMs.WAP.Name -Credential $Settings.Dac `
                         -ADFSTrustCredential $Settings.Dac `
                         -ADFSPfxFile "$($Settings.DomainPrefix)AdfsCertificate.pfx"
                         #-EnrollAcmeCertificates
    }
}

End
{
    Write-Verbose @VerboseSplat "Waited $($TotalTimeWaited.Value/1000) sec. for VMs."
}

# SIG # Begin signature block
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUj4HXuG1+rlrKd56lH/yH3EA/
# kj6gghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMTA2MDcxMjUwMzZaFw0yMzA2MDcx
# MzAwMzNaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzdFz3tD9N0VebymwxbB7s+YMLFKK9LlPcOyyFbAoRnYKVuF7Q6Zi
# fFMWIopnRRq/YtahEtmakyLP1AmOtesOSL0NRE5DQNFyyk6D02/HFhpM0Hbg9qKp
# v/e3DD36uqv6DmwVyk0Ui9TCYZQbMDhha/SvT+IS4PBDwd3RTG6VH70jG/7lawAh
# mAE7/gj3Bd5pi7jMnaPaRHskogbAH/vRGzW+oueG3XV9E5PWWeRqg1bTXoIhBG1R
# oSWCXEpcHekFVSnatE1FGwoZHTDYcqNnUOQFx1GugZE7pmrZsdLvo/1gUCSdMFvT
# oU+UeurZI9SlfhPd6a1jYT/BcgsZdghWUO2M8SCuQ/S/NuotAZ3kZI/3y3T5JQnN
# 9l9wMUaoIoEMxNK6BmsSFgEkiQeQeU6I0YT5qhDukAZDoEEEHKl17x0Q6vxmiFr0
# 451UPxWZ19nPLccS3i3/kEQjVXc89j2vXnIW1r5UHGUB4NUdktaQ25hxc6c+/Tsx
# 968S+McqxF9RmRMp4g0kAFhBHKj7WhUVt2Z/bULSyb72OF4BC54CCSt1Q4eElh0C
# 1AudkZgj9CQKFIyveTBFsi+i2g6D5cIpl5fyQQnqDh/j+hN5QuI8D7poLe3MPNA5
# r5W1c60B8ngrDsJd7XnJrX6GdJd2wIPh1RmzDlmoUxVXrgnFtgzeTUUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFEPCLoNYgwyQVHRrBSI9l0nSMwnLMA0G
# CSqGSIb3DQEBCwUAA4ICAQBiMW8cSS4L1OVu4cRiaPriaqQdUukgkcT8iWGWrAHL
# TFPzivIPI5+7qKwzIJbagOM3fJjG0e6tghaSCPfVU+sPWvXIKF3ro5XLUfJut6j5
# qUqoQt/zNuWpI12D1gs1NROWnJgqe1ddmvoAOn5pZyFqooC4SnD1fT7Srs+G8Hs7
# Qd2j/1XYAphZfLXoiOFs7uzkQLJbhmikhEJQKzKE4i8dcsoucNhe2lvNDftJqaGl
# oALzu04y1LcpgCDRbvjU0YDStZwKSEj9jvz89xpl5tMrgGWIK8ghjRzGf0iPhqb/
# xFOFcKP2k43X/wXWa9W7PlO+NhIlZmTM/W+wlgrRfgkawy2WLpO8Vop+tvVwLdyp
# 5n4UxRDXBhYd78Jfscb0fwpsU+DzONLrJEwXjdj3W+vdEZs7YIwAnsCGf8NznXWp
# N9D7OzqV0PT2Szkao5hEp3nS6dOedw/0uKAz+l5s7WJOTLtFjDhUk62g5vIZvVK2
# E9TWAuViPmUkVugnu4kV4c870i5YgRZz9l4ih5vL9XMoc4/6gohLtUgT4FD0xKXn
# bwtl/LczkzDO9vKLbx93ICmNJuzLj+K8S4AAo8q6PTgLZyGlozmTWRa3SmGVqTNE
# suZR41hGNpjtNtIIiwdZ4QuP8cj64TikUIoGVNbCZgcPDHrrz84ZjAFlm7H9SfTK
# 8jCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
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
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkH
# gD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIx
# MjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNV
# BAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28
# klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2J
# U+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307scpTjUCD
# HufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCR
# RinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+
# nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf
# 7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+
# pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY
# /ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwY
# UWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiw
# bjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3
# AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYE
# FGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEy
# NTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4
# Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp
# +6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJ
# iXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6
# UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr
# 5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmI
# vxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nf
# J2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH
# 5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeX
# upYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP1
# 0Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab3H4szP8X
# TE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMYIF6TCCBeUCAQEwJDAQMQ4wDAYDVQQD
# DAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU/bxJz2G9
# ttgKeB4bdgjiUhzFAaAwDQYJKoZIhvcNAQEBBQAEggIAwEa2qNgDHNb7nPbn5oLX
# hRcWL9fmR/5C7BMacj91flX139xgFxWYDy4IoHNCOjN5riN4zVePXF1bEfonkb8k
# /YRoPoHBRm8xOvmmA/Ze9nQAcXBPfc66fnVvef9rz+cFYXsCPRA+oY/HN6UACYnc
# nQ3k28JA+YtI8413X/4Lf3jky/b0TDj7bcLX8RUNV/R07gaNIfleR3TIjKG6hDVb
# Qyw355K58qPaOzUYaDwVTWvQE3oMDc8VHM2LxE3Fg0rNfUVLmUhcbqNrr8LJGe2Z
# jVzBFOn1wZrDX4qNTdrED11dzoTtU1EwY2mFy2oIWf6fNRJkyp9rn9jNUEBER/tz
# Wo0j4x43Zo63Qgh82oeHLVykIWyWpYYsWUdlZq87mbRzzgj9xX328mBIQQu5igDt
# p6BFlcIRe5QeK09/swYr+4+D63bgIO336zak+a7+rZS5O5r2EYOoF1aICoG4ap3+
# 2Y56q4narEILFU2pwT9ivt2El5EPCE3EjbKDeGTXxNbqbssXryCvMK6rAlgByXCl
# c0csQPI8V20gHuD/cKtreVWa0RIxjlavqQQsEpJ4H/Pyges2TSMbQ5OjfIxxWwQK
# BKItwL64e4nMyOsx05rFCEC+uuybH1RVjKyqxV5GxmNmQCj3Jf77h7HQOwgBYzBv
# bZWfLzUxY6wVqCp2Uhqg5uuhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwMjE1MTcwMDAx
# WjAvBgkqhkiG9w0BCQQxIgQgrQX4T7eSGCLm2lI3jmZUFZSw47KSYChUxeTwVS4q
# y2QwDQYJKoZIhvcNAQEBBQAEggIAhXxSMXNAR80WHVU4JjtfnhATZ13tmGHFBTj0
# FKv8He1bfR2fNM4nlEJ5I1XgLYDk/oOKhbKK9ciAu2OAX+qsPdNoUZ/NbnN4y7bm
# Fob8McyvLuCQlXp16jmZmRdkxjWNijEZTcidqEi995wjmAZ/7mPBR0JEV7a0Yx53
# vl/Izf2WGixjSP2kD8gSThRW+1nwvrZLesS+NLhTLgN6OY0s6kYXfdrzXvYl0JQJ
# LElYYmLR9dgwM2VGI4jdIIxvD3k70CKk5PuTMsDShruQGZWQVS7N8UNdV29sKP3v
# 9tUUemLR5Lfzv8AcWhHy+RTZZFoB+Q+kWlO6TzCBP49vgGEvWg5q+zQYcn8ODuPR
# TObrrpmjGtwztosICKJ6hnns1QKBEAwdJQwki+zHh9I1KR0RvFfRaonrVkHRIpSJ
# +lV3y8hjkwP0CLXUUdeJfSrJGLrSd9b2mOe5ZzUpe2TrFJNxdsoMQ0ctQvrtpI5V
# U5jgQ7/wz72+OCQ3Ip8QX0NThtTHPak0GOzOXWGoeEDXstDoZznr8PwUJVxAER7N
# QQenJ9YmIWiMVN0muf/ZXSt7kchWDdWTji+2kNCfWh7oayLm4FyaKOjhs4QTY3Dv
# +p/65H8+W2EqdWJ4wSerSpD+UZY9Q4KIiRtHusmOxA+NDfQPG8mBB1BMA5HqXls9
# xal2UN4=
# SIG # End signature block
