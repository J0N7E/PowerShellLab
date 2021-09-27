<#
 .DESCRIPTION
    Setup Active Directory Federation Services (ADFS)
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

    # Default generic lazy pswd
    $CertFilePassword = (ConvertTo-SecureString -String 'e72d4D6wYweyLS4sIAuKOif5TUlJjEpB' -AsPlainText -Force),

    [String]$FederationServiceName,
    [String]$PrimaryComputerName,
    [String]$CATemplate,
    [String]$CAConfig,
    [String]$GroupServiceAccountIdentifier,

    [Switch]$ExportCertificate
)

Begin
{
    # ██████╗ ███████╗ ██████╗ ██╗███╗   ██╗
    # ██╔══██╗██╔════╝██╔════╝ ██║████╗  ██║
    # ██████╔╝█████╗  ██║  ███╗██║██╔██╗ ██║
    # ██╔══██╗██╔══╝  ██║   ██║██║██║╚██╗██║
    # ██████╔╝███████╗╚██████╔╝██║██║ ╚████║
    # ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝

    # Convert switch to boolean
    if ($ExportCertificate.IsPresent)
    {
        $ExportCertificate = $true
    }
    else
    {
        $ExportCertificate = $false
    }

    ##############
    # Deserialize
    ##############

    $Serializable =
    @(
        @{ Name = 'Session';                                  },
        @{ Name = 'Credential';         Type = [PSCredential] },
        @{ Name = 'CertFilePassword';   Type = [SecureString] }
    )

    #########
    # Invoke
    #########

    Invoke-Command -ScriptBlock `
    {
        try
        {
            . $PSScriptRoot\s_Begin.ps1
        }
        catch [Exception]
        {
            throw $_
        }

    } -NoNewScope

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

        ##############
        # Check admin
        ##############

        if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {
            throw "Must be administrator to setup Webserver."
        }

        ###############
        # Check domain
        ###############

        $PartOfDomain = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty PartOfDomain

        # Check for part of domain
        if ($PartOfDomain)
        {
            $DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain
            $DomainNetbiosName = Get-CimInstance -ClassName Win32_NTDomain | Select-Object -ExpandProperty DomainName
            $FriendlyNetBiosName = $DomainNetbiosName.Substring(0, 1).ToUpper() + $DomainNetbiosName.Substring(1)
        }
        else
        {
            throw "Must be domain joined to setup ADFS."
        }

        # Set default ADFS federation service name
        if (-not $FederationServiceName)
        {
            $FederationServiceName = "adfs.$DomainName"
        }

        # Set default gmsa identifier
        if (-not $GroupServiceAccountIdentifier)
        {
            $GroupServiceAccountIdentifier = "$DomainNetbiosName\MsaAdfs$"
        }

        # ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗
        # ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║
        # ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║
        # ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║
        # ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
        # ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

        # Check if RSAT-AD-PowerShell is installed
        if (((Get-WindowsFeature -Name RSAT-AD-PowerShell).InstallState -ne 'Installed') -and
            (ShouldProcess @WhatIfSplat -Message "Installing RSAT-AD-PowerShell." @VerboseSplat))
        {
            Install-WindowsFeature -Name RSAT-AD-PowerShell > $null
        }

        # Check if ADFS-Federation is installed
        if (((Get-WindowsFeature -Name ADFS-Federation).InstallState -ne 'Installed') -and
            (ShouldProcess @WhatIfSplat -Message "Installing ADFS-Federation." @VerboseSplat))
        {
            Install-WindowsFeature -Name ADFS-Federation -IncludeManagementTools -Restart > $null
        }

        #  ██████╗███████╗██████╗ ████████╗██╗███████╗██╗ ██████╗ █████╗ ████████╗███████╗
        # ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝
        # ██║     █████╗  ██████╔╝   ██║   ██║█████╗  ██║██║     ███████║   ██║   █████╗
        # ██║     ██╔══╝  ██╔══██╗   ██║   ██║██╔══╝  ██║██║     ██╔══██║   ██║   ██╔══╝
        # ╚██████╗███████╗██║  ██║   ██║   ██║██║     ██║╚██████╗██║  ██║   ██║   ███████╗
        #  ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

        # Check certificate
        $ADFSCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $_.DnsNameList.Contains("$FederationServiceName") -and
            $_.DnsNameList.Contains("certauth.$FederationServiceName") -and
            $_.DnsNameList.Contains("enterpriseregistration.$DomainName") -and (
                $_.Extensions['2.5.29.37'].EnhancedKeyUsages.FriendlyName.Contains('Server Authentication')
            )
        }

        if ($ADFSCertificate)
        {
            $CertificateThumbprint = $ADFSCertificate.Thumbprint
        }
        else
        {
            if (-not $CATemplate)
            {
                throw "Can't find ADFS certificate, please use -CATemplate to submit request."
            }

            # FIX
            # use Get-Certificate

            # CA config
            $CAConfig = TryCatch { certutil -dump } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "^  (?:Config|Konfiguration):.*(?:``|`")(.*)(?:'|`")"
            } | Select-Object -First 1 | ForEach-Object { "$($Matches[1])" }

            if (-not $CAConfig)
            {
                throw "Can't find certificate authority, please use -CAConfig to submit request."
            }

            #################
            # Build inf file
            #################

            if (-not (Test-Path -Path "$env:TEMP\ADFSCertificateRequest.inf"))
            {
                # Set file content
                $RequestInfFile =
@"
[Version]
Signature = "`$Windows NT$"

[Strings]
szOID_SUBJECT_ALT_NAME2 = "2.5.29.17"
szOID_ENHANCED_KEY_USAGE = "2.5.29.37"
szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

[NewRequest]
Subject="CN=$FederationServiceName,$(Get-BaseDn -DomainName $DomainName)"
KeyLength=2048
MachineKeySet=TRUE
Exportable=$(if($ExportCertificate){'TRUE'}else{'FALSE'})
KeySpec=AT_KEYEXCHANGE

[Extensions]
%szOID_SUBJECT_ALT_NAME2% = "{text}"
_continue_ = "DNS=$FederationServiceName&"
_continue_ = "DNS=certauth.$FederationServiceName&"
_continue_ = "DNS=enterpriseregistration.$DomainName&"

%szOID_ENHANCED_KEY_USAGE% = "{text}%szOID_PKIX_KP_SERVER_AUTH%"
"@

                # Save request file
                Set-Content -Path "$env:TEMP\ADFSCertificateRequest.inf" -Value $RequestInfFile -Force
            }

            ##########
            # Request
            ##########

            if (-not (Test-Path -Path "$env:TEMP\ADFSCertificateRequest.csr") -and
                (ShouldProcess @WhatIfSplat -Message "Building new ADFS certificate request." @VerboseSplat))
            {
                TryCatch { certreq -f -q -machine -new "$env:TEMP\ADFSCertificateRequest.inf" "$env:TEMP\ADFSCertificateRequest.csr" } -ErrorAction Stop > $null
            }

            #########
            # Submit
            #########

            if (-not (Test-Path -Path "$env:TEMP\ADFSCertificateRequest.rsp") -and
                (ShouldProcess @WhatIfSplat -Message "Submitting certificate request to `"$CAConfig`"." @VerboseSplat))
            {
                $Response = TryCatch { certreq -f -q -submit -config "`"$CAConfig`"" -attrib "`"CertificateTemplate:$CATemplate`"" "$env:TEMP\ADFSCertificateRequest.csr" "$env:TEMP\ADFSCertificateRequest.cer" } -ErrorAction SilentlyContinue

                if (($Response -join '') -match 'Taken Under Submission')
                {
                    # Get request id
                    $RequestId = $Response[0] | Where-Object {
                        $_ -match "RequestId: (\d*)"
                    } | ForEach-Object { "$($Matches[1])" }

                    # Save reqest id
                    Set-Content -Path "$env:TEMP\ADFSCertificateRequestId.txt" -Value $RequestId

                    # Set result
                    $Result.Add('WaitingForResponse', $RequestId)

                    # Output result
                    Write-Output -InputObject $Result

                    Write-Warning -Message "Issue RequestId $RequestId on CA, rerun this script to continue setup..."

                    return
                }
                elseif ((($Response) -join '') -match 'Certificate retrieved')
                {
                    Remove-Item -Path "$env:TEMP\ADFSCertificateRequest.rsp" -Force
                }
                else
                {
                    throw $Response
                }
            }

            ###########
            # Retrieve
            ###########

            if (Test-Path -Path "$env:TEMP\ADFSCertificateRequestId.txt")
            {
                $RequestId = Get-Content -Path "$env:TEMP\ADFSCertificateRequestId.txt"

                if ($RequestId -and
                    (ShouldProcess @WhatIfSplat -Message "Retrieving certificate response $RequestId." @VerboseSplat))
                {
                    $Response = TryCatch { certreq -f -q -retrieve -config "`"$CAConfig`"" $RequestId "$env:TEMP\ADFSCertificateRequest.cer" } -ErrorAction SilentlyContinue

                    if (($Response -join '') -match 'Certificate retrieved')
                    {
                        Remove-Item -Path "$env:TEMP\ADFSCertificateRequestId.txt"
                    }
                    elseif (($Response -join '') -match 'Taken Under Submission')
                    {
                        # Set result
                        $Result.Add('WaitingForResponse', $RequestId)

                        # Output result
                        Write-Output -InputObject $Result

                        Write-Warning -Message "Certificate not issued, issue RequestId $RequestId on CA. Rerun this script to continue setup..."

                        return
                    }
                    else
                    {
                        throw $Response
                    }
                }
            }

            #########
            # Accept
            #########

            if ((Test-Path -Path "$env:TEMP\ADFSCertificateRequest.cer") -and
                (ShouldProcess @WhatIfSplat -Message "Installing certificate." @VerboseSplat))
            {
                $Response = TryCatch { certreq -q -machine -accept "$env:TEMP\ADFSCertificateRequest.cer" } -ErrorAction SilentlyContinue

                if (($Response -join '') -match 'Installed Certificate')
                {
                    # Get thumbprint
                    $CertificateThumbprint = $Response | Where-Object {
                        $_ -match "Thumbprint: (.*)"
                    } | ForEach-Object { "$($Matches[1])" }

                    Remove-Item -Path "$env:TEMP\ADFSCertificateRequest.*" -Force
                }
                else
                {
                    throw $Response
                }
            }
        }

        if (-not $ADFSCertificate -and $CertificateThumbprint)
        {
            $ADFSCertificate = Get-Item -Path "Cert:\LocalMachine\My\$CertificateThumbprint"
        }

        #  ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗ ██╗   ██╗██████╗ ███████╗
        # ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ ██║   ██║██╔══██╗██╔════╝
        # ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗██║   ██║██████╔╝█████╗
        # ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║██║   ██║██╔══██╗██╔══╝
        # ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝╚██████╔╝██║  ██║███████╗
        #  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝

        # Setup ADFS general parameters
        $ADFSParams =
        @{
            CertificateThumbprint = $CertificateThumbprint
            GroupServiceAccountIdentifier = $GroupServiceAccountIdentifier
        }

        if ($PrimaryComputerName)
        {
            # Setup ADFS other node parameters
            $ADFSParams +=
            @{
                PrimaryComputerName = $PrimaryComputerName
            }
        }
        else
        {
            # Setup ADFS 1st node parameters
            $ADFSParams +=
            @{
                FederationServiceDisplayName = "$FriendlyNetBiosName Adfs"
                FederationServiceName = $FederationServiceName
            }
        }

        # Check if ADFS is configured
        try
        {
            Get-AdfsSyncProperties > $null
        }
        catch
        {
            # ADFS Not configured
            if (ShouldProcess @WhatIfSplat -Message "Configuring ADFS." @VerboseSplat)
            {
                ##########
                # Install
                ##########

                try
                {
                    Install-AdfsFarm @ADFSParams -OverwriteConfiguration
                }
                catch [Exception]
                {
                    throw $_
                }
            }
        }

        # ██████╗  ██████╗ ███████╗████████╗
        # ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝
        # ██████╔╝██║   ██║███████╗   ██║
        # ██╔═══╝ ██║   ██║╚════██║   ██║
        # ██║     ╚██████╔╝███████║   ██║
        # ╚═╝      ╚═════╝ ╚══════╝   ╚═╝

        if ((Get-AdfsProperties).EnableIdpInitiatedSignonPage -eq $false -and
            (ShouldProcess @WhatIfSplat -Message "Enabling IdpInitiatedSignon page." @VerboseSplat))
        {
            Set-ADFSProperties -EnableIdPInitiatedSignonPage:$true
        }

        # FIX

        # SSL/TLS
        # ttps://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs

        # Extranet lockout
        # https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-extranet-smart-lockout-protection

        # Secure
        # https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs

        # brand
        # Set-AdfsWebTheme

        $Providers =
        @(
            'PrimaryIntranetAuthenticationProvider',
            'PrimaryExtranetAuthenticationProvider'
        )

        foreach($Provider in $Providers)
        {
            # Get authentication providers
            $Authentications = Get-AdfsGlobalAuthenticationPolicy | Select-Object -ExpandProperty $Provider

            # Check if cert auth is present
            if ('CertificateAuthentication' -notin $Authentications -and
                (ShouldProcess @WhatIfSplat -Message "Adding Certificate Authentication to $Provider." @VerboseSplat))
            {
                # Add cert auth
                $Authentications += 'CertificateAuthentication'

                # Set parameters
                $SetAdfsGlobAuthPolSplat =
                @{
                    $Provider = $Authentications
                }

                # Set auth policy
                Set-AdfsGlobalAuthenticationPolicy @SetAdfsGlobAuthPolSplat
            }


        }

        # Get WIASupportedUserAgents
        $WIASupportedUserAgents = Get-ADFSProperties | Select-Object -ExpandProperty WIASupportedUserAgents

        # Check if Mozilla/5.0 exist
        if (-not ('Mozilla/5.0' -in $WIASupportedUserAgents) -and
           (ShouldProcess @WhatIfSplat -Message "Adding `"Mozilla/5.0`" to WIASupportedUserAgents." @VerboseSplat))
        {
            Set-AdfsProperties -WIASupportedUserAgents ($WIASupportedUserAgents + 'Mozilla/5.0')
        }

        # Set-AdfsProperties -EnableExtranetLockout $true -ExtranetLockoutThreshold 15 -ExtranetObservationWindow ( new-timespan -Minutes 30 )

        # Set-AdfsEndpoint -TargetAddressPath /adfs/services/trust/2005/windowstransport -Proxy $false
        # Set-AdfsEndpoint -TargetAddressPath /adfs/services/trust/13/windowstransport -Proxy $false

        # ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███╗   ██╗
        # ██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║
        # ██████╔╝█████╗     ██║   ██║   ██║██████╔╝██╔██╗ ██║
        # ██╔══██╗██╔══╝     ██║   ██║   ██║██╔══██╗██║╚██╗██║
        # ██║  ██║███████╗   ██║   ╚██████╔╝██║  ██║██║ ╚████║
        # ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

        if ($ExportCertificate)
        {
                # Filename
                $PfxFile = "$($FriendlyNetBiosName)AdfsCertificate.pfx"

                # Export ADFS certificate
                Export-PfxCertificate -Cert $ADFSCertificate -Password $CertFilePassword -FilePath "$env:TEMP\$PfxFile" > $null

                # Inform
                Write-Warning -Message "Using password `"$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertFilePassword)))`" for `"$PfxFile`""

                # Get pfx
                $Pfx = Get-Item -Path "$env:TEMP\$PfxFile"

                # Add pfx
                $Result.Add($Pfx, (Get-Content -Path $Pfx.FullName -Raw))

                # Cleanup
                Remove-Item -Path "$env:TEMP\$PfxFile"
        }

        Write-Output -InputObject $Result

        # Check if restart
        if ($Reboot -and
            (ShouldProcess @WhatIfSplat -Message "Restarting `"$ENV:ComputerName`"." @VerboseSplat))
        {
            Restart-Computer -Force
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

    # Load functions
    Invoke-Command -ScriptBlock `
    {
        try
        {
            . $PSScriptRoot\f_ShouldProcess.ps1
            . $PSScriptRoot\f_CopyDifferentItem.ps1
            . $PSScriptRoot\f_CheckContinue.ps1
        }
        catch [Exception]
        {
            throw $_
        }

    } -NoNewScope

    # Initialize
    $InvokeSplat = @{}

    # Setup remote
    if ($Session -and $Session.State -eq 'Opened')
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CheckContinue.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_GetBaseDN.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            $CertFilePassword = $Using:CertFilePassword

            $FederationServiceName = $Using:FederationServiceName
            $PrimaryComputerName = $Using:PrimaryComputerName
            $CATemplate = $Using:CATemplate
            $CAConfig = $Using:CAConfig
            $GroupServiceAccountIdentifier = $Using:GroupServiceAccountIdentifier

            $ExportCertificate = $Using:ExportCertificate
        }

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
                . $PSScriptRoot\f_TryCatch.ps1
                . $PSScriptRoot\f_GetBaseDN.ps1
            }
            catch [Exception]
            {
                throw $_
            }

        } -NoNewScope

        $InvokeSplat.Add('NoNewScope', $true)
    }

    # Initialize
    $Result = @{}

    # Invoke
    try
    {
        # Run main
        $Result = Invoke-Command @InvokeSplat -ScriptBlock $MainScriptBlock -ErrorAction Stop

        $Result.Add('Success', $true)
    }
    catch [Exception]
    {
        Write-Error "$_ $( $_.ScriptStackTrace)"

        $Result.Add('Success', $false)
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
                else
                {
                    # Save in temp
                    Set-Content -Path "$env:TEMP\$($item.Key.Name)" -Value $item.Value

                    # Set original timestamps
                    Set-ItemProperty -Path "$env:TEMP\$($item.Key.Name)" -Name CreationTime -Value $item.Key.CreationTime
                    Set-ItemProperty -Path "$env:TEMP\$($item.Key.Name)" -Name LastWriteTime -Value $item.Key.LastWriteTime
                    Set-ItemProperty -Path "$env:TEMP\$($item.Key.Name)" -Name LastAccessTime -Value $item.Key.LastAccessTime

                    # Move to script root if different
                    Copy-DifferentItem -SourcePath "$env:TEMP\$($item.Key.Name)" -Delete -TargetPath "$PSScriptRoot\$($item.Key.Name)" @VerboseSplat
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
    if ($Session)
    {
        $Session | Remove-PSSession
    }
}

# SIG # Begin signature block
# MIIUvwYJKoZIhvcNAQcCoIIUsDCCFKwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUEQDdZZQVV9Hec4nayVsHCVN/
# CUuggg8yMIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
# AQsFADAOMQwwCgYDVQQDDANiY2wwHhcNMjAwNDI5MTAxNzQyWhcNMjIwNDI5MTAy
# NzQyWjAOMQwwCgYDVQQDDANiY2wwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCu0nvdXjc0a+1YJecl8W1I5ev5e9658C2wjHxS0EYdYv96MSRqzR10cY88
# tZNzCynt911KhzEzbiVoGnmFO7x+JlHXMaPtlHTQtu1LJwC3o2QLAew7cy9vsOvS
# vSLVv2DyZqBsy1O7H07z3z873CAsDk6VlhfiB6bnu/QQM27K7WkGK23AHGTbPCO9
# exgfooBKPC1nGr0qPrTdHpAysJKL4CneI9P+sQBNHhx5YalmhVHr0yNeJhW92X43
# WE4IfxNPwLNRMJgLF+SNHLxNByhsszTBgebdkPA4nLRJZn8c32BQQJ5k3QTUMrnk
# 3wTDCuHRAWIp/uWStbKIgVvuMF2DixkBJkXPP1OZjegu6ceMdJ13sl6HoDDFDrwx
# 93PfUoiK7UtffyObRt2DP4TbiD89BldjxwJR1hakJyVCxvOgbelHHM+kjmBi/VgX
# Iw7UDIKmxZrnHpBrB7I147k2lGUN4Q+Uphrjq8fUOM63d9Vb9iTRJZvR7RQrPuXq
# iWlyFKcSpqOS7apgEqOnKR6tV3w/q8SPx98FuhTLi4hZak8u3oIypo4eOHMC5zqc
# 3WxxHHHUbmn/624oJ/RVJ1/JY5EZhKNd+mKtP3LTly7gQr0GgmpIGXmzzvxosiAa
# yUxlSRAV9b3RwE6BoT1wneBAF7s/QaStx1HnOvmJ6mMQrmi0aQIDAQABo1EwTzAO
# BgNVHQ8BAf8EBAMCBaAwHgYDVR0lBBcwFQYIKwYBBQUHAwMGCSsGAQQBgjdQATAd
# BgNVHQ4EFgQUEOwHbWEJldZG1P09yIHEvoP0S2gwDQYJKoZIhvcNAQELBQADggIB
# AC3CGQIHlHpmA6kAHdagusuMfyzK3lRTXRZBqMB+lggqBPrkTFmbtP1R/z6tV3Kc
# bOpRg1OZMd6WJfD8xm88acLUQHvroyDKGMSDOsCQ8Mps45bL54H+8IKK8bwfPfh4
# O+ivHwyQIfj0A44L+Q6Bmb+I0wcg+wzbtMmDKcGzq/SNqhYUEzIDo9NbVyKk9s0C
# hlV3h+N9x2SZJvZR1MmFmSf8tVCgePXMAdwPDL7Fg7np+1lZIuKu1ezG7mL8ULBn
# 81SFUn6cuOTmHm/xqZrDq1urKbauXlnUr+TwpZP9tCuihwJxLaO9mcLnKiEf+2vc
# RQYLkxk5gyUXDkP4k85qvZjc7zBFj9Ptsd2c1SMakCz3EWP8b56iIgnKhyRUVDSm
# o2bNz7MiEjp3ccwV/pMr8ub7OSqHKPSjtWW0Ccw/5egs2mfnAyO1ERWdtrycqEnJ
# CgSBtUtsXUn3rAubGJo1Q5KuonpihDyxeMl8yuvpcoYQ6v1jPG3SAPbVcS5POkHt
# DjktB0iDzFZI5v4nSl8J8wgt9uNNL3cSAoJbMhx92BfyBXTfvhB4qo862a9b1yfZ
# S4rbeyBSt3694/xt2SPhN4Sw36JD99Z68VnX7dFqaruhpyPzjGNjU/ma1n7Qdrnp
# u5VPaG2W3eV3Ay67nBLvifkIP9Y1KTF5JS+wzJoYKvZ2MIIE/jCCA+agAwIBAgIQ
# DUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5n
# IENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEwNjAwMDAwMFowSDELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBU
# aW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMLm
# YYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQtSYQ/h3Ib5FrDJbnGlxI70Tlv5th
# zRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4bbx9+cdtCT2+anaH6Yq9+IRdHnbJ
# 5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOKfF1FLUuxUOZBOjdWhtyTI433UCXo
# ZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlKXAwxikqMiMX3MFr5FK8VX2xDSQn9
# JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYervnpbCiAvSwnJlaeNsvrWY4tOpXIc
# 7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0MA4GA1UdDwEB/wQEAwIHgDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEEGA1UdIAQ6MDgwNgYJ
# YIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29t
# L0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLkYaWyoiWyyBc1bjAdBgNVHQ4EFgQU
# NkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0fBGowaDAyoDCgLoYsaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwMqAwoC6GLGh0dHA6
# Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMIGFBggrBgEF
# BQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBP
# BggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOC
# AQEASBzctemaI7znGucgDo5nRv1CclF0CiNHo6uS0iXEcFm+FKDlJ4GlTRQVGQd5
# 8NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4eTZ6J7fz51Kfk6ftQ55757TdQSKJ
# +4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2hF3MN9PNlOXBL85zWenvaDLw9MtAb
# y/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1FUL1LTI4gdr0YKK6tFL7XOBhJCVP
# st/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6Xt/Q/hOvB46NJofrOp79Wz7pZdmGJ
# X36ntI5nePk2mOHLKNpbh6aKLzCCBTEwggQZoAMCAQICEAqhJdbWMht+QeQF2jaX
# whUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGln
# aUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTE2MDEwNzEyMDAwMFoXDTMxMDEw
# NzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hB
# MiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnFOVQoV7YjSsQOB0UzURB90Pl9TWh+
# 57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQAOPcuHjvuzKb2Mln+X2U/4Jvr40ZH
# BhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhisEeTwmQNtO4V8CdPuXciaC1TjqAlx
# a+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQjMF287DxgaqwvB8z98OpH2YhQXv1m
# blZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+fMRTWrdXyZMt7HgXQhBlyF/EXBu89
# zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW/5MCAwEAAaOCAc4wggHKMB0GA1Ud
# DgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCB
# gQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBQBgNVHSAESTBHMDgG
# CmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
# Y29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggEBAHGVEulRh1Zp
# ze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafDDiBCLK938ysfDCFaKrcFNB1qrpn4
# J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6HHssIeLWWywUNUMEaLLbdQLgcseY
# 1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4H9YLFKWA1xJHcLN11ZOFk362kmf7
# U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHKeZR+WfyMD+NvtQEmtmyl7odRIeRY
# YJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIoxhhWz0E0tmZdtnR79VYzIi8iNrJL
# okqV2PWmjlIxggT3MIIE8wIBATAiMA4xDDAKBgNVBAMMA2JjbAIQJoAlxDS3d7xJ
# EXeERSQIkTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU/EzqqaY7CPRqnl4PzivGbrpIuFswDQYJ
# KoZIhvcNAQEBBQAEggIAiw8FR7xf9F4cx4AHWcO8SGq7MfWd/c3/y+rJ790njvHn
# TmyvpAq42U5NGa70TSVZQMh4nYntJEqZfkftHupTdKqNUum8mLYOln2EXm3m5FNQ
# ln27wRPLM7RTQlt0Ds9d+DXnydXsJ8klCC8McEGZc7JjVp6eLRTava3t4kmc+Btr
# xLce85r32kjFJEKec9hjZTCSKJqLWO04y7osR6buPFi46O6I5W5V474OOonojSC2
# wmdjF6yj7yyHex5zVeLEIw/PuTPDnmbmFNJRLs/Dk/w++/naIS20M8qPlEqNN6Pi
# SXNKKj7B2/7H4np90Df5iJ6up1y8m4wWKS2OWI/XNutYAK9FoEFdizVyvxaWF7Pu
# TS+ns98981OjiVJxxZS0PqBD16u8t5mC3tkl3Tcdq6hCkvjGOB/fK4pJz6by0X7F
# sQ4DrfoejI5QEGxSFLx4YfAD6bkgG5YZtk4AKga/O4+zOqcRU1NosRAPr0cidpjO
# SbLby+mn96CYNFVoW2OQrPZsjPguiqAIdDGR5OfP9MkCJXfuyLIib7WCjEEamIhg
# 3iSkLcSSV2vSlBaiEOJsySmWaNANgBnW2SD9rNEeNNZmukqb6hYJSWHjOMf9EiSD
# ml0yYk6cKXsXX/AX03j6lw2jyvKoItlDDccN+Tzj8yAxd4yCckKXwxbYH1Rw7J6h
# ggIwMIICLAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGlu
# ZyBDQQIQDUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDkyNzE0MDAwNFow
# LwYJKoZIhvcNAQkEMSIEICsNCje0h5WVeloOJBOyP6jeyFI7sUmV1MDKv8ffUibj
# MA0GCSqGSIb3DQEBAQUABIIBAKqj//ARGKOM2F2DDuyQADG4spH81PfsMxESg77k
# RiOshiSc6/NFXe+lYtMM5Yj0M19C1Lx7DPaz6F/peRxUcEORKuEExBmpTF2GGfbi
# 1dRowErfPI9hcUDF405T+BQhgQhBHA+fToDZeYuWEpYWBAYEHIBQyRpP0nXwT7yJ
# Ly6oy3UmeGdGHJNmaG0gYCbF6ktgHdbs5SVFGN7SS/XUUdDtQVYvXPyZQuGJVlee
# YikHYxOdy8lSWx4JasVV2dA+7A74rMrpKQK91JwCHRnC42CfC4i7rJDSZtFwsMOZ
# 5adGXJhQmTDZ17ksvJkLjiCJe4x2EhIjvP9Z0u/1MOBq6q4=
# SIG # End signature block
