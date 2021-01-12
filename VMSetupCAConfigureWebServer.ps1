<#
 .DESCRIPTION
    Setup and configure Validation Authority (AIA, CDP and OCSP)
 .NOTES
    AUTHOR Jonas Henriksson
 .LINK
    https://github.com/bomberclaad
#>

[cmdletbinding(SupportsShouldProcess=$true, DefaultParameterSetName='Standard')]

Param
(
    # VM name
    [String]$VMName,
    # Computer name
    [String]$ComputerName,

    # Serializable parameters
    $Session,
    $Credential,

    # Certificate Authority common name
    [Parameter(ParameterSetName='Standard')]
    [Parameter(Mandatory=$true)]
    [String]$CACommonName,

    # Host name
    [String]$HostName,

    ########
    # Share
    ########

    # Share Name
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPAuto')]
    [Parameter(ParameterSetName='OCSPManual')]
    [String]$ShareName,

    # Share access
    # FIX
    # to array
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share', Mandatory=$true)]
    [Parameter(ParameterSetName='OCSPAuto')]
    [Parameter(ParameterSetName='OCSPManual')]
    [String]$ShareAccess,

    #####################
    # OCSP Enterprise CA
    #####################

    # OCSP CA config
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPAuto', Mandatory=$true)]
    [String]$OCSPCAConfig,

    # OCSP template name
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPAuto', Mandatory=$true)]
    [String]$OCSPTemplate,

    #####################
    # OCSP Standalone CA
    #####################

    # OCSP request signing certificate
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPManual', Mandatory=$true)]
    [Switch]$OCSPManualRequest,

    ########################
    # Common OCSP paramters
    ########################

    # OCSP hash algorithm
    [ValidateSet('MD2', 'MD4', 'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
    [String]$OCSPHashAlgorithm,

    # OCSP nonuce switch
    [Switch]$OCSPAddNounce,

    # OCSP refresh timeout
    [Int]$OCSPRefreshTimeout
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
        @{ Name = 'Session';                              },
        @{ Name = 'Credential';     Type = [PSCredential] }
    )

    #########
    # Invoke
    #########

    Invoke-Command -ScriptBlock `
    {
        try
        {
            . $PSScriptRoot\s_Begin.ps1
            . $PSScriptRoot\f_ShouldProcess.ps1
        }
        catch [Exception]
        {
            throw $_
        }

    } -NoNewScope

    ############
    # Get files
    ############

    # Initialize
    $CAFiles = @{}
    $CAResponseFile = $null

    # Itterate all ca files
    foreach($file in (Get-Item -Path "$PSScriptRoot\$CACommonName*"))
    {
        if ($file.Name -notmatch 'Response' -and
            $file.Name -notmatch '.req' -and
            $file.Name -notmatch '.p12')
        {
            # Get file content
            $CAFiles.Add($file, (Get-Content -Path $file.FullName -Raw))
        }
    }

    # Check crt
    if (-not $CAFiles.GetEnumerator().Where({$_.Key -match '.crt'}))
    {
        throw "Can't find `"$CACommonName`" crt, aborting..."
    }

    # Check crl
    if (-not $CAFiles.GetEnumerator().Where({$_.Key -match '.crl'}))
    {
        throw "Can't find `"$CACommonName`" crl, aborting..."
    }

    # Check response file
    $CAResponse = Get-Item -Path "$PSScriptRoot\$CACommonName-Response.crt" -ErrorAction SilentlyContinue

    if ($CAResponse -and
        (ShouldProcess @WhatIfSplat))
    {
        # Get file content
        $CAResponseFile = Get-Content -Path $CAResponse.FullName -Raw

        # Remove response file
        Remove-Item -Path $CAResponse.FullName
    }

    # ███╗   ███╗ █████╗ ██╗███╗   ██╗
    # ████╗ ████║██╔══██╗██║████╗  ██║
    # ██╔████╔██║███████║██║██╔██╗ ██║
    # ██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    # ██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    # ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

    $MainScriptBlock =
    {
        ###############
        # Check domain
        ###############

        $Win32_ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem

        # Check for part of domain
        if ($Win32_ComputerSystem.PartOfDomain)
        {
            $DomainName = $Win32_ComputerSystem.Domain
        }

        if (-not $HostName)
        {
            if ($DomainName)
            {
                $HostName = "pki.$DomainName"
            }
            else
            {
                throw "Not domain joined, please use -HostName to set FQDN of host."
            }
        }

        ######
        # IIS
        ######

        # Check if windows feature is installed
        if ((Get-WindowsFeature -Name Web-Server).InstallState -notmatch 'Install' -and
            (ShouldProcess @WhatIfSplat -Message "Installing Web-Server windows feature." @VerboseSplat))
        {
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools > $null
        }

        $AllFeatures =
        @(
            'Web-Asp-Net45'
        )

        foreach($feature in $AllFeatures)
        {
           if ((Get-WindowsFeature -Name $feature).InstallState -notmatch 'Install' -and
            (ShouldProcess @WhatIfSplat -Message "Installing $feature." @VerboseSplat))
            {
                Install-WindowsFeature -Name $feature > $null
            }
        }

        # Check if IIS drive is mapped
        try
        {
            Get-PSDrive -Name IIS -ErrorAction Stop > $null
        }
        catch
        {
            Import-Module WebAdministration
        }

        # Get ip address
        $IPAddress = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -in @('Manual', 'DHCP')} | Sort-Object -Property ifIndex | Select-Object -ExpandProperty IPAddress -First 1

        ##########
        # Binding
        ##########

        # Get web binding
        $WebBinding = Get-WebBinding -Name 'Default Web Site'

        # Check default binding
        if ($WebBinding.bindingInformation -eq "*:80:" -and
            (ShouldProcess @WhatIfSplat -Message "Remove default web binding `"*:80:`" from `"Default Web Site`"" @VerboseSplat))
        {
            Remove-WebBinding -Name 'Default Web Site' -IPAddress * -Port 80 -HostHeader ''
        }

        # Check pki binding
        if (-not $WebBinding.Where({$_.bindingInformation -eq "*:80:$HostName"}) -and
            (ShouldProcess @WhatIfSplat -Message "Adding web binding `"*:80:$HostName`" to `"Default Web Site`"" @VerboseSplat))
        {
            New-WebBinding -Name 'Default Web Site' -IPAddress * -Port 80 -HostHeader $HostName
        }

        ###########
        # Settings
        ###########

        # Check double escaping
        if ((Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter /system.webServer/Security/requestFiltering -Name allowDoubleEscaping).Value -eq $false -and
            (ShouldProcess @WhatIfSplat -Message "Enabling double escaping." @VerboseSplat))
        {
            Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter /system.webServer/Security/requestFiltering -Name allowDoubleEscaping -Value $true
        }

        # Check directory browsing
        if ((Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter /system.webServer/directoryBrowse -Name enabled).Value -eq $false -and
            (ShouldProcess @WhatIfSplat -Message "Enabling directory browsing." @VerboseSplat))
        {
            Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter /system.webServer/directoryBrowse -Name enabled -Value $true
        }

        # Hide files under wwwroot
        foreach ($File in (Get-ChildItem -Path "C:\inetpub\wwwroot" -Exclude '*.crt', '*.crl'))
        {
            if (-not ($File.Attributes -contains 'Hidden') -and
                ((ShouldProcess @WhatIfSplat -Message "Setting hidden on `"$($File.Name)`"." @VerboseSplat)))
            {
                $File.Attributes += 'Hidden'
            }
        }

        ########
        # Start
        ########

        # Check State
        if ((Get-Website -Name 'Default Web Site').State -ne 'Started' -and
            (ShouldProcess @WhatIfSplat -Message "Starting website `"Default Web Site`"" @VerboseSplat))
        {
            Start-Website -Name 'Default Web Site' -ErrorAction Stop
        }

        ########
        # Share
        ########

        if ($ShareName)
        {
            if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Creating share." @VerboseSplat))
            {
                # Add new share
                New-SmbShare -Name $ShareName -Path "C:\inetpub\wwwroot" -ReadAccess "Authenticated Users" > $null
            }

            if (-not (Get-SmbShareAccess -Name $ShareName | Where-Object { $_.AccountName -like "*$ShareAccess*" -and $_.AccessRight -eq 'Change'}) -and
                (ShouldProcess @WhatIfSplat -Message "Setting share change access for `"$ShareAccess`"." @VerboseSplat))
            {
                # Grant change access
                Grant-SmbShareAccess -Name $ShareName -AccountName $ShareAccess -AccessRight Change -Force > $null
            }

            # Get NTFS acl
            $Acl = Get-Acl -Path "C:\inetpub\wwwroot"

            if (-not ($Acl.Access | Where-Object { $_.FileSystemRights -eq 'Modify, Synchronize' -and $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -like "*$ShareAccess*" -and $_.InheritanceFlags -eq 'ContainerInherit, ObjectInherit' -and $_.PropagationFlags -eq 'None' }) -and
                (ShouldProcess @WhatIfSplat -Message "Setting share NTFS modify rights for `"$ShareAccess`"." @VerboseSplat))
            {
                # Add CA server modify
                $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList `
                @(
                    <#IdentityReference#> [System.Security.Principal.NTAccount] $ShareAccess,
                    [System.Security.AccessControl.FileSystemRights] "Modify, Synchronize",
                    [System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit"
                    [System.Security.AccessControl.PropagationFlags] "None",
                    [System.Security.AccessControl.AccessControlType] "Allow"
                )
                $Acl.AddAccessRule($Ace)

                # Set NTFS acl
                Set-Acl -AclObject $Acl -Path "C:\inetpub\wwwroot"
            }
        }

        ########
        # Files
        ########

        # Create temp Directory
        New-Item -ItemType Directory -Path "$env:TEMP" -Name $CACommonName -Force > $null

        # Itterate all file
        foreach($file in $CAFiles.GetEnumerator())
        {
            # Save file to temp
            Set-Content -Path "$env:TEMP\$CACommonName\$($file.Key.Name)" -Value $file.Value -Force

            # Set original timestamps
            Set-ItemProperty -Path "$env:TEMP\$CACommonName\$($file.Key.Name)" -Name CreationTime -Value $file.Key.CreationTime
            Set-ItemProperty -Path "$env:TEMP\$CACommonName\$($file.Key.Name)" -Name LastWriteTime -Value $file.Key.LastWriteTime
            Set-ItemProperty -Path "$env:TEMP\$CACommonName\$($file.Key.Name)" -Name LastAccessTime -Value $file.Key.LastAccessTime

            # Copy
            Copy-DifferentItem -SourcePath "$env:TEMP\$CACommonName\$($file.Key.Name)" -TargetPath "C:\inetpub\wwwroot\$($file.Key.Name)" @VerboseSplat
        }

        # Remove temp directory
        Remove-Item -Path "$env:TEMP\$CACommonName" -Force -Recurse

        #  ██████╗  ██████╗███████╗██████╗
        # ██╔═══██╗██╔════╝██╔════╝██╔══██╗
        # ██║   ██║██║     ███████╗██████╔╝
        # ██║   ██║██║     ╚════██║██╔═══╝
        # ╚██████╔╝╚██████╗███████║██║
        #  ╚═════╝  ╚═════╝╚══════╝╚═╝

        if ($OCSPManualRequest.IsPresent -or ($OCSPCAConfig -and $OCSPTemplate))
        {
            ##########
            # Feature
            ##########

            # Check if OCSP is installed
            if (((Get-WindowsFeature -Name ADCS-Online-Cert).InstallState -ne 'Installed') -and
                (ShouldProcess @WhatIfSplat -Message "Installing ADCS-Online-Cert." @VerboseSplat))
            {
                Install-WindowsFeature -Name ADCS-Online-Cert -IncludeManagementTools > $null
            }

            #Check if OCSP is configured
            try
            {
                # Throws if configured
                Install-AdcsOnlineResponder -WhatIf > $null

                if (ShouldProcess @WhatIfSplat -Message "Configuring OCSP." @VerboseSplat)
                {
                    Install-AdcsOnlineResponder -Force > $null
                }
            }
            catch
            {
                # OCSP is configured
            }

            ############
            # Configure
            ############

            # OCSP Signing Flags
            # http://msdn.microsoft.com/en-us/library/windows/desktop/aa386387(v=vs.85).aspx
            $OCSP_SF_SILENT = 0x001
            $OCSP_SF_ALLOW_SIGNINGCERT_AUTORENEWAL = 0x004
            $OCSP_SF_FORCE_SIGNINGCERT_ISSUER_ISCA = 0x008
            $OCSP_SF_AUTODISCOVER_SIGNINGCERT = 0x010
            $OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT = 0x020
            $OCSP_SF_RESPONDER_ID_KEYHASH = 0x040
            $OCSP_SF_ALLOW_NONCE_EXTENSION = 0x100
            $OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT = 0x200

            # Set default signing flags
            $OcspSigningFlags = $OCSP_SF_SILENT + `
                                $OCSP_SF_RESPONDER_ID_KEYHASH

            if ($OCSPAddNounce.IsPresent)
            {
                # Add nounce flag
                $OcspSigningFlags += $OCSP_SF_ALLOW_NONCE_EXTENSION
            }

            # Get OCSP admin
            $OcspAdmin = New-Object -Com "CertAdm.OCSPAdmin"
            $OcspAdmin.GetConfiguration($ComputerName, $true)

            # Get OCSP configuration
            $OcspConfig = $OcspAdmin.OCSPCAConfigurationCollection | Where-Object { $_.Identifier -eq $CACommonName }

            if (-not $OcspConfig -and
               (ShouldProcess @WhatIfSplat -Message "Creating OCSP configuration." @VerboseSplat))
            {
                $OcspConfig = $OcspAdmin.OCSPCAConfigurationCollection.CreateCAConfiguration($CACommonName, ([System.Security.Cryptography.X509Certificates.X509Certificate2] "C:\inetpub\wwwroot\$CACommonName.crt").RawData)
            }

            #############
            # Properties
            #############

            $OcspProperties = New-Object -Com "CertAdm.OCSPPropertyCollection"
            $OcspProperties.InitializeFromProperties($OcspConfig.ProviderProperties)

            #######
            # Crls
            #######

            $CRLUrls = @()
            $DeltaUrls = @()

            # Get crl files
            # FIX
            # use localhost
            foreach($file in Get-Item -Path "C:\inetpub\wwwroot\*$CACommonName*.crl")
            {
                if ($file.Name -notmatch '\+')
                {
                    $CRLUrls += "http://$HostName/$($file.Name)"
                }
                else
                {
                    $DeltaUrls += "http://$HostName/$($file.Name)"
                }
            }

            # Crl
            if ($CRLUrls)
            {
                if ($OcspProperties | Where-Object { $_.Name -eq 'BaseCrlUrls' })
                {
                    if (-not @(Compare-Object -ReferenceObject $CRLUrls -DifferenceObject $OcspProperties.ItemByName('BaseCrlUrls').Value -SyncWindow 0).Length -eq 0 -and
                        (ShouldProcess @WhatIfSplat -Message "Setting BaseCrlUrls $($CRLUrls -join ', ')." @VerboseSplat))
                    {
                        $OcspProperties.ItemByName('BaseCrlUrls').Value = $CRLUrls
                    }
                }
                elseif (ShouldProcess @WhatIfSplat -Message "Adding BaseCrlUrls $($CRLUrls -join ', ')." @VerboseSplat)
                {
                    $OcspProperties.CreateProperty("BaseCrlUrls", $CRLUrls) > $null
                }
            }

            # Delta
            if ($DeltaUrls)
            {
                if ($OcspProperties | Where-Object { $_.Name -eq 'DeltaCrlUrls' })
                {
                    if (-not @(Compare-Object -ReferenceObject $DeltaUrls -DifferenceObject $OcspProperties.ItemByName('DeltaCrlUrls').Value -SyncWindow 0).Length -eq 0 -and
                        (ShouldProcess @WhatIfSplat -Message "Setting DeltaCrlUrls $($DeltaUrls -join ', ')." @VerboseSplat))
                    {
                        $OcspProperties.ItemByName('DeltaCrlUrls').Value = $DeltaUrls
                    }
                }
                elseif (ShouldProcess @WhatIfSplat -Message "Adding DeltaCrlUrls $($DeltaUrls -join ', ')." @VerboseSplat)
                {
                    $OcspProperties.CreateProperty("DeltaCrlUrls", $DeltaUrls) > $null
                }
            }

            # RefreshTimeOut
            if ($OCSPRefreshTimeout)
            {
                if ($OcspProperties | Where-Object { $_.Name -eq 'RefreshTimeOut' })
                {
                    if ($OcspProperties.ItemByName('RefreshTimeOut').Value -ne $OCSPRefreshTimeout -and
                        (ShouldProcess @WhatIfSplat -Message "Setting RefreshTimeOut property." @VerboseSplat))
                    {
                        $OcspProperties.ItemByName('RefreshTimeOut').Value = $OCSPRefreshTimeout * 60000
                    }
                }
                elseif (ShouldProcess @WhatIfSplat -Message "Adding RefreshTimeOut property." @VerboseSplat)
                {
                    $OcspProperties.CreateProperty("RefreshTimeOut", ($OCSPRefreshTimeout * 60000)) > $null
                }
            }

            # Set properties
            $OcspConfig.ProviderProperties = $OcspProperties.GetAllProperties()

            ########################
            # Standalone CA Request
            ########################

            if ($OCSPManualRequest.IsPresent)
            {
                # Get signing certificate
                $SigningCertificate = Get-Item -Path Cert:\LocalMachine\My\* | Where-Object { $_.Subject -match "$CACommonName OCSP Signing" -and $_.Extensions['2.5.29.37'] -and $_.Extensions['2.5.29.37'].EnhancedKeyUsages.FriendlyName.Contains('OCSP Signing') }

                if ($SigningCertificate)
                {
                    if ($OcspConfig.SigningCertificate)
                    {
                        # Compare arrays
                        if (-not @(Compare-Object -ReferenceObject $SigningCertificate.RawData -DifferenceObject $OcspConfig.SigningCertificate -SyncWindow 0).Length -eq 0 -and
                           (ShouldProcess @WhatIfSplat -Message "Setting SigningCertificate `"$($SigningCertificate.Thumbprint)`"" @VerboseSplat))
                        {
                            $OcspConfig.SigningCertificate = $SigningCertificate.RawData
                        }
                    }
                    elseif (ShouldProcess @WhatIfSplat -Message "Adding SigningCertificate `"$($SigningCertificate.Thumbprint)`"" @VerboseSplat)
                    {
                        $OcspConfig.SigningCertificate = $SigningCertificate.RawData
                    }
                }
                else
                {
                    ##########
                    # Request
                    ##########

                    $OCSPCertifiateSubject = "CN=$ComputerName"

                    if ($DomainName)
                    {
                        $OCSPCertifiateSubject += ".$DomainName"
                    }
# FIX
# test KSP provider with SHA256
$RequestInf =
@"
[NewRequest]
Subject = "$OCSPCertifiateSubject"
MachineKeySet = True
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
KeyLength = 2048
[EnhancedKeyUsageExtension]
OID="1.3.6.1.5.5.7.3.9"
"@
                    # Save inf file
                    Set-Content -Path "$env:TEMP\$CACommonName OSCP Signing.inf" -Value $RequestInf

                    # New certificate request
                    TryCatch { certreq -f -q -new "$env:TEMP\$CACommonName OSCP Signing.inf" "$env:TEMP\$CACommonName OSCP Signing.req" } > $null

                    # Remove inf file
                    Remove-Item -Path "$env:TEMP\$CACommonName OSCP Signing.inf"
                }

                # Add manual flags
                $OcspSigningFlags += $OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT

                if (-not $OCSPHashAlgorithm)
                {
                    $OCSPHashAlgorithm = 'SHA1'
                }
            }

            ###############################
            # Enterprise CA Autoenrollment
            ###############################

            else
            {
                # Add autoenrollment flags
                $OcspSigningFlags += $OCSP_SF_ALLOW_SIGNINGCERT_AUTORENEWAL + `
                                     $OCSP_SF_FORCE_SIGNINGCERT_ISSUER_ISCA + `
                                     $OCSP_SF_AUTODISCOVER_SIGNINGCERT + `
                                     $OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT

                if (-not $OCSPHashAlgorithm)
                {
                    $OCSPHashAlgorithm = 'SHA256'
                }

                if ($OcspConfig.CAConfig -ne $OCSPCAConfig -and
                   (ShouldProcess @WhatIfSplat -Message "Setting CAConfig `"$OCSPCAConfig`"" @VerboseSplat))
                {
                    $OcspConfig.CAConfig = $OCSPCAConfig
                }

                if ($OcspConfig.SigningCertificateTemplate -ne $OCSPTemplate -and
                   (ShouldProcess @WhatIfSplat -Message "Setting SigningCertificateTemplate `"$OCSPTemplate`"" @VerboseSplat))
                {
                    $OcspConfig.SigningCertificateTemplate = $OCSPTemplate
                }
            }

            ################
            # Configuration
            ################

            if ($OcspConfig.ProviderCLSID -ne '{4956d17f-88fd-4198-b287-1e6e65883b19}' -and
               (ShouldProcess @WhatIfSplat -Message "Setting ProviderCLSID." @VerboseSplat))
            {
                $OcspConfig.ProviderCLSID = '{4956d17f-88fd-4198-b287-1e6e65883b19}'
            }

            if ($OcspConfig.ReminderDuration -ne 90 -and
               (ShouldProcess @WhatIfSplat -Message "Setting ReminderDuration 90" @VerboseSplat))
            {
                $OcspConfig.ReminderDuration = 90
            }

            if ($OcspConfig.SigningFlags -ne $OcspSigningFlags -and
               (ShouldProcess @WhatIfSplat -Message "Setting SigningFlags $OcspSigningFlags" @VerboseSplat))
            {
                $OcspConfig.SigningFlags = $OcspSigningFlags
            }

            if ($OcspConfig.HashAlgorithm -ne $OCSPHashAlgorithm -and
               (ShouldProcess @WhatIfSplat -Message "Setting HashAlgorithm $OCSPHashAlgorithm" @VerboseSplat))
            {
                $OcspConfig.HashAlgorithm = $OCSPHashAlgorithm
            }

            # FIX
            # refresh responder

            # Set configuration
            $OcspAdmin.SetConfiguration($ComputerName, $true)
        }

        # ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗
        # ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║
        # ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║
        # ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║
        # ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
        # ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

        # Check if OCSP signing certificate request exist
        if (Test-Path -Path "$env:TEMP\$CACommonName OSCP Signing.req")
        {
            # Check if file exist
            $CAResponseFileExist = Test-Path -Path "$env:TEMP\$CACommonName-Response.crt"

            # Check if response file exist
            if (($CAResponseFile -or $CAResponseFileExist) -and
                (ShouldProcess @WhatIfSplat -Message "Installing OCSP signing certificate..." @VerboseSplat))
            {
                if (-not $CAResponseFileExist)
                {
                    Set-Content -Path "$env:TEMP\$CACommonName-Response.crt" -Value $CAResponseFile
                }

                # Try installing certificate
                TryCatch { certreq -q -accept "`"$env:TEMP\$CACommonName-Response.crt`"" } -ErrorAction Stop > $null

                ############
                # Configure
                ############

                # Get signing certificate
                $SigningCertificate = Get-Item -Path Cert:\LocalMachine\My\* | Where-Object { $_.Subject -match "$CACommonName OCSP Signing" -and $_.Extensions['2.5.29.37'] -and $_.Extensions['2.5.29.37'].EnhancedKeyUsages.FriendlyName.Contains('OCSP Signing') }

                # Set key container path
                $SigningCertificateKeyContainerPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($SigningCertificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)"

                if (Test-Path -Path $SigningCertificateKeyContainerPath)
                {
                    # Get NTFS acl
                    $Acl = Get-Acl -Path $SigningCertificateKeyContainerPath

                    # Add system full control
                    $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList `
                    @(
                        <#IdentityReference#> [System.Security.Principal.NTAccount] "NT AUTHORITY\SYSTEM",
                        [System.Security.AccessControl.FileSystemRights] "FullControl",
                        [System.Security.AccessControl.InheritanceFlags] "None"
                        [System.Security.AccessControl.PropagationFlags] "None",
                        [System.Security.AccessControl.AccessControlType] "Allow"
                    )
                    $Acl.AddAccessRule($Ace)

                    # Add administrators full control
                    $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList `
                    @(
                        <#IdentityReference#> [System.Security.Principal.NTAccount] "BUILTIN\Administrators",
                        [System.Security.AccessControl.FileSystemRights] "FullControl",
                        [System.Security.AccessControl.InheritanceFlags] "None"
                        [System.Security.AccessControl.PropagationFlags] "None",
                        [System.Security.AccessControl.AccessControlType] "Allow"
                    )
                    $Acl.AddAccessRule($Ace)

                    # Add administrators full control
                    $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList `
                    @(
                        <#IdentityReference#> [System.Security.Principal.NTAccount] "NETWORK SERVICE",
                        [System.Security.AccessControl.FileSystemRights] "Read",
                        [System.Security.AccessControl.InheritanceFlags] "None"
                        [System.Security.AccessControl.PropagationFlags] "None",
                        [System.Security.AccessControl.AccessControlType] "Allow"
                    )
                    $Acl.AddAccessRule($Ace)

                    # Set NTFS acl
                    Set-Acl -AclObject $Acl -Path $SigningCertificateKeyContainerPath
                }

                # Get OCSP admin
                $OcspAdmin = New-Object -Com "CertAdm.OCSPAdmin"
                $OcspAdmin.GetConfiguration($ComputerName, $true)

                # Get OCSP configuration
                $OcspConfig = $OcspAdmin.OCSPCAConfigurationCollection | Where-Object { $_.Identifier -eq $CACommonName }

                # Set signing certificate
                $OcspConfig.SigningCertificate = $SigningCertificate.RawData

                # Commit Revocation Configuration
                $OcspAdmin.SetConfiguration($ComputerName, $true)

                ##########
                # Cleanup
                ##########

                # Remove request file
                Remove-Item -Path "$env:TEMP\$CACommonName OSCP Signing.req"

                # Remove response file
                Remove-Item -Path "$env:TEMP\$CACommonName-Response.crt"
            }
            else
            {
                # Update group policy
                Start-Process cmd -ArgumentList "/c gpupdate"

                # Output requestfile
                Write-Request -Path "$env:TEMP"
            }
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
            # f_ShouldProcess.ps1 loaded in Begin
            . $PSScriptRoot\f_CopyDifferentItem.ps1
        }
        catch [Exception]
        {
            throw $_
        }

    } -NoNewScope

    # Remote
    if ($Session -and $Session.State -eq 'Opened')
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_GetBaseDN.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_WriteRequest.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Splat
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $ComputerName = $Using:ComputerName

            $CACommonName = $Using:CACommonName
            $DomainName = $Using:DomainName

            $HostName = $Using:HostName
            $ShareName = $Using:ShareName
            $ShareAccess = $Using:ShareAccess

            $OCSPCAConfig = $Using:OCSPCAConfig
            $OCSPTemplate = $Using:OCSPTemplate

            $OCSPManualRequest = $Using:OCSPManualRequest

            $OCSPRefreshTimeout = $Using:OCSPRefreshTimeout
            $OCSPAddNounce = $Using:OCSPAddNounce
            $OCSPHashAlgorithm = $Using:OCSPHashAlgorithm

            # Files
            $CAFiles = $Using:CAFiles
            $CAResponseFile = $Using:CAResponseFile
        }

        # Run main
        $Result = Invoke-Command -Session $Session -ScriptBlock $MainScriptBlock
    }
    else # Locally
    {
        if ((Read-Host "Invoke locally? [y/n]") -ne 'y')
        {
            break
        }

        # Load functions
        Invoke-Command -ScriptBlock `
        {
            try
            {
                . $PSScriptRoot\f_TryCatch.ps1
                . $PSScriptRoot\f_GetBaseDN.ps1
                . $PSScriptRoot\f_WriteRequest.ps1
            }
            catch [Exception]
            {
                throw $_
            }

        } -NoNewScope

        # Run main
        $Result = Invoke-Command -ScriptBlock $MainScriptBlock -NoNewScope
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
            foreach($file in $Result.GetEnumerator())
            {
                # Save in temp
                Set-Content -Path "$env:TEMP\$($file.Key.Name)" -Value $file.Value

                # Set original timestamps
                Set-ItemProperty -Path "$env:TEMP\$($file.Key.Name)" -Name CreationTime -Value $file.Key.CreationTime
                Set-ItemProperty -Path "$env:TEMP\$($file.Key.Name)" -Name LastWriteTime -Value $file.Key.LastWriteTime
                Set-ItemProperty -Path "$env:TEMP\$($file.Key.Name)" -Name LastAccessTime -Value $file.Key.LastAccessTime

                # Move to script root if different
                Copy-DifferentItem -SourcePath "$env:TEMP\$($file.Key.Name)" -Delete -TargetPath "$PSScriptRoot\$($file.Key.Name)" @VerboseSplat
            }
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
# MIIXpgYJKoZIhvcNAQcCoIIXlzCCF5MCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUT6f1K8zNtzHRpNDfYpRxfl1U
# TXKgghI6MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# u5VPaG2W3eV3Ay67nBLvifkIP9Y1KTF5JS+wzJoYKvZ2MIIGajCCBVKgAwIBAgIQ
# AwGaAjr/WLFr1tXq5hfwZjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENBLTEwHhcNMTQxMDIyMDAw
# MDAwWhcNMjQxMDIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGln
# aUNlcnQxJTAjBgNVBAMTHERpZ2lDZXJ0IFRpbWVzdGFtcCBSZXNwb25kZXIwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjZF38fLPggjXg4PbGKuZJdTvM
# buBTqZ8fZFnmfGt/a4ydVfiS457VWmNbAklQ2YPOb2bu3cuF6V+l+dSHdIhEOxnJ
# 5fWRn8YUOawk6qhLLJGJzF4o9GS2ULf1ErNzlgpno75hn67z/RJ4dQ6mWxT9RSOO
# hkRVfRiGBYxVh3lIRvfKDo2n3k5f4qi2LVkCYYhhchhoubh87ubnNC8xd4EwH7s2
# AY3vJ+P3mvBMMWSN4+v6GYeofs/sjAw2W3rBerh4x8kGLkYQyI3oBGDbvHN0+k7Y
# /qpA8bLOcEaD6dpAoVk62RUJV5lWMJPzyWHM0AjMa+xiQpGsAsDvpPCJEY93AgMB
# AAGjggM1MIIDMTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDCCAb8GA1UdIASCAbYwggGyMIIBoQYJYIZIAYb9bAcB
# MIIBkjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCC
# AWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABp
# AHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABl
# AHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBp
# AEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5
# AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBj
# AGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQBy
# AGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5
# ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1sAxUwHwYDVR0jBBgwFoAU
# FQASKxOYspkH7R7for5XDStnAs0wHQYDVR0OBBYEFGFaTSS2STKdSip5GoNL9B6J
# wcp9MH0GA1UdHwR2MHQwOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRENBLTEuY3JsMDigNqA0hjJodHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURDQS0xLmNybDB3BggrBgEFBQcBAQRr
# MGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEF
# BQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEQ0EtMS5jcnQwDQYJKoZIhvcNAQEFBQADggEBAJ0lfhszTbImgVybhs4jIA+A
# h+WI//+x1GosMe06FxlxF82pG7xaFjkAneNshORaQPveBgGMN/qbsZ0kfv4gpFet
# W7easGAm6mlXIV00Lx9xsIOUGQVrNZAQoHuXx/Y/5+IRQaa9YtnwJz04HShvOlIJ
# 8OxwYtNiS7Dgc6aSwNOOMdgv420XEwbu5AO2FKvzj0OncZ0h3RTKFV2SQdr5D4HR
# mXQNJsQOfxu19aDxxncGKBXp2JPlVRbwuwqrHNtcSCdmyKOLChzlldquxC5ZoGHd
# 2vNtomHpigtt7BIYvfdVVEADkitrwlHCCkivsNRu4PQUCjob4489yq9qjXvc2EQw
# ggbNMIIFtaADAgECAhAG/fkDlgOt6gAK6z8nu7obMA0GCSqGSIb3DQEBBQUAMGUx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9v
# dCBDQTAeFw0wNjExMTAwMDAwMDBaFw0yMTExMTAwMDAwMDBaMGIxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOiCLZn5ysJClaWAc0Bw0p5WVFypxNJB
# Bo/JM/xNRZFcgZ/tLJz4FlnfnrUkFcKYubR3SdyJxArar8tea+2tsHEx6886QAxG
# TZPsi3o2CAOrDDT+GEmC/sfHMUiAfB6iD5IOUMnGh+s2P9gww/+m9/uizW9zI/6s
# VgWQ8DIhFonGcIj5BZd9o8dD3QLoOz3tsUGj7T++25VIxO4es/K8DCuZ0MZdEkKB
# 4YNugnM/JksUkK5ZZgrEjb7SzgaurYRvSISbT0C58Uzyr5j79s5AXVz2qPEvr+yJ
# IvJrGGWxwXOt1/HYzx4KdFxCuGh+t9V3CidWfA9ipD8yFGCV/QcEogkCAwEAAaOC
# A3owggN2MA4GA1UdDwEB/wQEAwIBhjA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYB
# BQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwggHSBgNVHSAEggHJ
# MIIBxTCCAbQGCmCGSAGG/WwAAQQwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3
# LmRpZ2ljZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUH
# AgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQBy
# AHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBj
# AGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAg
# AEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQ
# AGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBt
# AGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBj
# AG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBl
# AHIAZQBuAGMAZQAuMAsGCWCGSAGG/WwDFTASBgNVHRMBAf8ECDAGAQH/AgEAMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3Js
# MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
# SURSb290Q0EuY3JsMB0GA1UdDgQWBBQVABIrE5iymQftHt+ivlcNK2cCzTAfBgNV
# HSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEA
# RlA+ybcoJKc4HbZbKa9Sz1LpMUerVlx71Q0LQbPv7HUfdDjyslxhopyVw1Dkgrkj
# 0bo6hnKtOHisdV0XFzRyR4WUVtHruzaEd8wkpfMEGVWp5+Pnq2LN+4stkMLA0rWU
# vV5PsQXSDj0aqRRbpoYxYqioM+SbOafE9c4deHaUJXPkKqvPnHZL7V/CSxbkS3BM
# AIke/MV5vEwSV/5f4R68Al2o/vsHOE8Nxl2RuQ9nRc3Wg+3nkg2NsWmMT/tZ4CMP
# 0qquAHzunEIOz5HXJ7cW7g/DvXwKoO4sCFWFIrjrGBpN/CohrUkxg0eVd3HcsRtL
# SxwQnHcUwZ1PL1qVCCkQJjGCBNYwggTSAgEBMCIwDjEMMAoGA1UEAwwDYmNsAhAm
# gCXENLd3vEkRd4RFJAiRMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSJ8SgFMJQ1Hr/qw9kSyOEn
# 4qifgzANBgkqhkiG9w0BAQEFAASCAgA/G+rGg7t6GvQLVo15HlUO0FtnaMJuCaCZ
# Bob8T9YycAWFibk/E5OGx837/xRvzCslrtyZvH518lECaDYRre8gsmKO28pC2jSX
# WOwOHvvEsaT5KuZDyyzQnARlFuSf5Hhnz89qL7g/NRg3ID5j/uVaDdp3HxcB5xc9
# 8pn+usWZIeCYXSx7L5Znc1ZLU1HTB6WJNclXTHd9I32cS5SgKuH4qlRsH+St1HL9
# 9TmjetTkXf3uIx5OgEHRLrwXztNt6yzxqqJETZaHUouw4YGZHs3/IbJg+fJXHWxu
# 0hZQuPK9XLhJFpxSDfAJSDpi6DI38+6zt8FEjUZOoetGmaNhFexouc22hhqh5P+O
# HWxgLvC7Ri0DKYcI1Z0Fzb4dAdP8Ssl+ZI4SXpzw8KyBql2LQ54QiojqmxxadGn0
# e97Pf1jMC7nQdCLZ1svItiQK6Mo3njoGXZHd6Nypi/IWjEPxN5zD3SetVqIcHgHY
# 25uvsTHewunC/lhE8rXFm4G41YM76XCmxgS6lXCzDxMNnM404YTxVa9NjDwDfhWY
# ccXvvuqt/YIiTvXBlSBQeZvBvJdJqSK22dctGzHcVCH7Ut+L+dpqdy9qGMnFE1Ns
# kcwYTIMBRhtgNrmbAjQ0yB9DpplTKY92wUGJaQ885UJ6YSEypyTyG1wjpgQ39xzs
# UFzYKdEGbaGCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAxMDIzMTYwMDAyWjAjBgkqhkiG9w0BCQQx
# FgQUxHpWX5NgKSubx5gT3DLqvDqB3QAwDQYJKoZIhvcNAQEBBQAEggEAHWk60dwX
# dNbTndbehfal/3dVHV0s96NQWirNN4paEPTUVz672Z/Du0aW5+e2dC864ldqKdtJ
# P4NGC/2BqY0zxsxNZ+PYOhhZCw05m3HJ63pInOVCVD3eBo6NOGuUFf9WAJymUXsC
# GnlxN6He77ZhEfyjL4re21UHfu7ZzsXFLHa3vJ1Lv5wDxShAxtW+E1dm7zcrAgxc
# olQQ70eeYyuuHmphy33IJmHSrMc6k7ujTxrky7fiSZn9EWbQ0VNQq2fNbGEW5mK1
# G/gT0ygj9G9X43hIdyvyElatwjHAoGU8iNY8AJ7FNkp+iASPh4rjf3vXfvpTOkT+
# Bo32dBXK6Khj0g==
# SIG # End signature block
