<#
 .DESCRIPTION
    Setup and configure Validation Authority (AIA, CDP and OCSP)
 .NOTES
    AUTHOR Jonas Henriksson
 .LINK
    https://github.com/J0N7E
#>

[cmdletbinding(SupportsShouldProcess=$true, DefaultParameterSetName='Standard')]

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
    [Int]$OCSPRefreshTimeout,

    #######
    # NDES
    #######

    [Switch]$DeviceEnrollment
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
            $file.Extension -ne '.req' -and
            $file.Extension -ne '.p12')
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
    $CAResponse = Get-Item -Path "$PSScriptRoot\$CACommonName OSCP Signing-Response.crt" -ErrorAction SilentlyContinue

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

        # Files to be removed
        $RemoveFiles = @('iisstart.htm', 'iisstart.png')

        # Remove files
        foreach ($File in $RemoveFiles)
        {
            if ((Test-Path -Path "C:\inetpub\wwwroot\$File") -and
                (ShouldProcess @WhatIfSplat -Message "Remove $File." @VerboseSplat))
            {
                Remove-Item -Path "C:\inetpub\wwwroot\$File" -Force
            }
        }

        # Hide other files under wwwroot
        foreach ($File in (Get-ChildItem -Path "C:\inetpub\wwwroot" -Exclude '*.crt', '*.crl'))
        {
            if (-not ($File.Attributes -contains 'Hidden') -and
                (ShouldProcess @WhatIfSplat -Message "Setting hidden on `"$($File.Name)`"." @VerboseSplat))
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
            $FullName = "$env:TEMP\$CACommonName\$($file.Key.Name)"

            # Save file to temp
            Set-Content -Path $FullName -Value $file.Value -Force

            # Set original timestamps
            Set-ItemProperty -Path $FullName -Name CreationTime -Value $file.Key.CreationTime
            Set-ItemProperty -Path $FullName -Name LastWriteTime -Value $file.Key.LastWriteTime
            Set-ItemProperty -Path $FullName -Name LastAccessTime -Value $file.Key.LastAccessTime

            # Copy
            Copy-DifferentItem -SourcePath $FullName -TargetPath "C:\inetpub\wwwroot\$($file.Key.Name)" @VerboseSplat

            if (-not $DomainName -and $file.Key.Extension -eq '.crt')
            {
                if ($file.Key.Name -match 'Root' -and
                    -not (TryCatch { certutil -store root "`"$CACommonName`"" } -ErrorAction SilentlyContinue | Where-Object { $_ -match "command completed successfully" }) -and
                    (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Key.Name)`" to trusted root store." @VerboseSplat))
                {
                    TryCatch { certutil -addstore root "`"$FullName`"" } > $null
                }

                if (($file.Key.Name -match 'Sub' -or $file.Key.Name -match 'Issuing') -and
                    -not (TryCatch { certutil -store ca "`"$CACommonName`"" } -ErrorAction SilentlyContinue | Where-Object { $_ -match "command completed successfully" }) -and
                    (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Key.Name)`" to intermediate ca store." @VerboseSplat))
                {
                    TryCatch { certutil -addstore ca "`"$FullName`"" } > $null
                }
            }
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
            $OcspAdmin = New-Object -ComObject "CertAdm.OCSPAdmin"
            $OcspAdmin.GetConfiguration($ENV:ComputerName, $true)

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

            $OcspProperties = New-Object -ComObject "CertAdm.OCSPPropertyCollection"
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

# FIX
# test KSP provider with SHA256

$RequestInf =
@"
[NewRequest]
Subject = "CN=$CACommonName OCSP Signing"
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
            $OcspAdmin.SetConfiguration($ENV:ComputerName, $true)

            #########
            # Accept
            #########

            # Check if OCSP signing certificate request exist
            if (Test-Path -Path "$env:TEMP\$CACommonName OSCP Signing.req")
            {
                # Check if file exist
                $CAResponseFileExist = Test-Path -Path "$env:TEMP\$CACommonName OSCP Signing-Response.crt"

                # Check if response file exist
                if (($CAResponseFile -or $CAResponseFileExist) -and
                    (ShouldProcess @WhatIfSplat -Message "Installing OCSP signing certificate..." @VerboseSplat))
                {
                    if (-not $CAResponseFileExist)
                    {
                        Set-Content -Path "$env:TEMP\$CACommonName OSCP Signing-Response.crt" -Value $CAResponseFile
                    }

                    # Try installing certificate
                    TryCatch { certreq -q -accept "`"$env:TEMP\$CACommonName OSCP Signing-Response.crt`"" } -ErrorAction Stop > $null

                    #############################
                    # Set privat key permissions
                    #############################

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

                        # Add network service full control
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

                    ############
                    # Configure
                    ############

                    # Get OCSP admin
                    $OcspAdmin = New-Object -ComObject "CertAdm.OCSPAdmin"
                    $OcspAdmin.GetConfiguration($ENV:ComputerName, $true)

                    # Get OCSP configuration
                    $OcspConfig = $OcspAdmin.OCSPCAConfigurationCollection | Where-Object { $_.Identifier -eq $CACommonName }

                    # Set signing certificate
                    $OcspConfig.SigningCertificate = $SigningCertificate.RawData

                    # Commit Revocation Configuration
                    $OcspAdmin.SetConfiguration($ENV:ComputerName, $true)

                    ##########
                    # Cleanup
                    ##########

                    # Remove request file
                    Remove-Item -Path "$env:TEMP\$CACommonName OSCP Signing.req"

                    # Remove response file
                    Remove-Item -Path "$env:TEMP\$CACommonName OSCP Signing-Response.crt"
                }
                else
                {
                    if ($DomainName)
                    {
                        # Update group policy
                        Start-Process cmd -ArgumentList "/c gpupdate"
                    }

                    # Output requestfile
                    Write-Request -Path "$env:TEMP"
                }
            }
        }

        #  ███╗   ██╗██████╗ ███████╗███████╗
        #  ████╗  ██║██╔══██╗██╔════╝██╔════╝
        #  ██╔██╗ ██║██║  ██║█████╗  ███████╗
        #  ██║╚██╗██║██║  ██║██╔══╝  ╚════██║
        #  ██║ ╚████║██████╔╝███████╗███████║
        #  ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚══════╝

        if ($DeviceEnrollment.IsPresent)
        {
            # Check if windows feature is installed
            if ((Get-WindowsFeature -Name ADCS-Device-Enrollment).InstallState -notmatch 'Install' -and
                (ShouldProcess @WhatIfSplat -Message "Installing Device Enrollment windows feature." @VerboseSplat))
            {
                Install-WindowsFeature -Name ADCS-Device-Enrollment -IncludeManagementTools > $null
            }

            <#
            # Initialize
            $NdesConfigured = $false

            #Check if CA is configured
            try
            {
                # Throws if configured
                Install-AdcsNetworkDeviceEnrollmentService -WhatIf > $null
            }
            catch
            {
                # CA is configured
                $NdesConfigured = $true
            }

            # Service account permissions:
            # Allow log on locally
            # Log on as a service

            # Initialize
            $NdesParams =
            @{
                RAName = "$CACommonName NDES"
                RACountry = 'SE'
                CAConfig = $OCSPCAConfig
                ServiceAccountName = 'home\AzADDSConnector'
                ServiceAccountPassword = (ConvertTo-SecureString -String "PHptNlPKHxL0K355QsXIJulLDqjAhmfABbsWZoHqc0nnOd6p" -AsPlainText -Force)
            }

            try
            {
                if (-not $NdesConfigured -and
                    (ShouldProcess @WhatIfSplat -Message "Configuring Device Enrollment." @VerboseSplat))
                {
                    Install-AdcsNetworkDeviceEnrollmentService @NdesParams -Force > $null
                }
            }
            catch [Exception]
            {
                throw $_.Exception
            }
            #>
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
            . $PSScriptRoot\f_CheckContinue.ps1
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
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CheckContinue.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_GetBaseDN.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_WriteRequest.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Splat
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            $CACommonName = $Using:CACommonName

            $HostName = $Using:HostName
            $ShareName = $Using:ShareName
            $ShareAccess = $Using:ShareAccess

            $OCSPCAConfig = $Using:OCSPCAConfig
            $OCSPTemplate = $Using:OCSPTemplate

            $OCSPManualRequest = $Using:OCSPManualRequest

            $OCSPRefreshTimeout = $Using:OCSPRefreshTimeout
            $OCSPAddNounce = $Using:OCSPAddNounce
            $OCSPHashAlgorithm = $Using:OCSPHashAlgorithm

            $DeviceEnrollment = $Using:DeviceEnrollment

            # Files
            $CAFiles = $Using:CAFiles
            $CAResponseFile = $Using:CAResponseFile
        }

        # Run main
        $Result = Invoke-Command -Session $Session -ScriptBlock $MainScriptBlock
    }
    else # Locally
    {
        Check-Continue -Message "Invoke locally?"

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
# MIIUvwYJKoZIhvcNAQcCoIIUsDCCFKwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUFnrOhAFYY2PJ0UuMHTfNWT28
# rwKggg8yMIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU5wGWilNxcJvdNEupRLabKtTeTuMwDQYJ
# KoZIhvcNAQEBBQAEggIAaApudbnlmCqCaTdt7x8Vf30g266hpiBM+nLZycls2SpM
# 1hWBhdcB3eFSILV80LuQMRwgp+S0/cFJAzhxvbt31zSqqFSihTFb3efjLFEqOmsT
# iuUm/zQFVlA9Age2hn3U82AyRhRicpfcLHT00vGN1TV6fs5fCjdHYdVbY7ngSjjs
# LX9AKCmWAXyhfdIjvZvW6VPmnvqJLRF6wNd+7s39Nqv/T+b5dV18LbokE5Q/QqmE
# 2MjvWuGGWyniIGbauZM5WsWEPJQ4FxLMzAC5LWu8IPsV4LEdGbwGcdLt7s1fnOud
# W+WNU+QHVOIgPkppUaZyhi5Zi0q0E+8iofjGwcA0LWH1/EQPgZdcGW7ha6soffzT
# DV1eSvgh01f1+4DxKU69Pql42R9zUqHa+iXZH4MUdZ2nz9b7LdqWP6PVuUrzHe2C
# Pp/363TW7l6Sacee9bPrf2w/rBEzCJWM76q2myl0hJHSDCAmO/keHZR+v/HPCIKO
# BO/zGYnEI6SRy0wtqvsqTeGk5ic63t2JhCLpqaORJNrWEi3ghbOUCsieiG6Wp709
# ktwkBlR9+hjOa8NEorDyDaHVbxCkiDmuRC7sy3kmpGgZvm/Wt1jnu7Q0lbWDOpCd
# sGoIqNWE1I+6qxuL0jn1+nNZ4IrPLVhXzbYMTaM2vfNVBIDMWOEiFIILQstY+AGh
# ggIwMIICLAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGlu
# ZyBDQQIQDUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDMxODE3MDAwMlow
# LwYJKoZIhvcNAQkEMSIEIIDuWsY+AEJLPTQm3hHFXpEWITeeTP6fTYlTwlLIhT/I
# MA0GCSqGSIb3DQEBAQUABIIBAFwnJstJaEyogxhcw0JNlEKkYOH28JA1TzeLCfzU
# eVQEcQB/m3r+2ZMjaNkpFbzXwOoOZCceJ7SlzylIZ2TQKyiqeqDssicLhpT77Q4r
# NA8vdx3FzO5PUo3R7ohYAbs2b4jggC60GAEiLwOEOzM8ExFZbASJ6Z1cVr4Xnhiy
# PZ/LI3Tc3binzS1464peCkyYgtwpDD/FF5mC0TA11wUY+FB9zUhSBcaWjTHO2rBq
# oLcsJv6LatTzKQsHxGDg7jCwBa2B1Enjn6n1IktZzXJoQhMEl7QkdsgNU/eywE+J
# jo5xesLRL/y4p4XO1dHwn8vxRDpeesqDOOexw4G0EF5tdrw=
# SIG # End signature block
