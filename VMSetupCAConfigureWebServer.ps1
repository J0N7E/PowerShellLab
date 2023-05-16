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

    # Certificate Authority config
    [Parameter(ParameterSetName='Standard', Mandatory=$true)]
    [Parameter(ParameterSetName='Share', Mandatory=$true)]
    [Parameter(ParameterSetName='OCSPManual', Mandatory=$true)]
    [Parameter(ParameterSetName='OCSPTemplate', Mandatory=$true)]
    [String]$CAConfig,

    # Host name
    [String]$HostName,

    # Physical Path
    [String]$PhysicalPath,

    ######
    # IIS
    ######

    # Configure IIS
    [Switch]$ConfigureIIS,

    ########
    # Share
    ########

    # FIX
    # to array

    # Share access
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share', Mandatory=$true)]
    [Parameter(ParameterSetName='OCSPManual')]
    [Parameter(ParameterSetName='OCSPTemplate')]
    [String]$ShareAccess,

    #######
    # OCSP
    #######

    # Configure OCSP
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPManual', Mandatory=$true)]
    [Parameter(ParameterSetName='OCSPTemplate', Mandatory=$true)]
    [Switch]$ConfigureOCSP,

    # OCSP template name
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPTemplate', Mandatory=$true)]
    [String]$OCSPTemplate,

    ####################
    # OCSP Array Member
    ####################

    # FIX
    # add new parameterset OCSPArrayMember

    ########################
    # OCSP Common Paramters
    ########################

    # OCSP hash algorithm
    [ValidateSet('MD2', 'MD4', 'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
    [String]$OCSPHashAlgorithm,

    # OCSP nonuce switch
    [Switch]$OCSPAddNonce,

    # OCSP refresh timeout
    # Minutes
    [Int]$OCSPRefreshTimeout,

    #######
    # NDES
    #######

    # Configure Ndes
    [Switch]$ConfigureNDES
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
            . $PSScriptRoot\f_CheckContinue.ps1
            . $PSScriptRoot\f_ShouldProcess.ps1
            . $PSScriptRoot\f_CopyDifferentItem.ps1 #### Depends on Should-Process ####
        }
        catch [Exception]
        {
            throw $_
        }

    } -NoNewScope

    ###################
    # Check parameters
    ###################

    $CAConfig | Where-Object {
                    $_ -match "(.*?)\.(.*)\\(.*)"
    } | ForEach-Object {

        $CAConfigMatch = $Matches[0]
        $CAHostName = $Matches[1]
        $CACommonName = $Matches[3]
        $DomainName = $Matches[2]
    }

    if ($CAConfig -ne $CAConfigMatch)
    {
        throw "Invalid CAConfig `"$CAConfig`""
    }

    if (-not $HostName)
    {
        Check-Continue -Message "-HostName parameter not specified, using `"pki.$DomainName`" as HostName."

        $HostName = "pki.$DomainName"
    }

    if (-not $PhysicalPath)
    {
        Check-Continue -Message "-PhysicalPath parameter not specified, using `"C:\inetpub\wwwroot`" as PhysicalPath."

        $PhysicalPath = 'C:\inetpub\wwwroot'
    }

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
            $file.Extension -ne '.csr' -and
            $file.Extension -ne '.p12')
        {
            # Get file content
            $CAFiles.Add($file, (Get-Content -Path $file.FullName -Raw))
        }
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
        ##############
        # Check admin
        ##############

        if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {
            throw "Must be administrator to setup Webserver."
        }

        # ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗
        # ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║
        # ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║
        # ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║
        # ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
        # ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

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
        if (-not (Get-PSDrive -Name IIS -ErrorAction SilentlyContinue))
        {
            Import-Module -Name WebAdministration -Force
        }

        # Check if RSAT-ADCS-Mgmt is installed
        if (((Get-WindowsFeature -Name RSAT-ADCS-Mgmt).InstallState -notmatch 'Install') -and
            (ShouldProcess @WhatIfSplat -Message "Installing RSAT-ADCS-Mgmt feature." @VerboseSplat))
        {
            Install-WindowsFeature -Name RSAT-ADCS-Mgmt > $null
        }

        #  ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗ ██╗   ██╗██████╗ ███████╗
        # ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ ██║   ██║██╔══██╗██╔════╝
        # ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗██║   ██║██████╔╝█████╗
        # ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║██║   ██║██╔══██╗██╔══╝
        # ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝╚██████╔╝██║  ██║███████╗
        #  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝

        if ($ConfigureIIS)
        {
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

            <#
             # FIX
             # check if delta, then aply
             # copy set properties from NDES below
             #>

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

            ##################
            # Cleanup wwwroot
            ##################

            if ($PhysicalPath -eq 'C:\inetpub\wwwroot')
            {
                # Files to be removed
                $RemoveFiles = @('iisstart.htm', 'iisstart.png')

                # Remove files
                foreach ($File in $RemoveFiles)
                {
                    if ((Test-Path -Path "$PhysicalPath\$File") -and
                        (ShouldProcess @WhatIfSplat -Message "Remove $File." @VerboseSplat))
                    {
                        Remove-Item -Path "$PhysicalPath\$File" -Force
                    }
                }

                # Hide other files
                foreach ($File in (Get-ChildItem -Path $PhysicalPath -Exclude '*.crt', '*.crl'))
                {
                    if (-not ($File.Attributes -contains 'Hidden') -and
                        (ShouldProcess @WhatIfSplat -Message "Setting hidden on `"$($File.Name)`"." @VerboseSplat))
                    {
                        $File.Attributes += 'Hidden'
                    }
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
        }

        # ███████╗██╗  ██╗ █████╗ ██████╗ ███████╗
        # ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝
        # ███████╗███████║███████║██████╔╝█████╗
        # ╚════██║██╔══██║██╔══██║██╔══██╗██╔══╝
        # ███████║██║  ██║██║  ██║██║  ██║███████╗
        # ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

        if ($ShareAccess)
        {
            $ShareName = "$(Split-Path -Path $PhysicalPath -Leaf)$"

            if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Creating share `"$ShareName`"" @VerboseSplat))
            {
                # Add new share
                New-SmbShare -Name $ShareName -Path $PhysicalPath -ReadAccess "Authenticated Users" > $null
            }

            if (-not (Get-SmbShareAccess -Name $ShareName | Where-Object { $_.AccountName -like "*$ShareAccess*" -and $_.AccessRight -eq 'Change'}) -and
                (ShouldProcess @WhatIfSplat -Message "Setting share `"$ShareName`" change access for `"$ShareAccess`"." @VerboseSplat))
            {
                # Grant change access
                Grant-SmbShareAccess -Name $ShareName -AccountName $ShareAccess -AccessRight Change -Force > $null
            }

            # Get NTFS acl
            $Acl = Get-Acl -Path $PhysicalPath

            if (-not ($Acl.Access | Where-Object { $_.FileSystemRights -eq 'Modify, Synchronize' -and $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -like "*$ShareAccess*" -and $_.InheritanceFlags -eq 'ContainerInherit, ObjectInherit' -and $_.PropagationFlags -eq 'None' }) -and
                (ShouldProcess @WhatIfSplat -Message "Setting share `"$ShareName`" NTFS modify rights for `"$ShareAccess`"." @VerboseSplat))
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
                Set-Acl -AclObject $Acl -Path $PhysicalPath
            }
        }

        # ███████╗██╗██╗     ███████╗███████╗
        # ██╔════╝██║██║     ██╔════╝██╔════╝
        # █████╗  ██║██║     █████╗  ███████╗
        # ██╔══╝  ██║██║     ██╔══╝  ╚════██║
        # ██║     ██║███████╗███████╗███████║
        # ╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝

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
            Copy-DifferentItem -SourcePath $FullName -TargetPath "$PhysicalPath\$($file.Key.Name)" @VerboseSplat

            # Add certificates to root and ca stores
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

        foreach($Ext in ('crt', 'crl'))
        {
            if (-not (Test-Path -Path "$PhysicalPath\$CACommonName.$Ext"))
            {
                Write-Warning -Message "File missing `"$PhysicalPath\$CACommonName.$Ext`""
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

        if ($ConfigureOCSP.IsPresent)
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

            if ($OCSPAddNonce.IsPresent)
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
                $OcspConfig = $OcspAdmin.OCSPCAConfigurationCollection.CreateCAConfiguration($CACommonName, ([System.Security.Cryptography.X509Certificates.X509Certificate2] "$PhysicalPath\$CACommonName.crt").RawData)
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
            foreach($file in Get-Item -Path "$PhysicalPath\$CACommonName*.crl")
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
                if ($OCSPRefreshTimeout -lt 5)
                {
                    $OCSPRefreshTimeout = 5
                }

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

            ################
            # OCSP Template
            ################

            if ($OCSPTemplate)
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

                if ($OcspConfig.CAConfig -ne $CAConfig -and
                   (ShouldProcess @WhatIfSplat -Message "Setting CAConfig `"$CAConfig`"" @VerboseSplat))
                {
                    $OcspConfig.CAConfig = $CAConfig
                }

                if ($OcspConfig.SigningCertificateTemplate -ne $OCSPTemplate -and
                   (ShouldProcess @WhatIfSplat -Message "Setting SigningCertificateTemplate `"$OCSPTemplate`"" @VerboseSplat))
                {
                    $OcspConfig.SigningCertificateTemplate = $OCSPTemplate
                }
            }

            ######################
            # OCSP Manual Request
            ######################

            else
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
                    (
                        "[NewRequest]",
                        "Subject = `"CN=$CACommonName OCSP Signing`"",
                        "MachineKeySet = True",
                        "ProviderName = `"Microsoft Enhanced Cryptographic Provider v1.0`"",
                        "KeyLength = 2048",
                        "",
                        "[EnhancedKeyUsageExtension]",
                        "OID=`"1.3.6.1.5.5.7.3.9`""
                    )

                    # Save inf file
                    Set-Content -Path "$env:TEMP\$CACommonName OSCP Signing.inf" -Value $RequestInf

                    # New certificate request
                    TryCatch { certreq -f -q -new "$env:TEMP\$CACommonName OSCP Signing.inf" "$env:TEMP\$CACommonName OSCP Signing.csr" } > $null

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

            # Check directory browsing
            if ((Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\ocsp" -Filter /system.webServer/directoryBrowse -Name enabled).Value -eq $true -and
                (ShouldProcess @WhatIfSplat -Message "Disabling OCSP directory browsing." @VerboseSplat))
            {
                # Disable directory browsing
                Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\ocsp" -Filter /system.webServer/directoryBrowse -Name enabled -Value $false
            }

            #########
            # Accept
            #########

            # Check if OCSP signing certificate request exist
            if (Test-Path -Path "$env:TEMP\$CACommonName OSCP Signing.csr")
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

                    foreach ($Cert in (Get-Item -Path Cert:\LocalMachine\My\* | Where-Object {
                        $_.Subject -match "$CACommonName OCSP Signing" -and
                        $_.Extensions['2.5.29.37'] -and
                        $_.Extensions['2.5.29.37'].EnhancedKeyUsages.FriendlyName.Contains('OCSP Signing')
                    }))
                    {
                        $KeyContainerPath = (Get-ChildItem -Path C:\ProgramData\Microsoft\Crypto -Filter (
                            (certutil -store my $($Cert.Thumbprint)) | Where-Object {
                                $_ -match "([a-z0-9]{32}_[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})"
                            } | ForEach-Object { "$($Matches[1])" }) -Recurse
                        ).FullName

                        if (Test-Path -Path $KeyContainerPath)
                        {
                            # Get NTFS acl
                            $Acl = Get-Acl -Path $KeyContainerPath

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

                            # Add network service read
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
                            Set-Acl -AclObject $Acl -Path $KeyContainerPath
                        }
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
                    Remove-Item -Path "$env:TEMP\$CACommonName OSCP Signing.csr"

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
                    # Write-Output
                    Write-Request -FilePath "$env:TEMP\$CACommonName OSCP Signing.csr"
                }
            }
        }

        #  ███╗   ██╗██████╗ ███████╗███████╗
        #  ████╗  ██║██╔══██╗██╔════╝██╔════╝
        #  ██╔██╗ ██║██║  ██║█████╗  ███████╗
        #  ██║╚██╗██║██║  ██║██╔══╝  ╚════██║
        #  ██║ ╚████║██████╔╝███████╗███████║
        #  ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚══════╝

        if ($ConfigureNDES.IsPresent)
        {
            # Check if windows feature is installed
            if ((Get-WindowsFeature -Name ADCS-Device-Enrollment).InstallState -notmatch 'Install' -and
                (ShouldProcess @WhatIfSplat -Message "Installing ADCS-Device-Enrollment windows feature." @VerboseSplat))
            {
                Install-WindowsFeature -Name ADCS-Device-Enrollment -IncludeManagementTools > $null
            }

            # Check if windows feature is installed
            if ((Get-WindowsFeature -Name RSAT-AD-PowerShell).InstallState -notmatch 'Install' -and
                (ShouldProcess @WhatIfSplat -Message "Installing RSAT-AD-PowerShell windows feature." @VerboseSplat))
            {
                Install-WindowsFeature -Name RSAT-AD-PowerShell > $null
            }

            # Test service account
            # FIX add parameter for accountname

            if (-not (Test-ADServiceAccount -Identity MsaNdes) -and
                (ShouldProcess @WhatIfSplat -Message "Installing service account." @VerboseSplat))
            {
                Install-ADServiceAccount -Identity MsaNdes
            }

            # Add service account to iis_iusrs
            # FIX add parameter for accountname

            if (-not (Get-LocalGroupMember -Group iis_iusrs -Member home\MsaNdes$ -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Adding service account to iis_iusrs." @VerboseSplat))
            {
                Add-LocalGroupMember -Group iis_iusrs -Member home\MsaNdes$
            }

            # Add CertSrv application
            if (-not ( Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertSrv') -and
                (ShouldProcess @WhatIfSplat -Message "Adding CertSrv virtual directory." @VerboseSplat))
            {
                New-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertSrv' -PhysicalPath 'C:\Windows\System32\certsrv' > $null
            }

            #####################
            # Set IIS properties
            #####################

            $WebServerProperties =
            @(
                @{ DisplayName = 'Disable directory brosing on CertSrv';           Name = 'enabled';         Value = $false;  Path = 'IIS:\Sites\Default Web Site\CertSrv';  Filter = '/system.webServer/directoryBrowse' },
                @{ DisplayName = 'Set maxUrl=65536 on Default Web Site.';          Name = 'maxUrl';          Value = 65536;   Path = 'IIS:\Sites\Default Web Site';          Filter = '/system.webServer/security/requestFiltering/requestLimits' },
                @{ DisplayName = 'Set maxQueryString=65536 on Default Web Site.';  Name = 'maxQueryString';  Value = 65536;   Path = 'IIS:\Sites\Default Web Site';          Filter = '/system.webServer/security/requestFiltering/requestLimits' }
            )

            foreach ($Prop in $WebServerProperties)
            {
                # Check properties
                if ((Get-WebConfigurationProperty -PSPath $Prop.Path -Filter $Prop.Filter -Name $Prop.Name).Value -ne $Prop.Value -and
                    (ShouldProcess @WhatIfSplat -Message $Prop.DisplayName @VerboseSplat))
                {
                    Set-WebConfigurationProperty -PSPath $Prop.Path -Filter $Prop.Filter -Name $Prop.Name -Value $Prop.Value
                }
            }

            # Configure Ndes
            if (-not (Get-Item IIS:\AppPools\SCEP -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Configuring NDES." @VerboseSplat))
            {
                # Initialize
                $NdesParams =
                @{
                    ApplicationPoolIdentity = $true
                    CAConfig = $CAConfig
                    RAName = "$CACommonName MSCEP RA"
                    RACountry = 'SE'
                    SigningProviderName = 'Microsoft Strong Cryptographic Provider'
                    SigningKeyLength = 2048
                    EncryptionProviderName = 'Microsoft Strong Cryptographic Provider'
                    EncryptionKeyLength = 2048
                }

                try
                {
                    Install-AdcsNetworkDeviceEnrollmentService @NdesParams -Force > $null
                }
                catch [Exception]
                {
                    throw $_.Exception
                }
            }


            <#
            # Set application pool identity
            # FIX add parameter for accountname

            if ((Get-ItemProperty IIS:\AppPools\SCEP -name processModel).identityType -eq 'ApplicationPoolIdentity' -and
                (ShouldProcess @WhatIfSplat -Message "Setting service account as application pool identity." @VerboseSplat))
            {
                Set-ItemProperty IIS:\AppPools\SCEP -name processModel -value @{ userName="home\MsaNdes$"; identityType=3; }
            }
            #>

            #############################
            # Set privat key permissions
            #############################

            foreach ($Cert in (Get-Item -Path Cert:\LocalMachine\My\* | Where-Object {
                $_.Subject -match "$CACommonName MSCEP RA" -and
                $_.Extensions['2.5.29.37'] -and
                $_.Extensions['2.5.29.37'].EnhancedKeyUsages.FriendlyName.Contains('Certificate Request Agent')
            }))
            {
                $KeyContainerPath = (Get-ChildItem -Path C:\ProgramData\Microsoft\Crypto -Filter (
                    (certutil -store my $($Cert.Thumbprint)) | Where-Object {
                        $_ -match "([a-z0-9]{32}_[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})"
                    } | ForEach-Object { "$($Matches[1])" }) -Recurse
                ).FullName

                if (Test-Path -Path $KeyContainerPath)
                {
                    # Get NTFS acl
                    $Acl = Get-Acl -Path $KeyContainerPath

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

                    # Add service account read
                    # FIX add parameter for accountname
                    $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList `
                    @(
                        #<#IdentityReference#> [System.Security.Principal.NTAccount] "IIS APPPOOL\SCEP",
                        <#IdentityReference#> [System.Security.Principal.NTAccount] "home\MsaNdes$",
                        [System.Security.AccessControl.FileSystemRights] "Read",
                        [System.Security.AccessControl.InheritanceFlags] "None"
                        [System.Security.AccessControl.PropagationFlags] "None",
                        [System.Security.AccessControl.AccessControlType] "Allow"
                    )
                    $Acl.AddAccessRule($Ace)

                    # FIX add parameter for accountname
                    Write-Verbose @VerboseSplat -Message "Setting Read for `"home\MsaNdes$`" on key container `"$($Matches[1])`""

                    # Set NTFS acl
                    Set-Acl -AclObject $Acl -Path $KeyContainerPath
                }
            }

            ########################
            # Set registry settings
            ########################

            <#
            $NdesRegistrySettings =
            @(
                @{ Name = 'SignatureTemplate';       Value = 'HomeNDES';  PropertyType = 'String';  Path = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP' },
                @{ Name = 'EncryptionTemplate';      Value = 'HomeNDES';  PropertyType = 'String';  Path = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP' },
                @{ Name = 'GeneralPurposeTemplate';  Value = 'HomeNDES';  PropertyType = 'String';  Path = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP' },
                @{ Name = 'PasswordMax';             Value = '500';       PropertyType = 'Dword';   Path = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP\PasswordMax' },
                @{ Name = 'PasswordLength';          Value = '20';        PropertyType = 'Dword';   Path = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\MSCEP\PasswordLength' }
            )

            Set-Registry -Settings $NdesRegistrySettings
            #>

            # Remove default certificates
            # Enroll new certificates from custom templates
            # Export user certificate pfx and remove it
            # Import user certificate to local machine and remove pfx

            # Enroll TLS certificate
            # Force SSL on MSCEP_admin

            # Service account permissions:
            # Allow log on locally
            # Log on as a service

            # Move ISAPA 4.0 64bit Handler mapping down

            # useKernelMode false
            # useAppPoolCredentials true
            # authPersisSingleRequest true
            # extendedProtection tokenChecking Require
            # Remove providers, add Negotiate:Kerberos

            # setspn -s HTTP/hostname A-RECORD
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
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_WriteRequest.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetRegistry.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Splat
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            $CAConfig = $Using:CAConfig
            $CAHostName = $Using:CAHostName
            $CACommonName = $Using:CACommonName
            $DomainName = $Using:DomainName
            $HostName = $Using:HostName
            $PhysicalPath = $Using:PhysicalPath

            # IIS
            $ConfigureIIS = $Using:ConfigureIIS

            # Ndes
            $ConfigureNDES = $Using:ConfigureNDES

            # Share
            $ShareAccess = $Using:ShareAccess

            # OCSP
            $ConfigureOCSP = $Using:ConfigureOCSP
            $OCSPTemplate = $Using:OCSPTemplate
            $OCSPRefreshTimeout = $Using:OCSPRefreshTimeout
            $OCSPAddNonce = $Using:OCSPAddNonce
            $OCSPHashAlgorithm = $Using:OCSPHashAlgorithm

            # Files
            $CAFiles = $Using:CAFiles
            $CAResponseFile = $Using:CAResponseFile
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
                # f_CopyDifferentItem.ps1 loaded in Begin
                . $PSScriptRoot\f_TryCatch.ps1
                . $PSScriptRoot\f_WriteRequest.ps1
                . $PSScriptRoot\f_SetRegistry.ps1
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
}

# SIG # Begin signature block
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvYXd8d5Gs2cq5HK5Nlf/1BRC
# +12gghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUi0aLz6Kn
# x3XHhfHJByV3PMb0nM4wDQYJKoZIhvcNAQEBBQAEggIAfYH/g85IA1D1hW/br9H7
# iy2vAUXIyD92Gp9NTeCA8MM0Rh/YgxJgkQtkCRDxEzqgIsF5QOsXlXaSqGHlWmhM
# Unlg5LHvosOXIDeImzI8ieI7rdQcrdH4K3asa59zEVEAOsB90qx0ZRROwa+Jb7Zz
# HLRlXhEaL2EI5NcGe6w4dnuLkH0drlQaLP2W4eMLgu0u/UE5edLCEZfFzpINZAqB
# hrFEMeGtRZPU60IE0Z6T7H8LbQqO3cDMCQzWpP3RkjPNqKBZ0DDKkeVTGYm5zV9O
# UHrY1R3dK8fwU2ZteB3tK+doJ+cJpSOiA2NvIdsH5R0CKLKGQL+xtUSqsuBy8xXp
# iwbk1pRP0PDrgoD1D6RIXvPT97Gdp7lk7vmzqlMmQ5TpZJjrKd9Ct13cpFSMETXi
# irJ0zmg3cIX+685e4DSd9A1E81iaxMbDSRvC+WV5bYDYR+d/TYq2M+oZqQRe9t4N
# ejtH/eCO7/rHtWHU95vsx7dAYgeiXPhGlUdSj5+Yx+s+IYrEap2V8ENhrFzZC52Q
# onclmkuZkk2FQO12HT2pwMdoQ7uhZ0LsVoCk/fnkslJ7yfSY0sBWWqIU1lnzY7E4
# jnrHjDG1MttYAPbdD+XVLPx1xeNGVl5S1XrHkpqPsbtDbUj66JKuHVCMIHQt3iy7
# DjtRUifVeR3sqEOSdl5WVPuhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwNTE2MDgwMDAy
# WjAvBgkqhkiG9w0BCQQxIgQgzCRHuvZK7rzUtR5cdXo9D8vXQLx3JSu8MURjJqxK
# 024wDQYJKoZIhvcNAQEBBQAEggIALAJz5p4R3tNtv4TJK6mg9FwrjhtZdDxe6h2r
# mnsnRCmQR+wuAdYAZ//+MlTovlOrZQ0VpN84nmJr52qmSUC2chF72bu5THV+btGa
# B/es100VCeLE4UJq9ShQKC7OcQWUJ2rLCMBnWeEWTC+sYVzysAe/lM8kYiyVWEfL
# yabMxH8UTKTJNqnGcurNFSRfns+iv9RSRFWxZxnNKWquaWfJ8jd4oCQ9MLUQ0kg+
# lG6lSVgg1ZfqFa3ThsUD7MqhXSz1ReE9L0ahAU/9N5SoAY5aDkdXjZb1vRa/ZTi+
# yZqzlH5Lw1UAjhYAUT16BpPhTKvW9Fin5n4MqTDqKsSvmNsKTnuc0yxPTJ3NBdip
# P7EqiodmDFD+lG7tVotADbLlr6HAUpVZ+EvTLz4F4TFoVCm+OgakEgBl08ab6+eE
# js2datsQJl8qsYeyLW3XN/0jA+cFRuimq8xb445XtXno6e4DMFK3fXQwwTH1YUHH
# KakQvd0nnjrfkuMiHkqSOFaWLojrezsGgmAqxqHRWewsS568Ly79EKCRuRGKlaj6
# zl6x4v21tFm/LqHQ0I0m4Mk5mkftHUyex/Lw47QBQYTgZFcm6xjLoOZhVnDTZ1NX
# FF+3AW88yWyul8r6uJMzRNo9KKW2h0ZtJtHeF68NAXEh57ortalQ/po4ce6z/mZy
# v3setts=
# SIG # End signature block
