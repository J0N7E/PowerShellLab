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
    [Parameter(ParameterSetName='NDES', Mandatory=$true)]
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
    [Parameter(ParameterSetName='NDES')]
    [String]$ShareAccess,

    #######
    # OCSP
    #######

    # Configure OCSP
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPManual', Mandatory=$true)]
    [Parameter(ParameterSetName='OCSPTemplate', Mandatory=$true)]
    [Parameter(ParameterSetName='NDES')]
    [Switch]$ConfigureOCSP,

    # OCSP template name
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPTemplate', Mandatory=$true)]
    [Parameter(ParameterSetName='NDES')]
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
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPManual')]
    [Parameter(ParameterSetName='OCSPTemplate')]
    [Parameter(ParameterSetName='NDES', Mandatory=$true)]
    [Switch]$ConfigureNDES,

    [String]$NdesServiceAccountName = "MsaNdes$"

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
            'Web-CGI'
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

        #  ██████╗███████╗██████╗ ████████╗███████╗██████╗ ██╗   ██╗
        # ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██║   ██║
        # ██║     █████╗  ██████╔╝   ██║   ███████╗██████╔╝██║   ██║
        # ██║     ██╔══╝  ██╔══██╗   ██║   ╚════██║██╔══██╗╚██╗ ██╔╝
        # ╚██████╗███████╗██║  ██║   ██║   ███████║██║  ██║ ╚████╔╝
        #  ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝  ╚═══╝

        # Install-WindowsFeature -Name ADCS-Web-Enrollment

        # v2 template
        # CSP
        # IE: Trusted zone

        # IE: Initialize and script ActiveX controls not marked as safe for scripting
        # https://www.sysadmins.lv/retired-msft-blogs/alejacma/how-to-disable-this-web-site-is-attempting-to-perform-a-digital-certificate-operation-on-your-behalf-message.aspx

        # Add msa to "Certificate Service DCOM Access" group

        #  ███╗   ██╗██████╗ ███████╗███████╗
        #  ████╗  ██║██╔══██╗██╔════╝██╔════╝
        #  ██╔██╗ ██║██║  ██║█████╗  ███████╗
        #  ██║╚██╗██║██║  ██║██╔══╝  ╚════██║
        #  ██║ ╚████║██████╔╝███████╗███████║
        #  ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚══════╝

        if ($ConfigureNDES.IsPresent)
        {
            ################
            # Prerequisites
            ################

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
            if (-not (Test-ADServiceAccount -Identity $NdesServiceAccountName) -and
                (ShouldProcess @WhatIfSplat -Message "Service account $NdesServiceAccountName not installed, aborting..." @VerboseSplat))
            {
                #Install-ADServiceAccount -Identity $NdesServiceAccountName
                return
            }

            # Add service account to iis_iusrs
            if (-not (Get-LocalGroupMember -Group iis_iusrs -Member "$env:USERDOMAIN\$NdesServiceAccountName" -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Adding service account $env:USERDOMAIN\$NdesServiceAccountName to iis_iusrs." @VerboseSplat))
            {
                Add-LocalGroupMember -Group iis_iusrs -Member "$env:USERDOMAIN\$NdesServiceAccountName"
            }

            ################
            # Configure IIS
            ################

            # Add CertSrv application
            if (-not (Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertSrv') -and
                (ShouldProcess @WhatIfSplat -Message "Adding CertSrv virtual directory." @VerboseSplat))
            {
                New-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertSrv' -PhysicalPath 'C:\Windows\System32\certsrv' > $null
            }

            $WebServerProperties =
            @(
                @{ DisplayName = 'Disable directory browsing on CertSrv';          Name = 'enabled';         Value = $false;  Path = 'IIS:\Sites\Default Web Site\CertSrv';  Filter = '/system.webServer/directoryBrowse' },
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

            #######
            # NDES
            #######

            # Configure Ndes
            <#
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
            #>


            # Set application pool identity
            if ((Get-ItemProperty IIS:\AppPools\SCEP -name processModel).identityType -eq 'ApplicationPoolIdentity' -and
                (ShouldProcess @WhatIfSplat -Message "Setting service account as application pool identity." @VerboseSplat))
            {
                Set-ItemProperty IIS:\AppPools\SCEP -name processModel -value @{ userName="home\MsaNdes$"; identityType=3; }
            }

            # Remove default certificates
            # Enroll new certificates from custom templates
            # Export user certificate pfx and remove it
            # Import user certificate to local machine and remove pfx

            return

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



            # Enroll TLS certificate
            # Force SSL on MSCEP_admin


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

            # Share
            $ShareAccess = $Using:ShareAccess

            # OCSP
            $ConfigureOCSP = $Using:ConfigureOCSP
            $OCSPTemplate = $Using:OCSPTemplate
            $OCSPRefreshTimeout = $Using:OCSPRefreshTimeout
            $OCSPAddNonce = $Using:OCSPAddNonce
            $OCSPHashAlgorithm = $Using:OCSPHashAlgorithm

            # NDES
            $ConfigureNDES = $Using:ConfigureNDES
            $NdesServiceAccountName = $Using:NdesServiceAccountName

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
        throw "$_ $($_.ScriptStackTrace)"
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
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7T29AOjaaieQ+DYAv4KjD7ty
# NDygghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSNziOU
# SWsaHUs7BH7uHmQeq+nFZjANBgkqhkiG9w0BAQEFAASCAgDGc7bbGHq2UYUi/6fV
# yvHIVy/kpUxLJuTHEqZ1Nrtpp4tgjHDjMfFCa1rM0nJ5Y+lUJg58IuY3oj5B8tZC
# /LcE+KfACxsC0vSuDpg32voDsZtskHAqIUnFLOxScwJa4/NxsZcV653Cf4WbJmqc
# 0DscMyAZ15p3r9qvy90GsBLaBFdsIRpHpgYnXqFTO6z2BdpUm9H0+yLhZDOUe94B
# xbjVxqJS3PjtWg9X8piBnaA1X9FvsNliD7eCqq+jAQ9Nk1q5JXcC3116rPHjD4rX
# oCgRqLnsOL2vRsqQiO/vbPOLlFeNq8fjjSDMM/P0Y5+A0QCIXukjfX7DjypUl4y7
# 94Xq0IoR9bp7CHQed772X8Y5RZafHD2Wyc5FARpPd0/d5CV94yiftiC66wDEwH6Z
# sSZrX0QyKdfm45up4KvQVq06/3zYDa/e1IsPp0lZW5+zEs76r6Ftm6S9J91apmGW
# px7Z1kA4vLkazZqABkCGy6WY/HO/2tEVzeeAVY78O/sVn+ey8GnlOUgMooTRalrB
# me/B+TDrsz/iG4DyZHRDLbM06gaUHSS5BYt7FYWBf1ebhL5xDx69c4R5Wz1jzAv5
# aIcqf2aAnc+l77k8tGVf6VgLuYA5tAaH6DQON8p4GVsAwEQyYwpd3tpsPV44DNfM
# meuWIkkvrVzt4ClFLPKdOswO2aGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNDAzMDYxNTAw
# MDVaMC8GCSqGSIb3DQEJBDEiBCCsRpPBCu9LxVdQ0oSHEe73Aoe6w3wSt+oHnidD
# LnbrvzANBgkqhkiG9w0BAQEFAASCAgAgUx7TylxaB4rpbIpm1qHr+vKOYgZfwscx
# 8EneVtmVaGkofXwf5M3sEdAMk070K0yvFPZN28z26/D5J/xVe1+cRPW+3yA0+MFN
# IxrB4dP6Nz4ybj3E4WCb4D1PVf3NW5m57Qtz0LhMBiEYupcESPblVht6yXQ/JFWd
# HucenhGiCyyrsi+qNgsix/55sxtx/pBE2thp41/wYan9obafYkinpKJ70v2I6wXw
# WxGhGANbW6KBydymQyBiuPQ9lRsbiHl38xIleP6F3cmmKbSAflCPXGIJdPHOO3N2
# dFft3XJrLmUdG5LCxrbBiIXGsLDISiqSlN5TQ6aKmHS6KyrZra4uX53fdx4ewyzk
# fLua98CFbdH7HpyhCuNQXAd3k5phrp+Gf8/yXwozW+eSpKbhAoJd8UUixJ7GKHrZ
# eltXXgUNpH5Rl4J8bgZJVbDqSuBOH80cUWnARDnZ3U1rTkJC8ggcBrL4OIDc7iEw
# xYkClKvy0yzMIyPvRPkNHEH9OdRy0Fw3ABQfQq8+HMNkBauAqOOD5dS22vjtNQk5
# +/fME5JsmA3rwXz0WzWuEL4WpyJ5Z3ccnxJ71Q+HTGNcMYwRYjZ+TsY/GVjEJiza
# nipWA9AUushW+4z8ZO6VIe/z+lOL9gV+q8ijK5k7V0/TaebUOG9a4SjKrDwh6H2h
# 5SfzEtGDlQ==
# SIG # End signature block
