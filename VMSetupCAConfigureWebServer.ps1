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
    [Parameter(ParameterSetName='OCSPAuto', Mandatory=$true)]
    [Parameter(ParameterSetName='OCSPManual', Mandatory=$true)]
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
    [Parameter(ParameterSetName='OCSPTemplate')]
    [Parameter(ParameterSetName='OCSPManual')]
    [String]$ShareAccess,

    #######
    # Ndes
    #######

    # Configure Ndes
    [Switch]$ConfigureNDES,

    #####################
    # OCSP Enterprise CA
    #####################

    # OCSP template name
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPTemplate', Mandatory=$true)]
    [String]$OCSPTemplate,

    #####################
    # OCSP Standalone CA
    #####################

    # OCSP request signing certificate
    [Parameter(ParameterSetName='Standard')]
    [Parameter(ParameterSetName='Share')]
    [Parameter(ParameterSetName='OCSPManual', Mandatory=$true)]
    [Switch]$OCSPManualRequest,

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
            . $PSScriptRoot\f_CheckContinue.ps1
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
    foreach($file in (Get-Item -Path "$PSScriptRoot\$CACommonName.*"))
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
        try
        {
            Get-PSDrive -Name IIS -ErrorAction Stop > $null
        }
        catch
        {
            Import-Module WebAdministration
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

            # Check double escaping
            if ((Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter /system.webServer/Security/requestFiltering -Name allowDoubleEscaping).Value -eq $false -and
                (ShouldProcess @WhatIfSplat -Message "Enabling double escaping." @VerboseSplat))
            {
                Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter /system.webServer/Security/requestFiltering -Name allowDoubleEscaping -Value $true
            }
            #>

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

        #  ███╗   ██╗██████╗ ███████╗███████╗
        #  ████╗  ██║██╔══██╗██╔════╝██╔════╝
        #  ██╔██╗ ██║██║  ██║█████╗  ███████╗
        #  ██║╚██╗██║██║  ██║██╔══╝  ╚════██║
        #  ██║ ╚████║██████╔╝███████╗███████║
        #  ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚══════╝

        if ($ConfigureNDES.IsPresent)
        {
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

            # Check if windows feature is installed
            if ((Get-WindowsFeature -Name ADCS-Device-Enrollment).InstallState -notmatch 'Install' -and
                (ShouldProcess @WhatIfSplat -Message "Installing ADCS-Device-Enrollment windows feature." @VerboseSplat))
            {
                Install-WindowsFeature -Name ADCS-Device-Enrollment -IncludeManagementTools > $null
            }

            # Add CertSrv application
            if (-not ( Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertSrv') -and
                (ShouldProcess @WhatIfSplat -Message "Adding CertSrv virtual directory." @VerboseSplat))
            {
                New-WebVirtualDirectory -Site 'Default Web Site' -Name 'CertSrv' -PhysicalPath 'C:\Windows\System32\certsrv'> $null
            }

            # Check directory browsing
            if ((Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter /system.webServer/directoryBrowse -Name enabled).Value -eq $true -and
                (ShouldProcess @WhatIfSplat -Message "Disabling NDES directory browsing." @VerboseSplat))
            {
                # Disable directory browsing
                Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter /system.webServer/directoryBrowse -Name enabled -Value $false
            }

            # Configure Ndes
            # FIX
            # RPC server unavailable when using remote

            if (-not (Get-Item -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP -ErrorAction SilentlyContinue) -and
                (ShouldProcess @WhatIfSplat -Message "Configuring NDES." @VerboseSplat))
            {
                # Initialize
                $NdesParams =
                @{
                    ApplicationPoolIdentity = $true
                    CAConfig = $CAConfig
                    RAName = "$CACommonName NDES"
                    RACountry = 'SE'
                    RACompany = $DomainName
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

            # Set application pool identity
            # FIX add parameter for accountname

            if ((Get-ItemProperty IIS:\AppPools\SCEP -name processModel).identityType -eq 'ApplicationPoolIdentity' -and
                (ShouldProcess @WhatIfSplat -Message "Setting service account as application pool identity." @VerboseSplat))
            {
                Set-ItemProperty IIS:\AppPools\SCEP -name processModel -value @{ userName="home\MsaNdes$"; identityType=3; }
            }

            #############################
            # Set privat key permissions
            #############################

            foreach ($Cert in (Get-Item -Path Cert:\LocalMachine\My\* | Where-Object {
                $_.Subject -match "$CACommonName NDES" -and
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

                    # Add OCSP service read
                    $Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList `
                    @(
                        <#IdentityReference#> [System.Security.Principal.NTAccount] "IIS APPPOOL\SCEP",
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

            # Remove default certificates
            # Enroll new certificates from custom templates
            # Export user certificate pfx and remove it
            # Import user certificate to local machine

            # Enroll TLS certificate
            # Force SSL on MSCEP_admin

            # Set registry values



            # Move ISAPA 4.0 64bit Handler mapping down

            # useKernelMode false
            # useAppPoolCredentials true
            # authPersisSingleRequest true
            # extendedProtection tokenChecking Require
            # Remove providers, add Negotiate:Kerberos
            # setspn -s HTTP/hostname A-RECORD

            # Service account permissions:
            # Allow log on locally
            # Log on as a service
        }

        #  ██████╗  ██████╗███████╗██████╗
        # ██╔═══██╗██╔════╝██╔════╝██╔══██╗
        # ██║   ██║██║     ███████╗██████╔╝
        # ██║   ██║██║     ╚════██║██╔═══╝
        # ╚██████╔╝╚██████╗███████║██║
        #  ╚═════╝  ╚═════╝╚══════╝╚═╝

        if ($OCSPManualRequest.IsPresent -or $OCSPTemplate)
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
                    Write-Request -FilePath "$env:TEMP\$CACommonName OSCP Signing.csr"
                }
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
            # f_CheckContinue.ps1 loaded in Begin
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
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_WriteRequest.ps1

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
            $OCSPTemplate = $Using:OCSPTemplate
            $OCSPManualRequest = $Using:OCSPManualRequest
            $OCSPRefreshTimeout = $Using:OCSPRefreshTimeout
            $OCSPAddNonce = $Using:OCSPAddNonce
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
        Check-Continue -Message "Invoke locally?"

        # Load functions
        Invoke-Command -ScriptBlock `
        {
            try
            {
                . $PSScriptRoot\f_TryCatch.ps1
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
    if ($Session)
    {
        $Session | Remove-PSSession
    }
}

# SIG # Begin signature block
# MIIY9AYJKoZIhvcNAQcCoIIY5TCCGOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUi6kFdEeaj2SochUcKl5gkVnh
# kQygghJ3MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# u5VPaG2W3eV3Ay67nBLvifkIP9Y1KTF5JS+wzJoYKvZ2MIIGrjCCBJagAwIBAgIQ
# BzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAw
# MDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5
# NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYR
# oUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CE
# iiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCH
# RgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5K
# fc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDni
# pUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2
# nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp
# 88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1C
# vwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+
# 0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl2
# 7KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOC
# AV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaa
# L3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcw
# AoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+
# ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvX
# bYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tP
# iix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCy
# Xen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpF
# yd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3
# fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t
# 5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejx
# mF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxah
# ZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAA
# zV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vup
# L0QVSucTDh3bNzgaoSv27dZ8/DCCBsYwggSuoAMCAQICEAp6SoieyZlCkAZjOE2G
# l50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYg
# U0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAwMDBaFw0zMzAzMTQy
# MzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEk
# MCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0M+7MXGzj4CUu0jHk
# PECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pGbumjS0joiUF/DbLW
# +YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzrsvGD0Z/NCcW5QWpF
# QiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJfD1De1FksRHTAMkcZ
# W+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU4S8D7n+FAsmG4dUY
# FLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g7a5/KC7CnuALS8gI
# 0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtDich+X7Aa3Rm9n3RB
# Cq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0MdI1DNkdcvnfv8zbHB
# p8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/H+gr5BSyFtaBocra
# MJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw40KV6J67m0uy4rZB
# Peevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTngIspQnL3ebLdhOon
# 7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsG
# CWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNV
# HQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMwUTBPoE2gS4ZJaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5
# NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEADS0j
# dKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZiz9d5YZPvpM63io5
# WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZy6HC6kx2yqHcoSuW
# uJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiKn+8RyTFKWLbfOHzL
# +lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB89Bemh2RPPkaJFmMg
# a8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5PELkwNuTzqmkJqIt+
# ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV41pj+VG1/calIGnjd
# RncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKOKGukzp123qlzqkhq
# WUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+NbTmtQyimaXXFWs1
# DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px38qXsdhH6hyF4EVO
# EhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX4IvTnMxttQ2uR2M4
# RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwxggXnMIIF4wIBATAiMA4xDDAK
# BgNVBAMMA2JjbAIQJoAlxDS3d7xJEXeERSQIkTAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUqT+8
# OMffrmnKUCUagm8yCuPQTOgwDQYJKoZIhvcNAQEBBQAEggIAJwDR7g1NKV0x/8Bh
# FzB0AmOz9n+hOc3HEuboN8CtK3U7UkJTs+XS2s23vQ6dD4s9t1d3FkH8DW9jx6K8
# hT5E9vYOBFafWNH/7XLXzoFUsvlVemhmS1wFU9pQTBhuSQaOOoOhET00QekbyF2B
# KRiDNSoAVZz0cHfNd5MlVg2SNd8DJcUgouFIOCLFGRNOSm88YC9bhVJrvNJVhIMc
# 2UCR5Zh1B/L4BkiwB7ydzKDrJQ2P19u4VkmLCwhD76N4KmmYWk5Q42Nn7UcEfhu4
# 2sRaku76a2hIJrfCtgWexGC04VA3XJNc937I88+vtrBxqxCdCVQbPJISH9LPcxBg
# Ok7hxre7UNJJXKKTqz7Hu3Om4gy5osbU+00w1zyHhNLnm8DkPS0kcPMKWCkeVIEg
# nzpBbVbTdj8izLJZKpyYuB9Rf5OBPGkdAjrfFmuRe4oMn9dYZa06i7uYj0wt2mJ+
# BXFOaEWWnNlKuPbzuI6Mne9lIOicvRH5994P+h4mc0LfjFZWlBE768VRriT1NXPo
# wZT8MewdaCsb+MFsMqIBfULFXwxnGAb2YtSWwFE4JbSBZIFQGv/UQ13iJcCH8Hsa
# zIoveXv+BC+rVesjcg10YQXqpbAQHdBf4Ibmjz7U7yOge+CQ4cbfbR6qLYHm6Oh6
# FoZljAr6JccLbzxd9lpY8h95H1WhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkC
# AQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0
# YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJ
# KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNDE4MDUw
# MDAzWjAvBgkqhkiG9w0BCQQxIgQgkC5GnoXkKgILDDk6xriQjUNgBIuWq9iYohA0
# YIjErYUwDQYJKoZIhvcNAQEBBQAEggIAYQbI6PC7CqjjR89wIoPJ8GV93VFjrUuI
# uFV0fcb262R/8QX17PbAdlBlGSIBeGzTSIcCy4wLZFP1jn++k/lew5eCo4XJI/TQ
# HHvnB9yjvYCI+hY9iAFxCBxn/eSmOPtMl+ULLIM0kjW6mcE5V8jMRTSQ0eeUVbpB
# vN9p+vL32wf+XptMRh7s+/Q6rJTVEvea36gX0fy0oPWH8XCi+H9c582uWLGoTmyA
# YIf7caBkfcONhsTZGhemSeTf6CJfnvhYlmsjqrURCj7TrmfE/NaSxe/EeXdqAJpJ
# YSrzgAdqdSazwzq69Bdir5t99Md3VT5kfxnui2RkP0pN84zCX+RnKA1ZhcYPUXGm
# mP9AcZ2r7RIshkS6v7/d8/TucPfedtZaOTHtpuTeXOHaEUEP4YXFWLCR9QZjhR7v
# 2kXM0v8oDm/iywlOOSSy2zzGGJMudUFJrTZmp4h42nlHScsNGCyZfP+sKQ3MsX4q
# B55NJdwBAm1T1VlkObMxHrCG93U9UOLQHFQkCorRFH3tGl0aDp6FtPYSt3WACSiD
# kZryQY9LQyrqDeBhlh0mhVrPufMVg/YJy9FXzXjMUu5403U7KMmIMWL7WqqulW/i
# YthDvGnr7LhJJKe1eD1Q5enbuJ9oIIcPXhnoeXDzfAjnlNvgkBgtYrBNx/ScQPpL
# YP0uHkg6RXk=
# SIG # End signature block
