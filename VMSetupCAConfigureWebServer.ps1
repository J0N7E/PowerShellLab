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
# MIIZBgYJKoZIhvcNAQcCoIIY9zCCGPMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUi6kFdEeaj2SochUcKl5gkVnh
# kQygghKHMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# 8jCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh
# 1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+Feo
# An39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1
# decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxnd
# X7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6
# Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPj
# Q2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlREr
# WHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JM
# q++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh
# 3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8j
# u2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnS
# DmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# dwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAG
# A1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOC
# AgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp
# /GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40B
# IiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2d
# fNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibB
# t94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7
# T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZA
# myEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdB
# eHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnK
# cPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/
# pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yY
# lvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbGMIIErqADAgEC
# AhAKekqInsmZQpAGYzhNhpedMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwMzI5
# MDAwMDAwWhcNMzMwMzE0MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xJDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIy
# IC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALkqliOmXLxf1knw
# FYIY9DPuzFxs4+AlLtIx5DxArvurxON4XX5cNur1JY1Do4HrOGP5PIhp3jzSMFEN
# MQe6Rm7po0tI6IlBfw2y1vmE8Zg+C78KhBJxbKFiJgHTzsNs/aw7ftwqHKm9MMYW
# 2Nq867Lxg9GfzQnFuUFqRUIjQVr4YNNlLD5+Xr2Wp/D8sfT0KM9CeR87x5MHaGjl
# RDRSXw9Q3tRZLER0wDJHGVvimC6P0Mo//8ZnzzyTlU6E6XYYmJkRFMUrDKAz200k
# heiClOEvA+5/hQLJhuHVGBS3BEXz4Di9or16cZjsFef9LuzSmwCKrB2NO4Bo/tBZ
# mCbO4O2ufyguwp7gC0vICNEyu4P6IzzZ/9KMu/dDI9/nw1oFYn5wLOUrsj1j6siu
# gSBrQ4nIfl+wGt0ZvZ90QQqvuY4J03ShL7BUdsGQT5TshmH/2xEvkgMwzjC3iw9d
# RLNDHSNQzZHXL537/M2xwafEDsTvQD4ZOgLUMalpoEn5deGb6GjkagyP6+SxIXuG
# Z1h+fx/oK+QUshbWgaHK2jCQa+5vdcCwNiayCDv/vb5/bBMY38ZtpHlJrYt/YYcF
# aPfUcONCleieu5tLsuK2QT3nr6caKMmtYbCgQRgZTu1Hm2GV7T4LYVrqPnqYklHN
# P8lE54CLKUJy93my3YTqJ+7+fXprAgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMC
# B4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3Mp
# dpovdYxqII+eyG8wHQYDVR0OBBYEFI1kt4kh/lZYRIRhp+pvHDaP3a8NMFoGA1Ud
# HwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUF
# BwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# WAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAA0tI3Sm0fX46kuZPwHk9gzkrxad2bOMl4IpnENvAS2rOLVw
# Eb+EGYs/XeWGT76TOt4qOVo5TtiEWaW8G5iq6Gzv0UhpGThbz4k5HXBw2U7fIyJs
# 1d/2WcuhwupMdsqh3KErlribVakaa33R9QIJT4LWpXOIxJiA3+5JlbezzMWn7g7h
# 7x44ip/vEckxSli23zh8y/pc9+RTv24KfH7X3pjVKWWJD6KcwGX0ASJlx+pedKZb
# NZJQfPQXpodkTz5GiRZjIGvL8nvQNeNKcEiptucdYL0EIhUlcAZyqUQ7aUcR0+7p
# x6A+TxC5MDbk86ppCaiLfmSiZZQR+24y8fW7OK3NwJMR1TJ4Sks3KkzzXNy2hcC7
# cDBVeNaY/lRtf3GpSBp43UZ3Lht6wDOK+EoojBKoc88t+dMj8p4Z4A2UKKDr2xpR
# oJWCjihrpM6ddt6pc6pIallDrl/q+A8GQp3fBmiW/iqgdFtjZt5rLLh4qk1wbfAs
# 8QcVfjW05rUMopml1xVrNQ6F1uAszOAMJLh8UgsemXzvyMjFjFhpr6s94c/MfRWu
# FL+Kcd/Kl7HYR+ocheBFThIcFClYzG/Tf8u+wQ5KbyCcrtlzMlkI5y2SoRoR/jKY
# pl0rl+CL05zMbbUNrkdjOEcXW28T2moQbh9Jt0RbtAgKh1pZBHYRoad3AhMcMYIF
# 6TCCBeUCAQEwJDAQMQ4wDAYDVQQDDAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJ
# BgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAj
# BgkqhkiG9w0BCQQxFgQUqT+8OMffrmnKUCUagm8yCuPQTOgwDQYJKoZIhvcNAQEB
# BQAEggIAn43kfO5mvK8wM0TcKCRYoslAB1TmU2UNBFY2IJcHHi8qhwqZmps+bfV7
# dgMcPktd8MkSEHXarss6zl7n2p7RG9YF6G6nMDqbFjMXNd6O+3YUeUQmT2RetiM8
# 2cHDZVm9b4JqKoKpUsddc2l/tw7nR6/pE4qYZmj9UWe0/TllqXaA1lEayu2svxus
# c9nVxu4hhlRNJS+g83IjQbtsOArc+K6Icv34htiBqYc3PIAOsLQiuPdUDdL4//Rd
# vVm1fVvtyGq5CTLRU2054e0X7YgNWGt9DFQkdrZEixxZH2vOiD5mcjyTOt5YzPSQ
# aFh8A/CeUVbVMbzFDhhiUibEDbL2SpiIpjGPKMWAqM+vLEfLFaqXr8FDDzV9Htj2
# 4PsvFVjzItwM2VqEVACzUzjrRLS5cavovR03M6QlkW0gxCMPUPkRWZaFbTMhOFVl
# Ltnll0pYKc1UwvWK2kzA+5kwkimWm1Z5pr1QfxiljIBGP6ipA2JctoRgfdhg1yXU
# R6Gsg4vatzVPx29yjJTM4zsN5/o0Z/UY9HK/B6iEctFH7KCDvii22f4c5SkdieVy
# w1C5177j5zp239WaOzeG0uytD40SLRGa1W8IWOa8cR9LvLHUzr20Q+pcBLiJOZ/l
# LbJPrFPqHGK5QdfI9SBuJGoMxcNZ9sa04dK4wCKVX/pKzRAk6EGhggMgMIIDHAYJ
# KoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNB
# NDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0G
# CWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMjIwNTE4MTU0NTM0WjAvBgkqhkiG9w0BCQQxIgQgVboX0JbXx2vD
# RJtWlW0+u7X0N4zpnP0nwpQcuIfX/gcwDQYJKoZIhvcNAQEBBQAEggIATBn6s+Fc
# G+ZMqpMQrivL0P4VuvHF1YR0CVF3osIUFImv5FnvPwGyPT8XOm0aHAGUeKb3PLvL
# KJgpuQ97fxB5FHNFk5IlHWAk4pAjD/TU57E3BM+cV/hayFaWmdaTQKJhncBVNPQ5
# gqXe0hA/t4Bdm0BoCo+bhVYcKB1Wq9TSr7iWrvK9ZGC6QiFa5c7h3d7YcS2txWSi
# 0vG9F1Rk4o60Ch/1D1aBryI0T1q0IoxqiJ6bu9vyGce0civPnNrLW/+S9YDzso6c
# 7A6FDKwuxX3h4q1JUQ8oi8HPyTJVPSgdkrSAwkbDEWMrM6s8y7JfGLKWClEiscPU
# J+nWUF/Q0n8o50awb339vCLGcnDFKadANdyNR/7lBtzaiwRSx8T8qZOvk8A9jj3o
# 84zVPtmTsZ4ONKCUsbAW4t+YD2/f3R7KteJ6kH5lzZeWIWHGoZcXKmeCJtZ27Bkc
# j93VpSh22g7kbo2tmWdh9SCvLQHMgNOr8IkUmcuFpXr90xoop8eDBA7PaRFQiaFq
# aN03O9EpzswGFJTtrhQSO6Mu5CZkOFtfKLHVI21KQVmeGmyjKTqlLV9hGpiqWGgs
# gL+fO4uPnYyup0J7FL0Lq8MllS9Qqcrv2f6Lv0LfKyFwHUt7rXHxU6GmhgOjLQu5
# jacVNpaOS35bEEj80+qFoDFo1PNZ/Nxf0Vw=
# SIG # End signature block
