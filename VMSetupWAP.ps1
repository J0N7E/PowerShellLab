<#
 .DESCRIPTION
    Setup Web Application Proxy (WAP)
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
    $ADFSTrustCredential,

    # Default generic lazy pswd
    $CertFilePassword = (ConvertTo-SecureString -String 'e72d4D6wYweyLS4sIAuKOif5TUlJjEpB' -AsPlainText -Force),

    [String]$ADFSPfxFile,
    [String]$ADFSFederationServiceName,

    [Switch]$EnrollLetsEncryptCertificates
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
        @{ Name = 'Session';                                      },
        @{ Name = 'Credential';             Type = [PSCredential] },
        @{ Name = 'ADFSTrustCredential';    Type = [PSCredential] },
        @{ Name = 'CertFilePassword';       Type = [SecureString] }
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
        }
        catch [Exception]
        {
            throw "$_ $( $_.ScriptStackTrace)"
        }

    } -NoNewScope

    ######################
    # Get parent ca files
    ######################

    if ($ADFSPfxFile)
    {
        # Get file content
        $ADFSPfxFile = Get-Content -Path (Get-Item -Path $PSScriptRoot\$ADFSPfxFile -ErrorAction Stop).FullName -Raw
    }

    ################################
    # Default ADFS trust credential
    ################################

    if (-not $ADFSTrustCredential -and $Credential)
    {
        $ADFSTrustCredential = $Credential
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

        ###############
        # Check domain
        ###############

        $PartOfDomain = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty PartOfDomain

        # Check for part of domain
        if ($PartOfDomain)
        {
            $DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain

            if (-not $ADFSFederationServiceName)
            {
                $ADFSFederationServiceName = "adfs.$DomainName"
            }
        }
        elseif (-not $ADFSFederationServiceName)
        {
            throw "Can't find domain, please use -ADFSFederationServiceName and specify FQDN."
        }
        else
        {
            $DomainName = $ADFSFederationServiceName.Substring($ADFSFederationServiceName.IndexOf('.') + 1)
        }

        # ██████╗ ██████╗ ███████╗██████╗ ███████╗ ██████╗
        # ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗
        # ██████╔╝██████╔╝█████╗  ██████╔╝█████╗  ██║   ██║
        # ██╔═══╝ ██╔══██╗██╔══╝  ██╔══██╗██╔══╝  ██║▄▄ ██║
        # ██║     ██║  ██║███████╗██║  ██║███████╗╚██████╔╝
        # ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚══▀▀═╝

        ###############
        # Lets Encrypt
        # Acme
        ###############

        if ($EnrollLetsEncryptCertificates)
        {
            #########
            # Prereq
            #########

            # Check package provider
            if(-not (Get-PackageProvider | Where-Object { $_.Name -eq 'NuGet' }) -and
              (ShouldProcess @WhatIfSplat -Message "Installing NuGet package provider." @VerboseSplat))
            {
                # Install package provider
                Install-PackageProvider -Name NuGet -Force -ErrorAction Stop -Confirm:$false > $null
            }

            # Check module
            if(-not (Get-InstalledModule | Where-Object { $_.Name -eq 'Posh-ACME' }) -and
              (ShouldProcess @WhatIfSplat -Message "Installing Posh-ACME module." @VerboseSplat))
            {
                # Install module
                Install-Module -Name Posh-ACME -Force -ErrorAction Stop -Confirm:$false > $null
            }

            # Check server
            if(-not (Get-PAServer | Where-Object { $_.location -eq 'https://acme-v02.api.letsencrypt.org/directory' }) -and
              (ShouldProcess @WhatIfSplat -Message "Setting production server." @VerboseSplat))
            {
                # Set server
                Set-PAServer -DirectoryUrl 'https://acme-v02.api.letsencrypt.org/directory' > $null
            }

            # Check account
            if(-not (Get-PAAccount | Where-Object { $_.contact -eq "mailto:admin@$DomainName" }) -and
              (ShouldProcess @WhatIfSplat -Message "Adding account admin@$DomainName." @VerboseSplat))
            {
                # Adding account
                New-PAAccount -AcceptTOS -Contact "admin@$DomainName" > $null
            }

            ###############
            # Certificates
            ###############

            $Certificates =
            @(
                @("*.$DomainName")
            )

            ##########
            # Request
            ##########

            foreach ($Cert in $Certificates)
            {
                $PACertificate = Get-PACertificate -List | Where-Object { @(Compare-Object $_.AllSANs $Cert -SyncWindow 0).Length -eq 0 }

                # Check order status
                if(-not $PACertificate)
                {
                    $PACertificate = New-PACertificate -Domain $Cert -AcceptTOS -DNSSleep 20

                }
                if($PACertificate.NotAfter -le (get-date).AddDays(14).ToShortDateString())
                {
                    # Remove old cert
                    Remove-Item -Path "Cert:\LocalMachine\My\$($PACertificate.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue

                    if ($Cert.GetType().Name -eq 'object[]')
                    {
                        $MainDomain = $Cert[0]
                    }
                    else
                    {
                        $MainDomain = $Cert
                    }

                    $PACertificate = Submit-Renewal -MainDomain $MainDomain -NoSkipManualDns
                }

                $PACertificate | Install-PACertificate -StoreLocation LocalMachine -StoreName My -NotExportable
            }
        }

        ##################
        # Get certificate
        ##################

        $ADFSCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $_.DnsNameList.Contains("adfs.$DomainName") -and
            $_.DnsNameList.Contains("certauth.adfs.$DomainName") -and
            $_.DnsNameList.Contains("enterpriseregistration.$DomainName") -and
            (
                $_.Extensions['2.5.29.37'].EnhancedKeyUsages.FriendlyName.Contains('Server Authentication')
            )
        }

        #####################
        # Import certificate
        #####################

        if (-not $ADFSCertificate)
        {
            if (-not $ADFSPfxFile)
            {
                throw "Can't find ADFS certificate, please use -ADFSPfxFile to submit certificate."
            }
            elseif (ShouldProcess @WhatIfSplat -Message "Importing ADFS certificate from PFX." @VerboseSplat)
            {
                # Save pfx
                Set-Content -Value $ADFSPfxFile -Path "$env:TEMP\ADFSCertificate.pfx" -Force

                try
                {
                    # FIX
                    # make function
                    $Pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection;
                    $Pfx.Import("$env:TEMP\ADFSCertificate.pfx", [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertFilePassword)), 'PersistKeySet,MachineKeySet');

                    foreach ($Cert in $Pfx) {

                        # CA Version
                        if ($Cert.Extensions['1.3.6.1.4.1.311.21.1'])
                        {
                            # Authority Key Identifier
                            if ($Cert.Extensions['2.5.29.35'])
                            {
                                $Store = 'CA'
                            }
                            else
                            {
                                $Store = 'Root'
                            }
                        }
                        else
                        {
                            $Store = 'My'
                            $ADFSCertificate = $Cert
                        }

                        $X509Store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $Store,'LocalMachine'
                        $X509Store.Open('MaxAllowed')
                        $X509Store.Add($Cert)
                        $X509Store.Close > $null
                    }
                }
                catch [Exception]
                {
                    throw $_.Exception
                }
                finally
                {
                    # Cleanup
                    Remove-Item -Path "$env:TEMP\ADFSCertificate.pfx"
                }
            }
        }

        ##################
        # Disable TLS 1.3
        ##################

        $TLSRegistrySettings =
        @(
            @{ Name = 'DisabledByDefault';  Value = '1';  PropertyType = 'DWord';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' },
            @{ Name = 'Enabled';            Value = '0';  PropertyType = 'DWord';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' }
        )

        Set-Registry -Settings $TLSRegistrySettings

        ########
        # Hosts
        ########

        <#
        $Hosts =
        @(
            "192.168.0.150 adfs.$DomainName"
            "192.168.0.200 pki.$DomainName"
        )

        $HostsFile = Get-Item -Path 'C:\Windows\System32\drivers\etc\hosts'
        $HostsContent = $HostsFile | Get-Content

        # Add to hosts file
        foreach ($Item in $Hosts)
        {
            if ($HostsContent -notcontains $Item -and
              ((ShouldProcess @WhatIfSplat -Message "Adding `"$Item`" to hosts." @VerboseSplat)))
            {
                $HostsFile | Add-Content -Value $Item
            }
        }
        #>

        # ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗
        # ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║
        # ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║
        # ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║
        # ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
        # ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

        # Check if WAP is installed
        if (((Get-WindowsFeature -Name Web-Application-Proxy).InstallState -ne 'Installed') -and
             (ShouldProcess @WhatIfSplat -Message "Installing Web-Application-Proxy." @VerboseSplat))
        {
            Install-WindowsFeature -Name Web-Application-Proxy -IncludeManagementTools > $null
        }

        #  ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗ ██╗   ██╗██████╗ ███████╗
        # ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ ██║   ██║██╔══██╗██╔════╝
        # ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗██║   ██║██████╔╝█████╗
        # ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║██║   ██║██╔══██╗██╔══╝
        # ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝╚██████╔╝██║  ██║███████╗
        #  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝

        # Setup WAP parameters
        $WAPParams =
        @{
            FederationServiceName = $ADFSFederationServiceName
            CertificateThumbprint = $ADFSCertificate.Thumbprint
            FederationServiceTrustCredential = $ADFSTrustCredential
            #TlsClientPort = 443
        }

        # Check if WAP is configured
        try
        {
            Get-WebApplicationProxyApplication > $null
        }
        catch
        {
            # WAP not configured
            if (ShouldProcess @WhatIfSplat -Message "Configuring WAP." @VerboseSplat)
            {
                try
                {
                    Install-WebApplicationProxy @WAPParams -ErrorAction Stop > $null

                    $Reboot = $true
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

        $WAPApplications =
        @(
            @{ Name = "test.$DomainName";    Url = "http://test.$DomainName"; Auth = 'PassThrough'; }
        )

        $WildcardCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $_.DnsNameList.Contains("*.$DomainName") -and
            (
                $_.Extensions['2.5.29.37'].EnhancedKeyUsages.FriendlyName.Contains('Server Authentication')
            )
        }

        foreach ($App in $WAPApplications)
        {
            # Initialize
            $CertificateSplat = @{}

            # Check if certificate is needed
            if ($App.Url -match 'https')
            {
                if (-not $WildcardCertificate)
                {
                    Write-Warning -Message "No certificate found for '$($App.Url)'."
                    continue
                }

                $CertificateSplat +=
                @{
                    ExternalCertificateThumbprint = $WildcardCertificate.Thumbprint
                }
            }

            # Check WAP application
            $WapApp = Get-WebApplicationProxyApplication | Where-Object { $_.Name -eq $App.Name }

            # Add new
            if (-not $WapApp -and
                (ShouldProcess @WhatIfSplat -Message "Adding $($App.Name)" @VerboseSplat))
            {
                Add-WebApplicationProxyApplication @CertificateSplat -Name $App.Name -ExternalPreauthentication $App.Auth -ExternalUrl $App.Url -BackendServerUrl $App.Url
            }
            # Update certificate
            elseif (($WapApp.ExternalCertificateThumbprint -and $WapApp.ExternalCertificateThumbprint -ne $WildcardCertificate.Thumbprint) -and
                    (ShouldProcess @WhatIfSplat -Message "Updating $($App.Name) certificate." @VerboseSplat))
            {
                Set-WebApplicationProxyApplication @CertificateSplat -Id $WapApp.Id
            }
        }

        # Check if restart
        if ($Reboot -and
            (ShouldProcess @WhatIfSplat -Message "Restarting $ENV:ComputerName." @VerboseSplat))
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

    # Initialize
    $InvokeSplat = @{}

    # Setup remote
    if ($Session -and $Session.State -eq 'Opened')
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetRegistry.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            $ADFSTrustCredential = $Using:ADFSTrustCredential
            $CertFilePassword = $Using:CertFilePassword
            $ADFSPfxFile = $Using:ADFSPfxFile
            $ADFSFederationServiceName = $Using:ADFSFederationServiceName

            $EnrollLetsEncryptCertificates = $Using:EnrollLetsEncryptCertificates
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
                . $PSScriptRoot\f_ShouldProcess.ps1
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
        Invoke-Command @InvokeSplat -ScriptBlock $MainScriptBlock -ErrorAction Stop
    }
    catch [Exception]
    {
        throw "$_ $( $_.ScriptStackTrace)"
    }
}

End
{
}

# SIG # Begin signature block
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbWVkb+Ku0nxF2QZZ/RnXRA3v
# hkSgghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBT/Wevv
# ieltQLrQizAC9lr+XyRJrTANBgkqhkiG9w0BAQEFAASCAgCPItGrtgeNIUcREeGI
# beB2Z/fFsxQm8FKU7l2SEOSo2BRy5dg3OTFhkwsF3ayi6N9sgjkjr/NspIO6ElXc
# gd0pwea+AXDUk/qCzxs/nC3l+7NSj6vp79oTis8fSQkN5EJFg58+49gQabcmgzqH
# szRWACwuDaTxF62oO5njEfbYycwcTAzcHAn3bR3Kd9Oqsdr7WEJ6iqFLHJJO/HcY
# Aytw3xudcWKNBHiAlD/HcfBTt+Q/CjC0ULOQrPrWvMs+/8rCWVvaF+6nEvS7OaDw
# /wstMGN6O8gwYa4q7yGQVaPkSGjhz+8Yc/7iEXCns8mlmi0aQHCqq3byx1y2wPRr
# 7R9CzdOGsC8b0inQYnOF93dlrKq2DfPiMBNgx1B7GpDa7Fi2nu0TySYsUPwfkmp1
# 0gx46gvYquceEzN2U2yNSEFxvc1Si/P1G2psJ/JCIhNw5F7MgtE99lfoDyvoFowm
# CF02AetHgJakAfqP81P89DYE7Oa/kScLgBR0ftcCr29Re9CoJ6kafNg9cAD0D+5r
# H1KzQGvxd3UKDJB5+jFWGodsC9f/0FV/aAx+y64L7aP/lZ+mgQZAz5VdRnvoE51Q
# xtJ6yOQeHGwFO0Hgu3WSsguI/dOGsEI0bw3TO0UTWZ/hLnUjqIEWlItZqrx2URLo
# iVvrygk8E46eKisRixEp8ALidqGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA5MDcyMDAw
# MTJaMC8GCSqGSIb3DQEJBDEiBCBams5w+tDHYF6Y38Js4Br9ZdtFmO+OepSX7Bzq
# CPPF0TANBgkqhkiG9w0BAQEFAASCAgBIvqBqL7s1BwqGC0QQi/V/NDSTPz5MuNwJ
# /Vi3MKvrIzy5fFerbUiJkYpe2qNQN0QkTNVUyA+rFmXLTWgWw+l1jaEINtbNGaEh
# L1b6VsfF3E+tUq8iQ3LTsVXigRdIRenHQsih4mgW/PibzQDfonklTyimyMuVyjvw
# kMtV49KeJtKoecJGKlJy1k4ew1bCZy8aQ3+RrutdT+/DXfF0bbUthB3Im5/7RKnr
# kBeobX2hhVEF3EIMIWLBd2j18MbO6wuDBU9ySi+PqQ3H1ug9/9qmhhqihO7EF55J
# 4Y8OlwVg3lgrf/7kTMaM5S3rfdP1ReqTX7eDkvq7AfM0aFKzI3ZajF7JnuxMtz51
# NdMx6DmAW+8p8pn86JJb2oluDcwJqtBL4vYsp3vjkGLeokk73d+ii4Ghb2/S2xYt
# k5hG53brJGCcVfzNhjxyQDP+i+lHS+DTI6Oma7suT9mLKg1ffsAQ0WAH2Xii3J+s
# uTGglomj67O2a1Mpr4RFkFF62D094YFWuKoxI4uT3+DYd+dizVVjOUCtVwmDbydw
# JZb3L+pjm4ROlc2JBdbxiImaogkRg6O0gdN9ivU5ebysXcq60v8a0ILJjrgMXm+T
# xv32YVzlIftxs1EsXXFPJBgvnHxykJHtGWr0e8aGAhBaizKbnL1Sc9B5b7MSeqvW
# lI7LqrZK8w==
# SIG # End signature block
