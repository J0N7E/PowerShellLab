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

    [Switch]$EnrollAcmeCertificates
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

        #######
        # Acme
        #######

        if ($EnrollAcmeCertificates)
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

        ###########
        # Firewall
        ###########

        # Check if Windows Remote Management - Compatibility Mode (HTTP-In) firewall rule is enabled
        if ((Get-NetFirewallRule -Name WINRM-HTTP-Compat-In-TCP).Enabled -eq 'False' -and
            (ShouldProcess @WhatIfSplat -Message "Enabling WINRM-HTTP-Compat-In-TCP firewall rule." @VerboseSplat))
        {
            Enable-NetFirewallRule -Name WINRM-HTTP-Compat-In-TCP > $null
        }

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
            @{ Name = "pki.$DomainName";    Url = "http://pki.$DomainName"; Auth = 'PassThrough'; }
            @{ Name = "curity.$DomainName"; Url = "https://curity.$DomainName"; Auth = 'PassThrough'; }
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

            $EnrollAcmeCertificates = $Using:EnrollAcmeCertificates
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
                . $PSScriptRoot\f_ShouldProcess.ps1
                . $PSScriptRoot\f_CopyDifferentItem.ps1
            }
            catch [Exception]
            {
                throw $_
            }

        } -NoNewScope

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
# MIIZBgYJKoZIhvcNAQcCoIIY9zCCGPMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUA2fy6vbYNow7k1jq2hQCBdXP
# /augghKHMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# BgkqhkiG9w0BCQQxFgQUiTj0xaor4vm4Zoom3CBxVOJOWcUwDQYJKoZIhvcNAQEB
# BQAEggIABm8B+K2E1u82i/6Sm1/k3ZvS5NNfDN+k3Yu4rz5Ttev/YCsWdMnJqaxd
# K8pGsdHHnnmOHSXKXiOPPMkWpqvti36MuU4IaM9XApfBqM4FykpDZYESU/B/aiUr
# 3NTjWFphwH1Ejdyqij+hUR9ZBLl2QaL5j6JXXm0BphCCqpZRwTecKguzsGoPkeId
# y1D0ltyrpPHfVBibEHLSWnDQu7jZT2vwrDyyUGE8cySu6SnoUL4wephffMG2Yg2Z
# UqZkFUh+NMo4hPjEJmfGrNOGi+LwkH0bIg67NhxUlXY6V1IjMma2STugTgW8NgA6
# OwwdLNXaPWZT5SehQRJsvXUbIrkmDmG35FmnE2ZFrAgF2wSOBu7w+U6lJqXr6siI
# Fg39qMiFGJblId5DHc2JWcMP4QykICiTWlgPa0ePR5zE7qGZc/+kK72ZxnsKyxE2
# MNiGZoGLTEuRErZGVCl34wv5URh/enK5yUsgpevxS6CjOSPyYBjkL1F9NMtpQNmF
# LYckNu3JXwUg/F6j3W6jteHlZ7fIU0GRZa3KcDL99+ZCOWfCz6PELp2EWXmTUdUN
# Sw5rpeuIDl6wbBSWyjZEwm859nDGszlK5upg3XfXwbRQfU/RdsRR9rDd+RR5ThkW
# 2/beX5frRi+gtb1yEAzvfYx65XBmIza7mHxAFUCOi3gW1oMG7zOhggMgMIIDHAYJ
# KoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNB
# NDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0G
# CWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMjIwNTE4MTU0NTM2WjAvBgkqhkiG9w0BCQQxIgQg569CUxu+wiDi
# wf5zQUGzwrfn/MV8Ufsgq9dHW6uY3Z4wDQYJKoZIhvcNAQEBBQAEggIAsOTt9RLN
# qMeEZBhkgN3PbUzYxBln4tID4vpXMaALDAu/6bN/vBAHjreHgYLPW3PB52QywnyD
# N2/srg138g/lmHle0IVDxEsJTZ43kHhiXY6BVclNeTNmdmd1r0r7Unus8KSpF3a1
# M9lnd3nohcl5QqpfARFp1Y15aOkmuuBifhUuijvEGWV6bL4AmKffFqDazLj4Sfa6
# rsrlzSQPQJullOerDFwW0Kjuy+0uIUUsZRMrxiQK7Sro0ug5KUY3E66VJAk5cFWS
# DklZqzCkW+8/pBUdlcc6JymNvbLkuQDntu2digcazSrKHFAtk6HNv1gQ47hsaqKD
# O3JBV8cE3A4Dcis2GaIMzuJ6H4MYOq8ogMMBeYqqXhsU9mfKU8iGP2gyCBsWRvvN
# pv9+JI4L3umLaphr9TCdI7gzRBVxUjsJu6yxPM4gDaIv9IC2WfUTO9RgmlRNqtAu
# H0hUC8HF58+L+CJPV5U50aWyRyej02Kr9UOdzACk8DijBcE1qqPhpMU/ZocWHWuS
# +ITOFWtXdSIbHkJTzjA8WzV8soTzewTD0C3aERQhUi7E7bvWZxy/2C05LF52lJVK
# 6+O5DgQJJ05Ky5gxFnBlPukZ6JuTxZdIbwUUg/oLgszH978oeHTqgMdJR5XAU+0f
# JDeEEwQxHz6YxMd6Wc3yeWejS1dl6Cz+t6U=
# SIG # End signature block
