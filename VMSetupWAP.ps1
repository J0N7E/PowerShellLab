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
# MIIUvwYJKoZIhvcNAQcCoIIUsDCCFKwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUA2fy6vbYNow7k1jq2hQCBdXP
# /auggg8yMIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUiTj0xaor4vm4Zoom3CBxVOJOWcUwDQYJ
# KoZIhvcNAQEBBQAEggIAoAliJjiJ9jATsx5Czl3Lcq8fGXmhGUCMHeW4PgVqgrB6
# AJC73RKA8sttO+oVboUuz5PB9GiCNaryFy0QZIy8m+jef157dGU1ZkEJKziOSloT
# t1Hy5PkfWEnO97gfXtJZGfik0xLAiNixRuz1GqVsWJdQsv1ANyRndlYBdspI1Kod
# sN4xwJwHPwlgbMRPNnJG21/zm/DBwET8sbecuNQYYZUsWqld0BqoUJVlyA606UKB
# Zu/0YwFpd2RuoQnpL6wgx99pdssIYIYAXDIckfssBt3oShTbUaOsNUqgzXTNOwqv
# 6SQvqCkRyW/ZEnYxmbPizG6J5M1Fiwm16lmdpbtUVQDGW/rjjbR/E52LChY4n/Lj
# j15WZ+PQ3rUN4veGbHvYkbnjmlTbwzx0VBTFXXSAZBJ2c4Bx9Z3/dYd12+jTmahl
# uq3TR0KiTnTVp11ZAX04bzEZpER73bPYJlzWOlx6B8JUcfIM77ZbIUOendB/QbNL
# bKbd63N6sc9lups0DmGfHLU31a4/MjrLUu5Oc15aOM3eHucwW7GxWc43enrApqIP
# 985Up7QXPXepEcdm4J0GENSVVGDSSHqLH54eqa1xIAXVzYBqcAzUVCZ5zzMD9Voy
# Qs5GGyJxcGlPO2qCYNzycswOTY5BlFnUk0CgPRB6obnRefWkynER+lvHajnKX9Wh
# ggIwMIICLAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGlu
# ZyBDQQIQDUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIyMDMxNDE0MDAwM1ow
# LwYJKoZIhvcNAQkEMSIEIE1oStcGPyAmFF9Yp7oGoW7YRJW2DN8YcH3R343+f+Ty
# MA0GCSqGSIb3DQEBAQUABIIBAFrTk5ZtPLv6FR0mPo0G+W7kT29DYCf8qC60SnOm
# WR0R/pP5CrPBZEHsXX8s5LwAEbVwtYS1rfovVJRDO4hyhXPdHiV5JEmb8vtFYUwY
# R9FMxE5uoyIZ3K4hQ6a9WhmtO33mGBFIJ3gVTzlbXyPYPjEbYM7pTyH11Kz0ssou
# Ccim5A6mALnac8zE/4TOz/+ALhQ0LKuqR/FcfZN/VrOxd1Ha+X7i97kwmwplm8Zr
# jfvlAbwzrLgIt1Wa5hQFFi9DsxezNJIRnRZ9y9UNVjAYEz+nRxZyI5d/OJtMp2iC
# 5gE4f05rLZOnfFAT64NzqzCBolnUd12mxfRaFnF93nO2SkQ=
# SIG # End signature block
