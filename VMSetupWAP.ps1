<#
 .DESCRIPTION
    Setup Web Application Proxy (WAP)
 .NOTES
    AUTHOR Jonas Henriksson
 .LINK
    https://github.com/bomberclaad
#>

[cmdletbinding(SupportsShouldProcess=$true)]

Param
(
    # VM name
    [String]$VMName,
    # Computer name
    [String]$ComputerName,

    # Serializable parameters
    $Session,
    $Credential,
    $ADFSTrustCredential,

    # Default generic lazy pswd
    $CertFilePassword = (ConvertTo-SecureString -String 'e72d4D6wYweyLS4sIAuKOif5TUlJjEpB' -AsPlainText -Force),

    [String]$ADFSPfxFile,
    [String]$ADFSFederationServiceName
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
            throw $_
        }

    } -NoNewScope

    ######################
    # Get parent ca files
    ######################

    if ($ADFSPfxFile)
    {
        # Get file content
        $ADFSPfx = Get-Content -Path (Get-Item -Path $PSScriptRoot\$ADFSPfxFile -ErrorAction Stop).FullName -Raw
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

        # Get certificate
        $ADFSCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $_.DnsNameList.Contains("adfs.$DomainName") -and (
                $_.Extensions['2.5.29.37'].EnhancedKeyUsages.FriendlyName.Contains('Server Authentication')
            )
        }

        if (-not $ADFSCertificate)
        {
            if (-not $ADFSPfx)
            {
                throw "Can't find ADFS certificate, please use -ADFSPfxFile to submit certificate."
            }
            elseif (ShouldProcess @WhatIfSplat -Message "Importing ADFS certificate from PFX." @VerboseSplat)
            {
                # Save pfx
                Set-Content -Value $ADFSPfx -Path "$env:TEMP\ADFSCertificate.pfx" -Force

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

        # Check if Windows Remote Management - Compatibility Mode (HTTP-In) firewall rule is enabled
        if ((Get-NetFirewallRule -Name WINRM-HTTP-Compat-In-TCP).Enabled -eq 'False' -and
            (ShouldProcess @WhatIfSplat -Message "Enabling WINRM-HTTP-Compat-In-TCP firewall rule." @VerboseSplat))
        {
            Enable-NetFirewallRule -Name WINRM-HTTP-Compat-In-TCP > $null
        }

        # Hosts
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
        }

        # Check if WAP is configured
        try
        {
            # FIX
            # setup more reliable check
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

                    Write-Warning -Message "Restarting computer."
                    Restart-Computer -Force
                    return
                }
                catch [Exception]
                {
                    throw $_.Exception
                }
            }
        }

        # ██████╗  ██████╗ ███████╗████████╗
        # ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝
        # ██████╔╝██║   ██║███████╗   ██║
        # ██╔═══╝ ██║   ██║╚════██║   ██║
        # ██║     ╚██████╔╝███████║   ██║
        # ╚═╝      ╚═════╝ ╚══════╝   ╚═╝

        # FIX
        # add to hosts

        # 192.168.0.150 adfs01.bcl.nu
        # 192.168.0.150 adfs.bcl.nu

        # 192.168.0.200 as01.bcl.nu
        # 192.168.0.200 pki.bcl.nu
        # 192.168.0.200 dke.bcl.nu
        # 192.168.0.200 test.bcl.nu


        #  █████╗  ██████╗███╗   ███╗███████╗
        # ██╔══██╗██╔════╝████╗ ████║██╔════╝
        # ███████║██║     ██╔████╔██║█████╗
        # ██╔══██║██║     ██║╚██╔╝██║██╔══╝
        # ██║  ██║╚██████╗██║ ╚═╝ ██║███████╗
        # ╚═╝  ╚═╝ ╚═════╝╚═╝     ╚═╝╚══════╝

        # Check package provider
        if(-not (Get-PackageProvider | Where-Object { $_.Name -eq 'NuGet' }) -and
          (ShouldProcess @WhatIfSplat -Message "Installing NuGet package provider." @VerboseSplat))
        {
            # Install package provider
            Install-PackageProvider -Name NuGet -Force -Confirm:$false > $null
        }

        # Check module
        if(-not (Get-InstalledModule | Where-Object { $_.Name -eq 'Posh-ACME' }) -and
          (ShouldProcess @WhatIfSplat -Message "Installing Posh-ACME module." @VerboseSplat))
        {
            # Install module
            Install-Module -Name Posh-ACME -Force -Confirm:$false > $null
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

        # Get order
        $Order = Get-PAOrder | Where-Object { $_.MainDomain -eq "*.$DomainName" }

        # Check order
        if(-not $Order -and
          (ShouldProcess @WhatIfSplat -Message "Adding order for *.$DomainName." @VerboseSplat))
        {
            # Adding order
            $Order = New-PAOrder -Domain "*.$DomainName"
        }

        # Check order status
        if($Order.Status -eq 'Pending')
        {
            # Get auth
            $Auth = $Order | Get-PAAuthorizations

            # FIX
            # check Auth status
            if ($Auth)
            {
                # Get token
                $Token = Get-KeyAuthorization -Token $Auth.DNS01Token -ForDNS

                Write-Host -Object "Add TXT record _acme-challenge.$DomainName with value '$Token'"
                Read-Host -Prompt "Press <Enter> when done"

                # Resolve
                $TXTRecord = Resolve-DnsName -Name "_acme-challenge.$DomainName" -Type TXT

                # Check dns
                if(($TXTRecord | Where-Object { $_.Strings -eq $Token }) -and
                  (ShouldProcess @WhatIfSplat -Message "Sending challenge." @VerboseSplat))
                {

                    Send-ChallengeAck -ChallengeUrl $Auth.DNS01Url
                }
                elseif ($TXTRecord)
                {
                    Write-Warning -Message "TXT record value '$($TXTRecord | Select-Object -ExpandProperty Strings)' differs from token '$Token'"
                }
                else
                {
                    Write-Warning -Message "Couldn't resolve TXT record _acme-challenge.$DomainName"
                }
            }

            # Check certificate
            if(-not (Get-PACertificate | Where-Object { $_.Subject -eq "CN=*.$DomainName" }) -and
              (ShouldProcess @WhatIfSplat -Message "Getting certificate." @VerboseSplat))
            {
                # Get certitificate
                New-PACertificate -AcceptTOS -Domain "*.$DomainName" | Install-PACertificate -StoreLocation LocalMachine -StoreName My -NotExportable
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

    # Remote
    if ($Session -and $Session.State -eq 'Opened')
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Splat
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $ComputerName = $Using:ComputerName

            $ADFSTrustCredential = $Using:ADFSTrustCredential
            $CertFilePassword = $Using:CertFilePassword
            $ADFSPfx = $Using:ADFSPfx
            $ADFSFederationServiceName = $Using:ADFSFederationServiceName
        }

        # Run main
        Invoke-Command -Session $Session -ScriptBlock $MainScriptBlock
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
                . $PSScriptRoot\f_ShouldProcess.ps1
                . $PSScriptRoot\f_CopyDifferentItem.ps1
            }
            catch [Exception]
            {
                throw $_
            }

        } -NoNewScope

        # Run main
        Invoke-Command -ScriptBlock $MainScriptBlock -NoNewScope
    }
}

End
{
}

# SIG # Begin signature block
# MIIXpgYJKoZIhvcNAQcCoIIXlzCCF5MCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0VxUvpHCMjpKR8kd25vL0fJU
# 6QagghI6MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBR/roz5m0w8pAdKDkAYyZqc
# 7ZizTjANBgkqhkiG9w0BAQEFAASCAgB1P8JER6qeYW3yYftiHt/da7fUwrJaoABk
# nAleOZtNJcdvb5oPS/hKU+GwoAIpWpsF8UXWNdj0rlOpU1vKhOZL47RMuAZSpt+Z
# mPzaOGFcL+Wywzqoh+IE4zlXZ+I0BCZet0VOpaWaEpWreL1/1q+VdpDe6THoUqwh
# rfEtAPoVxv9DQhPKlakeZCGYB3FCoyyFv64oMkFsL7sJC8dH/VmwaBuJVWiApq64
# 6+MbFaf6LuX94EGV+6xj9FvlLuapTZKkt1JLkP8Gs0XuonunZURsSn43TJqqta5y
# 2eCLYXAAiPdbSJTypycA3is50p6COdL8ocveqB6rPK2O0I3JeSDlOIqnsQPOi7we
# ha0J6Rqc13gaLjK0jumg8Kib9vjC9DMl0MVqLMDgYkH28j1V1GE1Lg4hBJFFHsuC
# cuOPgiNhACD85/4GSXBk982BuLSj/ZthHpJtOsraaN+NE2E9UHfHksQkuj5dKntx
# HDHMTylcW03uTLM0ZgkW044rfMydfVqNZoQnp+mlXKNSKtGIDmAKRQhjBK8ws14m
# 642Wb08ejN3rt1HGd71KAwJmPX/qExrXwd40uR7I7ic/jmTV/mZWAQwcZHSBiCjD
# 7WX3jwu+RRXNMAcXlgEBGSkuhE4EqgbIsotLIBJDegUUG0Dx8ieKa3zJtrKyq17z
# uO92e7+aqaGCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAxMTExMTcwMDAzWjAjBgkqhkiG9w0BCQQx
# FgQUfDSpSRwVQXO5W067RY//FMBlA5AwDQYJKoZIhvcNAQEBBQAEggEAhO0TSK9f
# N3FvOK000iy8oMLhHS4zNFRYRiO0nwWNmlaJM2w5GMLWn0YR3I9Mjv76VqyNF4Hs
# eOBKjO0lCeo9kfUksUOWrq8lYRjZTT5z7OyKgO191jCk+KZTZ2xntsVpYHtJdCWe
# H6sOYdGfT490Os59/Ill22nGe4GDANb5JLtZJneL3ovYrqcMA/WY2Xve1FHw3afu
# 3ZJl5BIA1J6sHr3JNe4n1fEcl8gmQUF6YcMKo24Oc9JvpXKFN9l/DYGy/hWaErWe
# z3INroctie/hollKxZd6kM6jqlnBbOuttF7snjXGB2C0EZqd8J7IqVkKnH1jraTK
# aJfuIGlVzSUB9A==
# SIG # End signature block
