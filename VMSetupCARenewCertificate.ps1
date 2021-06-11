<#
 .DESCRIPTION
    Renew CA certificate
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

    # Hash algorithm
    [ValidateSet('MD2', 'MD4', 'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
    [String]$HashAlgorithmName = 'SHA256',

    # Key length
    [ArgumentCompleter({

        if ($args[4].HashAlgorithmName)
        {
            $HashAlgorithmName = $args[4].HashAlgorithmName
        }
        else
        {
            $HashAlgorithmName = 'SHA256'
        }

        @{
            MD2    = @(               512, 1024, 2048, 4096)
            MD4    = @(               512, 1024, 2048, 4096)
            MD5    = @(               512, 1024, 2048, 4096)
            SHA1   = @(256, 384, 521, 512, 1024, 2048, 4096)
            SHA256 = @(256, 384, 521, 512, 1024, 2048, 4096)
            SHA384 = @(256, 384, 521, 512, 1024, 2048, 4096)
            SHA512 = @(256, 384, 521, 512, 1024, 2048, 4096)

        }.Item($HashAlgorithmName)
    })]
    [Int]$KeyLength = 4096,

    # Crypto providers
    [ArgumentCompleter({

        if ($args[4].HashAlgorithmName)
        {
            $HashAlgorithmName = $args[4].HashAlgorithmName
        }
        else
        {
            $HashAlgorithmName = 'SHA256'
        }

        if ($args[4].KeyLength)
        {
            $KeyLength = $args[4].KeyLength
        }
        else
        {
            $KeyLength = 4096
        }

        @{
            MD2 =
            @{
                512  = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'")
                1024 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
                2048 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
                4096 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
            }
            MD4 =
            @{
                512  = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'")
                1024 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
                2048 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
                4096 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
            }
            MD5 =
            @{
                512  = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'")
                1024 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
                2048 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
                4096 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
            }
            SHA1 =
            @{
                256  = @("'ECDSA_P256#Microsoft Software Key Storage Provider'", "'ECDSA_P256#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P256#SafeNet Key Storage Provider'")
                384  = @("'ECDSA_P384#Microsoft Software Key Storage Provider'", "'ECDSA_P384#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P384#SafeNet Key Storage Provider'")
                521  = @("'ECDSA_P521#Microsoft Software Key Storage Provider'", "'ECDSA_P521#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P521#SafeNet Key Storage Provider'")

                512  = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'",                                                                                                                                         "'DSA#Microsoft Software Key Storage Provider'", "'Microsoft Base DSS Cryptographic Provider'", "'DSA#SafeNet Key Storage Provider'")
                1024 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'", "'DSA#Microsoft Software Key Storage Provider'", "'Microsoft Base DSS Cryptographic Provider'", "'DSA#SafeNet Key Storage Provider'")
                2048 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'", "'DSA#Microsoft Software Key Storage Provider'")
                4096 = @("'RSA#Microsoft Software Key Storage Provider'", "'Microsoft Strong Cryptographic Provider'", "'Microsoft Enhanced Cryptographic Provider v1.0'", "'Microsoft Base Cryptographic Provider v1.0'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'Microsoft Base Smart Card Crypto Provider'", "'RSA#SafeNet Key Storage Provider'")
            }
            SHA256 =
            @{
                256  = @("'ECDSA_P256#Microsoft Software Key Storage Provider'", "'ECDSA_P256#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P256#SafeNet Key Storage Provider'", "'ECDH_P256#SafeNet Key Storage Provider'")
                384  = @("'ECDSA_P384#Microsoft Software Key Storage Provider'", "'ECDSA_P384#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P384#SafeNet Key Storage Provider'", "'ECDH_P384#SafeNet Key Storage Provider'")
                521  = @("'ECDSA_P521#Microsoft Software Key Storage Provider'", "'ECDSA_P521#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P521#SafeNet Key Storage Provider'", "'ECDH_P521#SafeNet Key Storage Provider'")

                512  = @("'RSA#Microsoft Software Key Storage Provider'")
                1024 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
                2048 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
                4096 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
            }
            SHA384 =
            @{
                256  = @("'ECDSA_P256#Microsoft Software Key Storage Provider'", "'ECDSA_P256#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P256#SafeNet Key Storage Provider'", "'ECDH_P256#SafeNet Key Storage Provider'")
                384  = @("'ECDSA_P384#Microsoft Software Key Storage Provider'", "'ECDSA_P384#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P384#SafeNet Key Storage Provider'", "'ECDH_P384#SafeNet Key Storage Provider'")
                521  = @("'ECDSA_P521#Microsoft Software Key Storage Provider'", "'ECDSA_P521#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P521#SafeNet Key Storage Provider'", "'ECDH_P521#SafeNet Key Storage Provider'")

                512  = @("'RSA#Microsoft Software Key Storage Provider'")
                1024 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
                2048 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
                4096 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
            }
            SHA512 =
            @{
                256  = @("'ECDSA_P256#Microsoft Software Key Storage Provider'", "'ECDSA_P256#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P256#SafeNet Key Storage Provider'", "'ECDH_P256#SafeNet Key Storage Provider'")
                384  = @("'ECDSA_P384#Microsoft Software Key Storage Provider'", "'ECDSA_P384#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P384#SafeNet Key Storage Provider'", "'ECDH_P384#SafeNet Key Storage Provider'")
                521  = @("'ECDSA_P521#Microsoft Software Key Storage Provider'", "'ECDSA_P521#Microsoft Smart Card Key Storage Provider'", "'ECDSA_P521#SafeNet Key Storage Provider'", "'ECDH_P521#SafeNet Key Storage Provider'")

                512  = @("'RSA#Microsoft Software Key Storage Provider'")
                1024 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
                2048 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
                4096 = @("'RSA#Microsoft Software Key Storage Provider'", "'RSA#Microsoft Smart Card Key Storage Provider'", "'RSA#SafeNet Key Storage Provider'")
            }
        }.Item($HashAlgorithmName).Item($KeyLength)
    })]
    [String]$CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider',
    [String]$CustomCryptoProviderName,
       [Int]$CustomCryptoProviderType,

    # Default generic lazy pswd
    $CertFilePassword = (ConvertTo-SecureString -String 'e72d4D6wYweyLS4sIAuKOif5TUlJjEpB' -AsPlainText -Force),

    # Switches
    [Switch]$ReuseKeys,
    [Switch]$ConvertCryptoProvider,
    [Switch]$ExportCertificate
)

Begin
{
    # ██████╗ ███████╗ ██████╗ ██╗███╗   ██╗
    # ██╔══██╗██╔════╝██╔════╝ ██║████╗  ██║
    # ██████╔╝█████╗  ██║  ███╗██║██╔██╗ ██║
    # ██╔══██╗██╔══╝  ██║   ██║██║██║╚██╗██║
    # ██████╔╝███████╗╚██████╔╝██║██║ ╚████║
    # ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝

    ######################
    # Validate parameters
    ######################

    # Get valid key lenghts from argumentcompleter scriptblock
    $ValidKeyLengths = Invoke-Command -ScriptBlock $MyInvocation.MyCommand.Parameters.Item("KeyLength").Attributes.ScriptBlock -ArgumentList @($null, $null, $null, $null, @{ HashAlgorithmName = $HashAlgorithmName })

    # Check if valid key length
    if ($KeyLength -notin $ValidKeyLengths)
    {
        throw "Invalid KeyLength $KeyLength, valid key lengths for $HashAlgorithmName is $ValidKeyLengths"
    }

    # Get valid crypto providers from argumentcompleter scriptblock
    $ValidCryptoProviderNames = Invoke-Command -ScriptBlock $MyInvocation.MyCommand.Parameters.Item("CryptoProviderName").Attributes.ScriptBlock -ArgumentList @($null, $null, $null, $null, @{ HashAlgorithmName = $HashAlgorithmName; KeyLength = $KeyLength })

    # Check if valid crypto provider
    if ("'$CryptoProviderName'" -notin $ValidCryptoProviderNames)
    {
        throw "Invalid CryptoProviderName `"$CryptoProviderName`", valid providers for $HashAlgorithmName/$KeyLength is $ValidCryptoProviderNames"
    }

    ##############
    # Deserialize
    ##############

    $Serializable =
    @(
        @{ Name = 'Session';                                  },
        @{ Name = 'Credential';         Type = [PSCredential] },
        @{ Name = 'CertFilePassword';   Type = [SecureString] }
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

    #####################
    # Get response files
    #####################

    # Initialize
    $CerFiles = @{}

    # Itterate all parent ca files
    foreach($file in (Get-Item -Path "$PSScriptRoot\*.cer"))
    {
        # Get file content
        $CerFiles.Add($file, (Get-Content -Path $file.FullName -Raw))
    }


    # ███╗   ███╗ █████╗ ██╗███╗   ██╗
    # ████╗ ████║██╔══██╗██║████╗  ██║
    # ██╔████╔██║███████║██║██╔██╗ ██║
    # ██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    # ██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    # ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

    $MainScriptBlock =
    {
        # Define restart of service
        $Restart = $false

        # Get configuration
        $Configuration = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\*' -ErrorAction Stop

        # Get common name
        $CACommonName = $Configuration | Select-Object -ExpandProperty CommonName -ErrorAction Stop

        # Get CA type
        $CAType = $Configuration | Select-Object -ExpandProperty CAType -ErrorAction Stop

        # Get CertEnrollDirectory
        $CertEnrollDirectory = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction Stop | Select-Object -ExpandProperty CertEnrollDirectory -ErrorAction SilentlyContinue

        # Check CertEnrollDirectory
        if (-not $CertEnrollDirectory)
        {
            # Set default CertEnrollDirectory
            $CertEnrollDirectory = "$env:SystemRoot\System32\CertSrv\CertEnroll"
        }

        # Get CA certificate hash from file
        $CACertHash = TryCatch { certutil -dump "`"$((Get-Item -Path "$CertEnrollDirectory\*.crt" | Where-Object { $_.Name -match ".*$CACommonName(?:\(\d\))?\.crt" } | Sort-Object -Property LastWriteTime | Select-Object -Last 1).FullName)`"" } -ErrorAction Stop | Where-Object {
            $_ -match "^Cert\sHash\(sha1\):\s(.*)$"
        } | ForEach-Object { "$($Matches[1])" }

        # Convert secure string to string
        $CertFilePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertFilePassword))

        #########################
        # CSP\Provider
        # EncryptionCSP\Provider
        #########################

        # Check custom crypto provider name
        if ($CustomCryptoProviderName)
        {
            # Set custom crypto provider name
            $CryptoProviderName = $CustomCryptoProviderName
        }

        # Get provider
        $ProviderName = $CryptoProviderName | Where-Object { $_ -match "(?:.*#|^)(.*)" } | ForEach-Object { $Matches[1] }

        # Get CA provider
        $CAProvider = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\*\CSP" | Select-Object -ExpandProperty Provider

        # Change provider
        if ($ProviderName -ne $CAProvider)
        {
            if ($ConvertCryptoProvider.IsPresent)
            {
                if ((Read-Host "Procceed converting cryptographic provider? [y/n]") -ne 'y')
                {
                    break
                }

                # Get temp
                $Temp = $env:TEMP

                if (-not (Test-Path -Path "$CertEnrollDirectory\$CACommonName.p12") -and
                    (ShouldProcess @WhatIfSplat -Message "Backing up CA private key to `"$CertEnrollDirectory\$CACommonName.p12`"" @VerboseSplat))
                {
                    TryCatch { certutil -p $CertFilePassword -backupkey "$CertEnrollDirectory" } -ErrorAction Stop > $null
                }

                if ((Test-Path -Path "$Temp\$CACommonName.p12") -and
                    (ShouldProcess @WhatIfSplat -Message "Importing CA certificate as `"$ProviderName`"." @VerboseSplat))
                {
                    TryCatch { certutil -f -p $CertFilePassword -csp "$ProviderName" -importpfx "$CertEnrollDirectory\$CACommonName.p12" } -ErrorAction Stop > $null
                }

                if (-not (Test-Path -Path "$Temp\$CACommonName.pfx") -and
                    (ShouldProcess @WhatIfSplat -Message "Exporting CA certificate." @VerboseSplat))
                {
                    TryCatch { certutil -p $CertFilePassword -exportpfx my $CACertHash "$Temp\$CACommonName.pfx" } -ErrorAction Stop > $null
                }

                Remove-Item -Path "Cert:\LocalMachine\My\$CACertHash" -DeleteKey
                Remove-Key -CACommonName $CACommonName @VerboseSplat

                if ((Test-Path -Path "$Temp\$CACommonName.pfx") -and
                    (ShouldProcess @WhatIfSplat -Message "Restoring CA certificate." @VerboseSplat))
                {
                    TryCatch { certutil -f -p $CertFilePassword -restorekey "$Temp\$CACommonName.pfx" } -ErrorAction Stop > $null
                }

                # Cleanup
                Remove-Item -Path "$Temp\$CACommonName.pfx" -Force

                $Restart = $true
            }

            $Restart = Set-CASetting -Key 'CSP\Provider' -Value $ProviderName -InputFlag $Restart
            $Restart = Set-CASetting -Key 'EncryptionCSP\Provider' -Value $ProviderName -InputFlag $Restart
        }

        #############################
        # CSP\ProviderType
        # EncryptionCSP\ProviderType
        #############################

        # FIX
        # get from certutil -csplist

        # Set provider type depending on provider
        switch -regex ($ProviderName)
        {
            'Key Storage Provider'
            {
                $ProviderType = 0
            }
            'DSS'
            {
                $ProviderType = 3
            }
            Default
            {
                $ProviderType = 1
            }
        }

        # Check custom crypto provider type
        if ($CustomCryptoProviderType)
        {
            # Set custom crypto provider type
            $ProviderType = $CustomCryptoProviderType
        }

        # Set provider type
        $Restart = Set-CASetting -Key 'CSP\ProviderType' -Value $ProviderType -InputFlag $Restart
        $Restart = Set-CASetting -Key 'EncryptionCSP\ProviderType' -Value $ProviderType -InputFlag $Restart

        ####################
        # CSP\HashAlgorithm
        ####################

        # Define hash algorithms
        $HashAlgorithms =
        @{
            'MD2'    = '32769'
            'MD4'    = '32770'
            'MD5'    = '32771'
            'SHA1'   = '32772'
            'SHA256' = '0xffffffff'
            'SHA384' = '0xffffffff'
            'SHA512' = '0xffffffff'
        }

        # Set hash algorithm
        $Restart = Set-CASetting -Key 'CSP\HashAlgorithm' -Value $HashAlgorithms.Item($HashAlgorithmName) -InputFlag $Restart

        ########################################
        # CSP\CNGHashAlgorithm
        # CSP\CNGPublicKeyAlgorithm
        # EncryptionCSP\CNGPublicKeyAlgorithm
        # EncryptionCSP\CNGEncryptionAlgorithm
        # EncryptionCSP\SymmetricKeySize
        ########################################

        # Get algorithm
        $ProviderAlgorithm = $CryptoProviderName | Where-Object { $_ -match "(.*)#" } | ForEach-Object { $Matches[1] }

        # Set values depending on algorithm
        switch -regex ($ProviderAlgorithm)
        {
            'ECDSA_P256'
            {
                $CNGPublicKeyAlgorithm  = 'ECDH_P256'
                $CNGEncryptionAlgorithm = 'AES'
                $SymmetricKeySize       = 128
            }
            'ECDSA_P384'
            {
                $CNGPublicKeyAlgorithm  = 'ECDH_P384'
                $CNGEncryptionAlgorithm = 'AES'
                $SymmetricKeySize       = 256
            }
            'ECDSA_P521'
            {
                $CNGPublicKeyAlgorithm  = 'ECDH_P521'
                $CNGEncryptionAlgorithm = 'AES'
                $SymmetricKeySize       = 256
            }
            default
            {
                $CNGPublicKeyAlgorithm  = 'RSA'
                $CNGEncryptionAlgorithm = '3DES'
                $SymmetricKeySize       = 168
            }
        }

        # Values to set if ksp
        $PropertySplats =
        @(
            @{ Key = 'CSP\CNGHashAlgorithm';                  Value = $HashAlgorithmName; }
            @{ Key = 'CSP\CNGPublicKeyAlgorithm';             Value = $ProviderAlgorithm; }

            @{ Key = 'EncryptionCSP\CNGPublicKeyAlgorithm';   Value = $CNGPublicKeyAlgorithm; }
            @{ Key = 'EncryptionCSP\CNGEncryptionAlgorithm';  Value = $CNGEncryptionAlgorithm; }
            @{ Key = 'EncryptionCSP\SymmetricKeySize';        Value = $SymmetricKeySize; }
        )

        # Check if csp
        $Csp = $ProviderName -notmatch 'Key Storage Provider'

        foreach($Splat in $PropertySplats)
        {
            # Remove values if csp
            if ($Csp)
            {
                $Splat.Add('Remove', $true)
                $Splat.Remove('Value')
            }

            $Restart = Set-CASetting @Splat -InputFlag $Restart
        }

        ####################################
        # EncryptionCSP\EncryptionAlgorithm
        # EncryptionCSP\KeySize
        ####################################

        # Check if elliptic curve
        if ($ProviderAlgorithm -match 'ECDSA')
        {
            $EncryptionAlgorithm = '0xffffffff'
            $KeySize = $KeyLength
        }
        else
        {
            $EncryptionAlgorithm = 26115
            $KeySize = 2048
        }

        $Restart = Set-CASetting -Key 'EncryptionCSP\EncryptionAlgorithm' -Value $EncryptionAlgorithm -InputFlag $Restart
        $Restart = Set-CASetting -Key 'EncryptionCSP\KeySize' -Value $KeySize -InputFlag $Restart

        ########
        # Renew
        ########

        # FIX
        # get keylength from Cert:\

        # FIX
        # restart before renew

        # FIX
        # add RenewalValidityPeriodUnits & RenewalValidityPeriod=years to CAPolicy.inf

        $CAKeyLength = $KeyLength

        if (($KeyLength -ne $CAKeyLength -or $Force.IsPresent) -and
            (ShouldProcess @WhatIfSplat -Message "Renewing CA certificate." @VerboseSplat))
        {
            # Check if parent CA certificate request exist
            if (Test-Path -Path "$CertEnrollDirectory\*.csr")
            {
                ######################
                # Get csr key id hash
                ######################

                $CsrKeyIdHash = (certutil -dump "$(Get-Item -Path "$CertEnrollDirectory\*.csr" | Select-Object -First 1 -ExpandProperty FullName)") | Where-Object {
                    $_ -match "Key Id Hash\(sha1\): (.*)"
                } | ForEach-Object { "$($Matches[1])" }

                #####################
                # Set response files
                #####################

                # Itterate all files
                foreach($file in $CerFiles.GetEnumerator())
                {
                    # Set file to temp
                    Set-Content -Path "$env:TEMP\$($file.Key.Name)" -Value $file.Value -Force

                    # Check key id hash
                    if ($CsrKeyIdHash -eq ((certutil -dump "$env:TEMP\$($file.Key.Name)") | Where-Object {
                            $_ -match "Key Id Hash\(sha1\): (.*)"
                        } | ForEach-Object { "$($Matches[1])" }))
                    {
                        # Matching key id
                        $ParentCAResponseFilePath = "$env:TEMP\$($file.Key.Name)"
                    }
                    else
                    {
                        # Remove other files
                        Remove-Item -Path "$env:TEMP\$($file.Key.Name)"
                    }
                }

                # Check if response file matched
                if ($ParentCAResponseFilePath -and
                    (ShouldProcess @WhatIfSplat -Message "Installing CA certificate..." @VerboseSplat))
                {
                    #  ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗      ██████╗███████╗██████╗ ████████╗
                    #  ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     ██╔════╝██╔════╝██╔══██╗╚══██╔══╝
                    #  ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     ██║     █████╗  ██████╔╝   ██║
                    #  ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     ██║     ██╔══╝  ██╔══██╗   ██║
                    #  ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗╚██████╗███████╗██║  ██║   ██║
                    #  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝

                    # Try installing certificate
                    TryCatch { certutil -f -installcert "`"$ParentCAResponseFilePath`"" } -ErrorAction Stop > $null

                    Restart-CertSvc

                    # Give CA some time to create certificate and crl
                    Start-Sleep -Seconds 3

                    # Cleanup
                    Remove-Item -Path "$CertEnrollDirectory\*.csr"
                    Remove-Item -Path "$ParentCAResponseFilePath"
                }
                else
                {
                    # Output requestfile
                    Write-Request -Path $CertEnrollDirectory
                    return
                }
            }
            else
            {
                # ██████╗ ███████╗███╗   ██╗███████╗██╗    ██╗ ██████╗███████╗██████╗ ████████╗
                # ██╔══██╗██╔════╝████╗  ██║██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗╚══██╔══╝
                # ██████╔╝█████╗  ██╔██╗ ██║█████╗  ██║ █╗ ██║██║     █████╗  ██████╔╝   ██║
                # ██╔══██╗██╔══╝  ██║╚██╗██║██╔══╝  ██║███╗██║██║     ██╔══╝  ██╔══██╗   ██║
                # ██║  ██║███████╗██║ ╚████║███████╗╚███╔███╔╝╚██████╗███████╗██║  ██║   ██║

                # FIX
                # set keylength in capolicy.inf

                $RenewArguments = "-f -renewcert"

                # Check if to reuse keys
                if ($ReuseKeys.IsPresent)
                {
                    Write-Warning -Message "Reusing CA certificate keys."
                    $RenewArguments += " reusekeys"
                }

                if ((Read-Host "Procceed? [y/n]") -ne 'y')
                {
                    break
                }

                # Renew
                $Process = Start-Process -FilePath "$env:SystemRoot\System32\certutil.exe" -NoNewWindow -ArgumentList $RenewArguments -PassThru

                # Kill certutil gui popup
                Start-Sleep -Seconds 3
                Stop-Process -InputObject $Process

                # CAType enum
                # https://docs.microsoft.com/gl-es/windows/win32/api/certsrv/ne-certsrv-enum_catypes
                if ($CAType -in @(1,3))
                {
                    # Restart service
                    $Restart = $true
                }
                elseif ($CAType -in @(2,4))
                {
                    # Output requestfile
                    Write-Request -Path $CertEnrollDirectory
                    break
                }
            }
        }

        ##########
        # Restart
        ##########

        if ($Restart)
        {
            Restart-CertSvc
        }

        #  ██████╗███████╗██████╗ ████████╗███████╗███╗   ██╗██████╗  ██████╗ ██╗     ██╗
        # ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔════╝████╗  ██║██╔══██╗██╔═══██╗██║     ██║
        # ██║     █████╗  ██████╔╝   ██║   █████╗  ██╔██╗ ██║██████╔╝██║   ██║██║     ██║
        # ██║     ██╔══╝  ██╔══██╗   ██║   ██╔══╝  ██║╚██╗██║██╔══██╗██║   ██║██║     ██║
        # ╚██████╗███████╗██║  ██║   ██║   ███████╗██║ ╚████║██║  ██║╚██████╔╝███████╗███████╗
        #  ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝

        if ($CertEnrollDirectory -ne "$env:SystemRoot\System32\CertSrv\CertEnroll")
        {
            # Itterate all files under certenroll
            foreach($file in (Get-Item -Path "$env:SystemRoot\System32\CertSrv\CertEnroll\*" -ErrorAction SilentlyContinue))
            {
                switch($file.Extension)
                {
                    '.crt'
                    {
                        $FileName = $file.Name | Where-Object {
                            $_ -match ".*($CACommonName.*\.crt)"
                        } | ForEach-Object { "$($Matches[1])" }
                    }
                    '.crl'
                    {
                        $FileName = $file.Name
                    }
                }

                Copy-DifferentItem -SourcePath $file.FullName -TargetPath "$CertEnrollDirectory\$FileName" @VerboseSplat
            }
        }

        # ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███╗   ██╗
        # ██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║
        # ██████╔╝█████╗     ██║   ██║   ██║██████╔╝██╔██╗ ██║
        # ██╔══██╗██╔══╝     ██║   ██║   ██║██╔══██╗██║╚██╗██║
        # ██║  ██║███████╗   ██║   ╚██████╔╝██║  ██║██║ ╚████║
        # ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

        # Initialize result
        $Result = @{}

        # Itterate CA files under certenroll
        foreach($file in (Get-Item -Path "$CertEnrollDirectory\*$CACommonName*" -ErrorAction SilentlyContinue))
        {
            $Result.Add($file, (Get-Content -Path $file.FullName -Raw))
        }

        if ($ExportCertificate.IsPresent)
        {
            # Export CA certificate
            TryCatch { certutil -p $CertFilePassword -backupkey "$env:TEMP" } -ErrorAction Stop > $null

            # Inform
            Write-Warning -Message "Using password `"$CertFilePassword`" for `"$CACommonName.p12`""

            # Get p12
            $CACertificateP12 = Get-Item -Path "$env:TEMP\$CACommonName.p12"

            # Add result
            $Result.Add($CACertificateP12, (Get-Content -Path $CACertificateP12.FullName -Raw))

            # Cleanup
            Remove-Item -Path "$env:TEMP\$CACommonName.p12"
        }

        # Return
        Write-Output -InputObject $Result
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
            . $PSScriptRoot\f_TryCatch.ps1
            . $PSScriptRoot\f_ShouldProcess.ps1
            . $PSScriptRoot\f_CopyDifferentItem.ps1
            . $PSScriptRoot\f_CheckContinue.ps1
        }
        catch [Exception]
        {
            throw $_
        }

    } -NoNewScope

    # Remote
    if ($Session)
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CheckContinue.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetCASetting.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_RemoveKey.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_RestartCertSvc.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_WriteRequest.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            # Crypto params
            $HashAlgorithmName = $Using:HashAlgorithmName
            $KeyLength = $Using:KeyLength
            $CryptoProviderName = $Using:CryptoProviderName
            $CustomCryptoProviderName = $Using:CustomCryptoProviderName
            $CustomCryptoProviderType = $Using:CustomCryptoProviderType

            # Default generic lazy pswd
            $CertFilePassword = $Using:CertFilePassword

            # Switches
            $ReuseKeys = $Using:ReuseKeys
            $ConvertCryptoProvider = $Using:ConvertCryptoProvider
            $ExportCertificate = $Using:ExportCertificate

            $CerFiles = $Using:CerFiles
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
                . $PSScriptRoot\f_SetCASetting.ps1
                . $PSScriptRoot\f_RemoveKey.ps1
                . $PSScriptRoot\f_RestartCertSvc.ps1
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

                if ($file.Key.Extension -eq '.crt' -or $file.Key.Extension -eq '.crl')
                {
                    # Convert to base 64
                    TryCatch { certutil -f -encode "$env:TEMP\$($file.Key.Name)" "$env:TEMP\$($file.Key.Name)" } > $null
                }

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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDfCe2MhragYALZGxZpSFFA2D
# ZsSggg8yMIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUORaI9lxg2dtcUtkvm2E7LUdPWWQwDQYJ
# KoZIhvcNAQEBBQAEggIAMsatqmWCsgN6Yu+XxaU34V8klJQBtumZoGVDzHoPoAWN
# Fd3GYrbH7QTWPakgL+P0lJ+w7Txt6h9/2VkVkGsB1zv5dOY0neuuOrQW6BwSP6uN
# v4OcIliamh2aBjAKAkdBwC5ssBINLCEXwq6iYBdBfEpXt5sjGZWh+I2TCQYnkhwB
# ye2Eh7fuILbW5NMuX2yfxFTdRsiZ9B+Xj22FurG4/vlO61/3VdamC+vdpyFwev73
# VgIbw4tOJWCP3SfC4B8/NH4WvZQNvMCu0cUGvmaAZrTLYbLjpWVy8ZAGi92/QEmG
# 3OGs4Pxn78OpNqCHGdgIIdQNknKelKgr0UgoYhPoV6WsyPSALs6wI+qfM2jVesz1
# sLI35CJVPyStrKnrjA96FzwXSrZo/c+SJ++c6+miSH0RnPjp4QyPTLl3pXV5uKhs
# GN6G4ppOWqBJsJHZ/NdeFkF7ISXzYRwspcDRUbVHqzTADN4mwmVGzfgQ02j2OhdP
# hOykUVoE/LsPnwbNHMZ35rMQlIuZ4V+jk1JLhKbsOO/OCFFJ3GWGhsyYMZAi/fF2
# 4q7SZ5V0RTuDBkWdZmKau+Jy+JBJY7tta/em51y8Y48SUlSumZI0DuuD7eFzo2bD
# ntDH5KzOLgcxbMYibef8VZjAy/+FCLkRHHPt9ONGtbSEoEnqCGKqM1qQ4AWyD++h
# ggIwMIICLAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGlu
# ZyBDQQIQDUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDYxMTExMDAwMlow
# LwYJKoZIhvcNAQkEMSIEIHCFfNJEskCh/PFPsVm4R60TUw8O6W5R2RmlK97Fh7wQ
# MA0GCSqGSIb3DQEBAQUABIIBAL6sqtQ97oZmXJZ8OqPEjITlrc/dWQBtcXY3C0iB
# +xi+Qo43u0LfET+X99mbnuZDghljRvc94kv11ZKJrwAfLgSsb/xDzkp66gmyGorl
# oDTxRJlE0LE1H5oa6wgvZ3fxDuLZUyGbimSkeZMIguyMxbXzhZB7I4EeT4wcQx45
# sYFq/5FrrnIm34h3BkeBjACN8hHfpt1+fBHiTBWgQj1tZEkEmLJbboL9icemoR2n
# tyrudnsDz/wHo5bvSSjScgaiDrX6H/eas83ySUiPjw9eCfxucAUi2Z49XWAAh/A9
# y3mPAgVLFxDXhq0ksu/J7G84/RRydfBzwEzuQNaXk2Q7f3I=
# SIG # End signature block
