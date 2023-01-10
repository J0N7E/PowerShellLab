<#
 .DESCRIPTION
    Setup and configure Certificate Authority
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
    # Always prompt
    [Switch]$AlwaysPrompt,

    # Serializable parameters
    $Session,
    $Credential,

    # CAType
    [Parameter(ParameterSetName='CertFile_StandaloneRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA', Mandatory=$true)]
    [Switch]$StandaloneRootCA,

    [Parameter(ParameterSetName='CertFile_EnterpriseSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA', Mandatory=$true)]
    [Switch]$EnterpriseSubordinateCA,

    [Parameter(ParameterSetName='CertFile_EnterpriseRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA', Mandatory=$true)]
    [Switch]$EnterpriseRootCA,

    [Parameter(ParameterSetName='CertFile_StandaloneSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA', Mandatory=$true)]
    [Switch]$StandaloneSubordinateCA,

    # Path to certfile
    [Parameter(ParameterSetName='CertFile_EnterpriseRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='CertFile_StandaloneRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='CertFile_EnterpriseSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='CertFile_StandaloneSubordinateCA', Mandatory=$true)]
    [String]$CertFile,

    # Default generic lazy pswd
    [Parameter(ParameterSetName='CertFile_EnterpriseRootCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneRootCA')]
    [Parameter(ParameterSetName='CertFile_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneSubordinateCA')]
    $CertFilePassword = (ConvertTo-SecureString -String 'e72d4D6wYweyLS4sIAuKOif5TUlJjEpB' -AsPlainText -Force),

    # Certificate Key Container Name
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA', Mandatory=$true)]
    [String]$KeyContainerName,

    # Certificate Authority CN
    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA', Mandatory=$true)]
    [String]$CACommonName,

    # Ignore Unicode
    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA')]
    [Switch]$IgnoreUnicode,

    # DN Suffix
    [String]$CADistinguishedNameSuffix,

    # Policy OID
    [Parameter(ParameterSetName='CertFile_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA')]
    [String]$PolicyOID = '2.5.29.32.0',

    # Policy URL
    [Parameter(ParameterSetName='CertFile_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA')]
    [String]$PolicyURL,

    [String]$CAPolicy,

    # Root CA certificate validity period units
    [Parameter(ParameterSetName='CertFile_EnterpriseRootCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA')]
    [String]$RootValidityPeriodUnits = '20',

    # Root CA certificate validity period
    [Parameter(ParameterSetName='CertFile_EnterpriseRootCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA')]
    [ValidateSet('Hours', 'Days', 'Weeks', 'Months', 'Years')]
    [String]$RootValidityPeriod = 'Years',

    # Parent CA CN
    # FIX remove parameter for Enterprise CA
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA', Mandatory=$true)]
    [String]$ParentCACommonName,

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

    # Crypto provider name
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

    # FIX add custom provider
    #[String]$CustomCryptoProviderName,
    #   [Int]$CustomCryptoProviderType,

    # Path length
    [String]$PathLength,

    # Directory locations
    # https://www.sysadmins.lv/blog-en/install-adcscertificationauthority-issue-when-installing-an-offline-certification-authority.aspx
    [String]$LogDirectory = '$env:SystemRoot\System32\CertLog',
    [String]$DatabaseDirectory = '$env:SystemRoot\System32\CertLog',
    [String]$CertEnrollDirectory = '$env:SystemDrive\CertSrv\CertEnroll',

    # Validity period of issued certificates
    [String]$ValidityPeriodUnits,
    [ValidateSet('Hours', 'Days', 'Weeks', 'Months', 'Years')]
    [String]$ValidityPeriod,

    # Set host for OCSP
    [String]$OCSPHost,

    # Set host for AIA
    [String]$AIAHost,

    # Set host for CDP
    [String]$CDPHost,

    # Crl publishing locations
    [Array]$CRLPublishAdditionalPaths,

    # Crl Distribution Point (CDP)
    [String]$CRLPublicationURLs,

    # Authority Information Access (AIA)
    [String]$CACertPublicationURLs,

    # CRL settings
    [String]$CRLPeriodUnits,
    [ValidateSet('Hours', 'Days', 'Weeks', 'Months', 'Years')]
    [String]$CRLPeriod,

    [String]$CRLOverlapUnits,
    [ValidateSet('Minutes', 'Hours', 'Days', 'Weeks', 'Months', 'Years')]
    [String]$CRLOverlapPeriod,

    [String]$CRLDeltaPeriodUnits,
    [ValidateSet('Hours', 'Days', 'Weeks', 'Months', 'Years')]
    [String]$CRLDeltaPeriod,

    [String]$CRLDeltaOverlapUnits,
    [ValidateSet('Minutes', 'Hours', 'Days', 'Weeks', 'Months', 'Years')]
    [String]$CRLDeltaOverlapPeriod,

    # Set log level
    [String]$AuditFilter = 127,

    # DSConfigDN / DSDomainDN
    [Parameter(ParameterSetName='CertFile_StandaloneRootCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA')]
    [String]$AddDomainConfig,

    ###########
    # Switches
    ###########

    [Switch]$UseDefaultSettings,
    [Switch]$UsePolicyNameConstraints,

    [Parameter(ParameterSetName='CertFile_EnterpriseRootCA')]
    [Parameter(ParameterSetName='CertFile_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA')]
    [Switch]$PublishTemplates,

    [Switch]$PublishCRL,
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

    ##############
    # Deserialize
    ##############

    $Serializable =
    @(
        @{ Name = 'Session';                                         },
        @{ Name = 'Credential';                Type = [PSCredential] },
        @{ Name = 'CertFilePassword';          Type = [SecureString] },
        @{ Name = 'CRLPublishAdditionalPaths'; Type = [Array]        }
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
            throw "$_ $( $_.ScriptStackTrace)"
        }

    } -NoNewScope

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
    # Set CA Type
    ##############

    if ($StandaloneRootCA.IsPresent)
    {
        $CAType = 'StandaloneRootCA'
    }
    elseif ($EnterpriseSubordinateCA.IsPresent)
    {
        $CAType = 'EnterpriseSubordinateCA'
    }
    elseif ($EnterpriseRootCA.IsPresent)
    {
        $CAType = 'EnterpriseRootCA'
    }
    elseif ($StandaloneSubordinateCA.IsPresent)
    {
        $CAType = 'StandaloneSubordinateCA'
    }

    #######################
    # Get ParameterSetName
    #######################

    $ParameterSetName = $PsCmdlet.ParameterSetName

    ######################
    # Get parent ca files
    ######################

    # Initialize
    $ParentCAFiles = @{}
    $ParentCAResponseFiles = @{}

    if ($ParameterSetName -match 'NewKey.*Subordinate')
    {
        # Itterate all posbile parent ca files
        foreach($file in (Get-Item -Path "$PSScriptRoot\*.cer"))
        {
            $CertutilDump = (certutil -dump $file) | Out-String

            ######################
            # Get parent response
            # for Subordinate CA
            ######################

            if (Test-Path -Path "$PSScriptRoot\$CACommonName-Request*.csr")
            {
                # Check issuer
                if ($CACommonName -eq ($CertutilDump | Where-Object {
                        $_ -match "Subject:\r\n.*CN=(.*)\r\n"
                    } | ForEach-Object { "$($Matches[1])" }) -and

                    $ParentCACommonName -eq ($CertutilDump | Where-Object {
                        $_ -match "Issuer:\r\n.*CN=(.*)\r\n"
                    } | ForEach-Object { "$($Matches[1])" }))
                {
                    Write-Verbose -Message "Getting parent CA response file: $($file.Name)" @VerboseSplat

                    # Get file content
                    $ParentCAResponseFiles.Add($file, (Get-Content -Path $file.FullName -Raw))
                }
            }

            #########################
            # Get parent certificate
            # for Standalone CA
            #########################

            if ($ParameterSetName -eq 'NewKey_StandaloneSubordinateCA')
            {
                # Check subject
                if ($ParentCACommonName -eq ($CertutilDump | Where-Object {
                        $_ -match "Subject:\r\n.*CN=(.*)\r\n"
                    } | ForEach-Object { "$($Matches[1])" }))
                {
                    Write-Verbose -Message "Getting parent CA certificate: $($file.Name)" @VerboseSplat

                    # Get file content
                    $ParentCAFiles.Add($file, (Get-Content -Path $file.FullName -Raw))
                }
            }
        }

        ###########################
        # Check parent certificate
        # for Standalone CA
        ###########################

        if ($ParameterSetName -eq 'NewKey_StandaloneSubordinateCA')
        {
            # Check if not found
            if ($ParentCAFiles -eq 0)
            {
                throw "No parent certificate for `"$ParentCACommonName`" found, aborting..."
            }
        }
    }

    ###########
    # CertFile
    ###########

    if ($ParameterSetName -match 'CertFile' -and
        (Test-Path -Path $CertFile -ErrorAction SilentlyContinue))
    {
        $CertFile = Get-Content -Path $CertFile -Raw
    }

    # ██████╗ ██████╗ ███████╗███████╗███████╗████████╗███████╗
    # ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔════╝
    # ██████╔╝██████╔╝█████╗  ███████╗█████╗     ██║   ███████╗
    # ██╔═══╝ ██╔══██╗██╔══╝  ╚════██║██╔══╝     ██║   ╚════██║
    # ██║     ██║  ██║███████╗███████║███████╗   ██║   ███████║
    # ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝   ╚══════╝

    $Preset =
    @{
        StandaloneRootCA =
        @{
            # CAPolicy parameters
            PathLength = 'None'

            # Validity period of issued certificates    # Default
            ValidityPeriodUnits = 10                    # 1
            ValidityPeriod = 'Years'

            # CRL settings                              # Default
            CRLPeriodUnits = 180                        # 1
            CRLPeriod = 'Days'                          # Weeks
            CRLOverlapUnits = 14                        # 0
            CRLOverlapPeriod = 'Days'                   # Hours
            CRLDeltaPeriodUnits = 0
            CRLDeltaPeriod = 'Days'
            CRLDeltaOverlapUnits = 0
            CRLDeltaOverlapPeriod = 'Minutes'
        }

        EnterpriseRootCA =
        @{
            # CAPolicy parameters
            PathLength = 0

            # Validity period of issued certificates
            ValidityPeriodUnits = 1
            ValidityPeriod = 'Years'

            # CRL settings
            CRLPeriodUnits = 1
            CRLPeriod = 'Weeks'
            CRLOverlapUnits = 84
            CRLOverlapPeriod = 'Hours'
            CRLDeltaPeriodUnits = 0
            CRLDeltaPeriod = 'Days'
            CRLDeltaOverlapUnits = 0
            CRLDeltaOverlapPeriod = 'Minutes'
        }

        EnterpriseSubordinateCA =
        @{
            # CAPolicy parameters
            PathLength = 0

            # Validity period of issued certificates
            ValidityPeriodUnits = 1
            ValidityPeriod = 'Years'

            # CRL settings
            CRLPeriodUnits = 1
            CRLPeriod = 'Weeks'
            CRLOverlapUnits = 84
            CRLOverlapPeriod = 'Hours'
            CRLDeltaPeriodUnits = 0
            CRLDeltaPeriod = 'Days'
            CRLDeltaOverlapUnits = 0
            CRLDeltaOverlapPeriod = 'Minutes'
        }

        StandaloneSubordinateCA =
        @{
            # CAPolicy parameters
            PathLength = 0

            # Validity period of issued certificates
            ValidityPeriodUnits = 1
            ValidityPeriod = 'Years'

            # CRL settings                              # Default
            CRLPeriodUnits = 1
            CRLPeriod = 'Weeks'
            CRLOverlapUnits = 84                        # 0
            CRLOverlapPeriod = 'Hours'
            CRLDeltaPeriodUnits = 0                     # 1
            CRLDeltaPeriod = 'Days'
            CRLDeltaOverlapUnits = 0
            CRLDeltaOverlapPeriod = 'Minutes'
        }
    }

    if (-not $UseDefaultSettings.IsPresent)
    {
        # Set preset values for missing parameters
        foreach ($Var in $MyInvocation.MyCommand.Parameters.Keys)
        {
            if ($Preset.Item($CAType).ContainsKey($Var) -and
                -not (Get-Variable -Name $Var).Value)
            {
                Set-Variable -Name $Var -Value $Preset.Item($CAType).Item($Var)
            }
        }
    }

    # ███╗   ███╗ █████╗ ██╗███╗   ██╗
    # ████╗ ████║██╔══██╗██║████╗  ██║
    # ██╔████╔██║███████║██║██╔██╗ ██║
    # ██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    # ██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    # ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

    $MainScriptBlock =
    {
        # Initialize
        $Result = @{}

        ##############
        # Check admin
        ##############

        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {
            throw "Must be administrator to setup Certficate Authority."
        }

        #####################
        # Check installation
        #####################

        # Initialize
        $CAInstalled = $false
        $CAConfigured = $false

        # Check if CA is installed
        if (((Get-WindowsFeature -Name ADCS-Cert-Authority).InstallState -eq 'Installed'))
        {
            # CA is installed
            $CAInstalled = $true

            #Check if CA is configured
            try
            {
                # Throws if configured
                Install-AdcsCertificationAuthority -WhatIf > $null
            }
            catch
            {
                # CA is configured
                $CAConfigured = $true
            }
        }

        ###############
        # Check domain
        ###############

        $Win32ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $PartOfDomain = $Win32ComputerSystem | Select-Object -ExpandProperty PartOfDomain

        # Check for part of domain
        if ($PartOfDomain)
        {
            $DomainName = $Win32ComputerSystem | Select-Object -ExpandProperty Domain
            $DomainNetbiosName = Get-CimInstance -ClassName Win32_NTDomain | Select-Object -ExpandProperty DomainName
        }
        elseif ($ParameterSetName -match 'Enterprise')
        {
            throw "Must be domain joined to setup Enterprise Subordinate CA."
        }
        elseif ($AddDomainConfig)
        {
            $DomainName = $AddDomainConfig
        }
        else
        {
            Check-Continue -Message "-AddDomainConfig parameter not specified, DSDomainDN and DSConfigDN will not be set."
        }

        # Get basedn from domain name
        if ($DomainName)
        {
            $BaseDn = Get-BaseDn -DomainName $DomainName

            if (-not $CAConfigured -and -not $CADistinguishedNameSuffix)
            {
                $CADistinguishedNameSuffix = $BaseDn

                Check-Continue -Message "-CADistinguishedNameSuffix parameter not specified, using default suffix $BaseDn."
            }
        }
        elseif (-not $CAConfigured -and -not $CADistinguishedNameSuffix)
        {
            Check-Continue -Message "-CADistinguishedNameSuffix parameter not specified, no suffix will be used."
        }

        ###################
        # Expand variables
        ###################

        $LogDirectory        = $ExecutionContext.InvokeCommand.ExpandString($LogDirectory)
        $DatabaseDirectory   = $ExecutionContext.InvokeCommand.ExpandString($DatabaseDirectory)
        $CertEnrollDirectory = $ExecutionContext.InvokeCommand.ExpandString($CertEnrollDirectory)


        #  █████╗ ██╗ █████╗     ██╗ ██████╗██████╗ ██████╗
        # ██╔══██╗██║██╔══██╗   ██╔╝██╔════╝██╔══██╗██╔══██╗
        # ███████║██║███████║  ██╔╝ ██║     ██║  ██║██████╔╝
        # ██╔══██║██║██╔══██║ ██╔╝  ██║     ██║  ██║██╔═══╝
        # ██║  ██║██║██║  ██║██╔╝   ╚██████╗██████╔╝██║
        # ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝     ╚═════╝╚═════╝ ╚═╝

        ######
        # AIA
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831574(v=ws.11)#publish-the-aia-extension
        ######

        # Check if exist
        if (-not $CACertPublicationURLs)
        {
            # Set default AIA
            $CACertPublicationURLs = "1:$CertEnrollDirectory\%3%4.crt"

            # Check if exist
            if ($AIAHost)
            {
                # Add AIA url
                $CACertPublicationURLs += "\n2:http://$AIAHost/%3%4.crt"
            }
            elseif ($DomainName)
            {
                Check-Continue -Message "-AIAHost parameter not specified, using `"pki.$DomainName`" as AIAHost."

                # Add default AIA url
                $CACertPublicationURLs += "\n2:http://pki.$DomainName/%3%4.crt"
            }
            else
            {
                Check-Continue -Message "-AIAHost parameter not specified, no AIA will be used."
            }

            # Check if exist
            if ($OCSPHost)
            {
                # Add OCSP url
                $CACertPublicationURLs += "\n32:http://$OCSPHost/oscp"
            }
            elseif ($ParameterSetName -match 'Subordinate')
            {
                if ($DomainName)
                {
                    Check-Continue -Message "-OCSPHost parameter not specified, using `"pki.$DomainName/ocsp`" as OCSPHost."

                    # Add default OCSP url
                    $CACertPublicationURLs += "\n32:http://pki.$DomainName/ocsp"
                }
                else
                {
                    Check-Continue -Message "-OCSPHost parameter not specified, no OCSP will be used."
                }
            }
        }

        ######
        # CDP
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831574(v=ws.11)#publish-the-cdp-extension
        ######

        # Check if exist
        if (-not $CRLPublicationURLs)
        {
            ##################
            # PublishToServer
            ##################

            $PublishToServer = 0

            if ($CRLPeriodUnits -gt 0)
            {
                $PublishToServer += 1
            }

            if ($CRLDeltaPeriodUnits -gt 0)
            {
                $PublishToServer += 64
            }

            ##################
            # Set default CDP
            ##################

            $CRLPublicationURLs = "$($PublishToServer):$env:SystemRoot\System32\CertSrv\CertEnroll\%3%8%9.crl"

            if ($CertEnrollDirectory -ne "$env:SystemRoot\System32\CertSrv\CertEnroll")
            {
                # Add custom CertEnroll directory
                $CRLPublicationURLs += "\n$($PublishToServer):$CertEnrollDirectory\%3%8%9.crl"
            }

            ##################
            # AddTo (Include)
            ##################

            $AddTo = 0

            if ($CRLPeriodUnits -gt 0)
            {
                $AddTo += 2
            }

            if ($CRLDeltaPeriodUnits -gt 0)
            {
                $AddTo += 4
            }

            # Check if exist
            if ($CDPHost)
            {
                # Add CDP url
                $CRLPublicationURLs += "\n$($AddTo):http://$CDPHost/%3%8%9.crl"
            }
            elseif ($DomainName)
            {
                Check-Continue -Message "-CDPHost parameter not specified, using `"pki.$DomainName`" as CDPHost."

                # Add default CDP url
                $CRLPublicationURLs += "\n$($AddTo):http://pki.$DomainName/%3%8%9.crl"
            }
            else
            {
                Check-Continue -Message "-CDPHost parameter not specified, no CDP will be used."
            }

            ####################
            # Publish Locations
            ####################

            if ($CRLPublishAdditionalPaths)
            {
                foreach ($Item in $CRLPublishAdditionalPaths)
                {
                    # Add publishing paths
                    $CRLPublicationURLs += "\n$($PublishToServer):$Item\%3%8%9.crl"
                }
            }
            elseif ($ParameterSetName -match 'Subordinate')
            {
                Check-Continue -Message "-CRLPublishAdditionalPaths parameter not specified, CRL will not be published to another server."
            }
        }

        # ██████╗  ██████╗ ██╗     ██╗ ██████╗██╗   ██╗
        # ██╔══██╗██╔═══██╗██║     ██║██╔════╝╚██╗ ██╔╝
        # ██████╔╝██║   ██║██║     ██║██║      ╚████╔╝
        # ██╔═══╝ ██║   ██║██║     ██║██║       ╚██╔╝
        # ██║     ╚██████╔╝███████╗██║╚██████╗   ██║
        # ╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝   ╚═╝

        if (-not $CAConfigured -or $True)
        {
            if ($ParameterSetName -match 'Subordinate')
            {
                if (-not $PolicyURL -and $PolicyOID -ne '2.5.29.32.0' -and $DomainName)
                {
                    Check-Continue -Message "-PolicyURL parameter not specified, using `"http://pki.$DomainName/cps`" as PolicyURL."

                    # Add default AIA url
                    $PolicyURL = "http://pki.$DomainName/cps"
                }
                else
                {
                    Check-Continue -Message "-PolicyURL parameter not specified, no policy url will be used."
                }
            }

            ##################
            # Standalone Root
            ##################

            $CAPolicy_StandaloneRootCA =
            @(
                "[Version]",
                "Signature=`"`$Windows NT$`"",
                "",
                "[BasicConstraintsExtension]",
                "Critical=Yes",
                "",
                "[Certsrv_Server]",
                "RenewalKeyLength=$KeyLength",
                "AlternateSignatureAlgorithm=0"
            )

            if (-not $UseDefaultSettings.IsPresent)
            {
                $CAPolicy_StandaloneRootCA +=
                @(
                    "CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits",
                    "CRLDeltaPeriod=$CRLDeltaPeriod"
                )
            }

            ##################
            # Enterprise Root
            ##################

            $CAPolicy_EnterpriseRootCA =
            @(
                "[Version]",
                "Signature=`"`$Windows NT$`"",
                "",
                "[PolicyStatementExtension]",
                "Policies=AllIssuancePolicy",
                "Critical=No",
                "",
                "[AllIssuancePolicy]",
                "OID=2.5.29.32.0",
                "Notice=`"All Issuance Policy`"",
                "",
                "[BasicConstraintsExtension]",
                "Pathlength=$PathLength",
                "Critical=Yes",
                "",
                "[Certsrv_Server]",
                "RenewalKeyLength=$KeyLength",
                "AlternateSignatureAlgorithm=0",
                "LoadDefaultTemplates=0"
            )

            if (-not $UseDefaultSettings.IsPresent)
            {
                $CAPolicy_EnterpriseRootCA +=
                @(
                    "CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits",
                    "CRLDeltaPeriod=$CRLDeltaPeriod"
                )
            }

            if ($UsePolicyNameConstraints.IsPresent)
            {
                $CAPolicy_EnterpriseRootCA +=
                @(
                    "",
                    "[Strings]",
                    "szOID_NAME_CONSTRAINTS = `"2.5.29.30`"",
                    "",
                    "[Extensions]",
                    "Critical = %szOID_NAME_CONSTRAINTS%",
                    "%szOID_NAME_CONSTRAINTS% = `"{text}`"",
                    "",
                    "_continue_ = `"SubTree=Include&`"",
                    "_continue_ = `"DNS = $DomainName&`"",
                    "_continue_ = `"UPN = @$DomainName&`"",
                    "_continue_ = `"Email = @$DomainName&`"",
                    "_continue_ = `"DirectoryName = $BaseDn&`""
                )
            }

            #########################
            # Enterprise Subordinate
            #########################

            $CAPolicy_EnterpriseSubordinateCA =
            @(
                "[Version]",
                "Signature=`"`$Windows NT$`"",
                "",
                "[PolicyStatementExtension]",
                "Policies=IssuancePolicy",
                "Critical=No",
                "",
                "[IssuancePolicy]",
                "OID=$PolicyOID"
            )

            if ($PolicyURL)
            {
                $CAPolicy_EnterpriseSubordinateCA += @("URL=$PolicyURL")
            }

            $CAPolicy_EnterpriseSubordinateCA +=
            @(
                "",
                "[BasicConstraintsExtension]",
                "Pathlength=$PathLength",
                "Critical=Yes",
                "",
                "[Certsrv_Server]",
                "RenewalKeyLength=$KeyLength",
                "AlternateSignatureAlgorithm=0",
                "LoadDefaultTemplates=0"
            )

            if (-not $UseDefaultSettings.IsPresent)
            {
                $CAPolicy_EnterpriseSubordinateCA +=
                @(
                    "CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits",
                    "CRLDeltaPeriod=$CRLDeltaPeriod"
                )
            }

            if ($UsePolicyNameConstraints.IsPresent)
            {
                $CAPolicy_EnterpriseSubordinateCA +=
                @(
                    "",
                    "[Strings]"
                    "szOID_NAME_CONSTRAINTS = `"2.5.29.30`""
                    "",
                    "[Extensions]",
                    "Critical = %szOID_NAME_CONSTRAINTS%",
                    "%szOID_NAME_CONSTRAINTS% = `"{text}`"",
                    "",
                    "_continue_ = `"SubTree=Include&`"",
                    "_continue_ = `"DNS = $DomainName&`"",
                    "_continue_ = `"UPN = @$DomainName&`"",
                    "_continue_ = `"Email = @$DomainName&`"",
                    "_continue_ = `"DirectoryName = $BaseDn&`""
                )
            }

            #########################
            # Standalone Subordinate
            #########################

            $CAPolicy_StandaloneSubordinateCA =
            @(
                "[Version]",
                "Signature=`"`$Windows NT$`"",
                "",
                "[PolicyStatementExtension]",
                "Policies=AllIssuancePolicy",
                "Critical=No",
                "",
                "[AllIssuancePolicy]",
                "OID=2.5.29.32.0",
                "Notice=`"All Issuance Policy`"",
                "",
                "[BasicConstraintsExtension]",
                "Pathlength=$PathLength",
                "Critical=Yes",
                "",
                "[Certsrv_Server]",
                "RenewalKeyLength=$KeyLength",
                "AlternateSignatureAlgorithm=0"
            )

            if (-not $UseDefaultSettings.IsPresent)
            {
                $CAPolicy_StandaloneSubordinateCA +=
                @(
                    "CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits",
                    "CRLDeltaPeriod=$CRLDeltaPeriod"
                )
            }

            #############
            # Set policy
            #############

            # Save CA policy to temp
            Set-Content -Value (Get-Variable -Name "CAPolicy_$($CAType)").Value -Path "$env:TEMP\CAPolicy.inf"

            # Move to systemroot if different
            Copy-DifferentItem -SourcePath "$env:TEMP\CAPolicy.inf" -Delete -Backup -TargetPath "$env:SystemRoot\CAPolicy.inf" @VerboseSplat
        }

        # ██████╗  ██████╗  ██████╗ ████████╗     ██████╗███████╗██████╗ ████████╗██╗███████╗██╗ ██████╗ █████╗ ████████╗███████╗
        # ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝
        # ██████╔╝██║   ██║██║   ██║   ██║       ██║     █████╗  ██████╔╝   ██║   ██║█████╗  ██║██║     ███████║   ██║   █████╗
        # ██╔══██╗██║   ██║██║   ██║   ██║       ██║     ██╔══╝  ██╔══██╗   ██║   ██║██╔══╝  ██║██║     ██╔══██║   ██║   ██╔══╝
        # ██║  ██║╚██████╔╝╚██████╔╝   ██║       ╚██████╗███████╗██║  ██║   ██║   ██║██║     ██║╚██████╗██║  ██║   ██║   ███████╗
        # ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝        ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

        if ($ParameterSetName -eq 'NewKey_StandaloneSubordinateCA')
        {
            #############
            # Get hashes
            #############

            # Certificate
            $RootCertificateHashArray = TryCatch { certutil -store root "$ParentCACommonName" } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "Cert Hash\(sha1\): (.*)$"
            } | ForEach-Object { "$($Matches[1])" }

            #############
            # Save files
            #############

            # Create temp Directory
            New-Item -ItemType Directory -Path "$env:TEMP" -Name $ParentCACommonName -Force > $null

            # Itterate all files
            foreach($file in $ParentCAFiles.GetEnumerator())
            {
                # Save file to temp
                Set-Content -Path "$env:TEMP\$ParentCACommonName\$($file.Key.Name)" -Value $file.Value -Force

                # Set original timestamps
                Set-ItemProperty -Path "$env:TEMP\$ParentCACommonName\$($file.Key.Name)" -Name CreationTime -Value $file.Key.CreationTime
                Set-ItemProperty -Path "$env:TEMP\$ParentCACommonName\$($file.Key.Name)" -Name LastWriteTime -Value $file.Key.LastWriteTime
                Set-ItemProperty -Path "$env:TEMP\$ParentCACommonName\$($file.Key.Name)" -Name LastAccessTime -Value $file.Key.LastAccessTime
            }

            ######
            # Add
            ######

            # Initialize arrays
            $ParentFileCertificateHashArray = @()

            # Itterate all parent ca files
            foreach($file in (Get-Item -Path "$env:TEMP\$ParentCACommonName\*"))
            {
                # Get CA certificate hash
                $ParentFileCertificateHash = TryCatch { certutil -dump "$($file.FullName)" } -ErrorAction SilentlyContinue | Where-Object {
                    $_ -match "Cert Hash\(sha1\): (.*)"
                } | ForEach-Object { "$($Matches[1])" }

                # Add cert hash to array
                $ParentFileCertificateHashArray += $ParentFileCertificateHash

                # Check if certificate hash is in root store
                if ($ParentFileCertificateHash -notin $RootCertificateHashArray -and
                    (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Name)`" ($ParentFileCertificateHash) to root store." @VerboseSplat))
                {
                    TryCatch { certutil -addstore root "$($file.FullName)" } -ErrorAction Stop > $null
                }
            }

            #########
            # Remove
            #########

            # Certificate
            foreach($CertificateHash in $RootCertificateHashArray)
            {
                if ($CertificateHash -notin $ParentFileCertificateHashArray -and
                    (ShouldProcess @WhatIfSplat -Message "Remove crt ($CertificateHash) from root store." @VerboseSplat))
                {
                    TryCatch { certutil -delstore root "$CertificateHash" } > $null
                }
            }

            ##########
            # Cleanup
            ##########

            # Remove temp directory
            Remove-Item -Path "$env:TEMP\$ParentCACommonName" -Force -Recurse
        }

        # ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗
        # ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║
        # ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║
        # ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║
        # ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
        # ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

        # Check if directories exist
        foreach ($Directory in ($CertEnrollDirectory, $DatabaseDirectory, $LogDirectory))
        {
            if ($Directory -and -not (Test-Path -Path $Directory) -and
                (ShouldProcess @WhatIfSplat -Message "Creating `"$Directory`"" @VerboseSplat))
            {
                New-Item -ItemType Directory -Path $Directory > $null
            }
        }

        # Install CA feature
        if (-not $CAInstalled -and
            (ShouldProcess @WhatIfSplat -Message "Installing ADCS-Cert-Authority." @VerboseSplat))
        {
            Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools -Restart > $null
        }

        #  ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗ ██╗   ██╗██████╗ ███████╗
        # ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ ██║   ██║██╔══██╗██╔════╝
        # ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗██║   ██║██████╔╝█████╗
        # ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║██║   ██║██╔══██╗██╔══╝
        # ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝╚██████╔╝██║  ██║███████╗
        #  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝

        if (-not $CAConfigured)
        {
            # Initialize
            $ADCSCAParams =
            @{
                'CAType' = $CAType
                'AllowAdministratorInteraction' = $true
            }

            # Ignore unicode
            if ($IgnoreUnicode.IsPresent)
            {
                $ADCSCAParams.Add('IgnoreUnicode', $true)
            }

            if ($ParameterSetName -match 'CertFile')
            {
                # Get content
                Set-Content -Path "$env:TEMP\CertFile.p12" -Value $CertFile

                # Certfile parameters
                $ADCSCAParams +=
                @{
                    'CertFilePassword' = $CertFilePassword
                    'CertFile' = "$env:TEMP\CertFile.p12"
                }
            }
            else
            {
                if ($ParameterSetName -match 'KeyContainerName')
                {
                    # KeyContainerName parameters
                    $ADCSCAParams.Add('KeyContainerName', $KeyContainerName)
                }
                else
                {
                    # None keycontainer default parameters
                    $ADCSCAParams +=
                    @{
                        'CACommonName' = $CACommonName
                        'KeyLength' = $KeyLength
                    }
                }

                # Default parameters
                $ADCSCAParams +=
                @{
                    'CryptoProviderName' = $CryptoProviderName
                    'HashAlgorithmName' = $HashAlgorithmName
                }

                if ($CADistinguishedNameSuffix)
                {
                    $ADCSCAParams.Add('CADistinguishedNameSuffix', $CADistinguishedNameSuffix)
                }

                if ($ParameterSetName -match 'Root')
                {
                    $ADCSCAParams +=
                    @{
                        'ValidityPeriod' = $RootValidityPeriod
                        'ValidityPeriodUnits' = $RootValidityPeriodUnits
                    }
                }
                elseif ($ParameterSetName -match 'NewKey.*Subordinate')
                {
                    $ADCSCAParams.Add('OutputCertRequestFile', "$CertEnrollDirectory\$CACommonName-Request.csr")
                }
            }

            if ($DatabaseDirectory)
            {
                $ADCSCAParams.Add('DatabaseDirectory', $DatabaseDirectory)
            }

            if ($LogDirectory)
            {
                $ADCSCAParams.Add('LogDirectory', $LogDirectory)
            }

            #########
            # Verify
            #########

            foreach($Param in $ADCSCAParams.GetEnumerator())
            {
                if ($Param.Value -match " ")
                {
                    $Param.Value = "`"$($Param.Value)`""
                }

                Write-Verbose -Message "-$($Param.Key) $($Param.Value)" @VerboseSplat
            }

            Check-Continue @AlwaysPromptSplat -Message "Proceed with CA setup?"

            ##########
            # Install
            ##########

            try
            {
                if (ShouldProcess @WhatIfSplat -Message "Configuring Certificate Authority." @VerboseSplat)
                {
                    Install-AdcsCertificationAuthority @ADCSCAParams -Force > $null
                }

                if ($ParameterSetName -match 'Root')
                {
                    # Give CA some time to create certificate and crl
                    Start-Sleep -Seconds 3
                }
            }
            catch [Exception]
            {
                if ($_ -notmatch 'The Certification Authority is already installed.')
                {
                    throw $_.Exception
                }
            }
            finally
            {
                if ($CertFile -and (Test-Path -Path "$env:TEMP\CertFile.p12"))
                {
                    Remove-Item -Path "$env:TEMP\CertFile.p12"
                }
            }
        }

        #  ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗      ██████╗███████╗██████╗ ████████╗
        #  ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     ██╔════╝██╔════╝██╔══██╗╚══██╔══╝
        #  ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     ██║     █████╗  ██████╔╝   ██║
        #  ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     ██║     ██╔══╝  ██╔══██╗   ██║
        #  ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗╚██████╗███████╗██║  ██║   ██║
        #  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝

        # Define restart of service
        $Restart = $false

        if ($ParameterSetName -match 'NewKey.*Subordinate')
        {
            $CsrfilePath = "$CertEnrollDirectory\$CACommonName-Request.csr"

            # Check if parent CA certificate request exist
            if (Test-Path -Path $CsrfilePath)
            {
                # Get csr key id hash
                $CsrKeyIdHash = TryCatch { certutil -dump "$(Get-Item -Path `"$CsrfilePath`" | Select-Object -ExpandProperty FullName -First 1)" } -ErrorAction Stop | Where-Object {
                    $_ -match "Key Id Hash\(sha1\): (.*)"
                } | ForEach-Object { "$($Matches[1])" }

                # Itterate all posible response files
                foreach($file in $ParentCAResponseFiles.GetEnumerator())
                {
                    # Set file to temp
                    Set-Content -Path "$env:TEMP\$($file.Key.Name)" -Value $file.Value -Force

                    # Check key id hash
                    if ($CsrKeyIdHash -eq (TryCatch { certutil -dump "$env:TEMP\$($file.Key.Name)" } -ErrorAction SilentlyContinue | Where-Object {
                            $_ -match "Key Id Hash\(sha1\): (.*)"
                        } | ForEach-Object { "$($Matches[1])" }))
                    {
                        # Matching key id
                        $ParentCAResponseFileMatch = "$env:TEMP\$($file.Key.Name)"

                        Write-Verbose -Message "Matched CA Request Key Id Hash $CsrKeyIdHash in $ParentCAResponseFileMatch" @VerboseSplat
                    }
                    else
                    {
                        # Remove non-matching file
                        Remove-Item -Path "$env:TEMP\$($file.Key.Name)"

                        Write-Warning -Message "Response file `"$($file.Key.Name)`" did not match CA Request Key Id Hash $CsrKeyIdHash."
                    }
                }

                # Check if response file exist
                if ($ParentCAResponseFileMatch -and
                    (ShouldProcess @WhatIfSplat -Message "Installing CA certificate..." @VerboseSplat))
                {
                    # Try installing certificate
                    TryCatch { certutil -f -q -installcert "`"$ParentCAResponseFileMatch`"" } -ErrorAction Stop > $null

                    $Result.Add('CertificateInstalled', $true)
                    $Restart = $true

                    # Cleanup
                    Remove-Item -Path "$ParentCAResponseFileMatch"
                    Remove-Item -Path "$CsrfilePath"
                }
                else
                {
                    # Get file
                    $CsrFile = Get-Item -Path $CsrfilePath

                    # Add file, content and set result
                    $Result.Add($CsrFile, (Get-Content -Path $CsrFile.FullName -Raw))
                    $Result.Add('WaitingForResponse', $true)

                    # Output result
                    Write-Output -InputObject $Result

                    Write-Warning -Message "Submit `"$($CsrFile.Name)`" and rerun this script to continue..."

                    return
                }
            }
        }

        # ██████╗  ██████╗ ███████╗████████╗
        # ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝
        # ██████╔╝██║   ██║███████╗   ██║
        # ██╔═══╝ ██║   ██║╚════██║   ██║
        # ██║     ╚██████╔╝███████║   ██║
        # ╚═╝      ╚═════╝ ╚══════╝   ╚═╝

        # Get configuration
        $Configuration = Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction SilentlyContinue

        # Check configuration
        if (-not $Configuration)
        {
            Write-Warning -Message 'Configuration is missing under "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc"'
        }
        else
        {
            ########################
            # Set registry settings
            ########################

            # Set CertEnrollDirectory
            if ($Configuration.GetValue('CertEnrollDirectory') -ne $CertEnrollDirectory -and
                (ShouldProcess @WhatIfSplat -Message "Setting CertEnrollDirectory `"$CertEnrollDirectory`"" @VerboseSplat))
            {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name CertEnrollDirectory -Value $CertEnrollDirectory
                $Restart = $true
            }

            if (-not $UseDefaultSettings.IsPresent)
            {
                # Set validity period of issued certificates
                $Restart = Set-CASetting -Key 'ValidityPeriodUnits' -Value $ValidityPeriodUnits -InputFlag $Restart
                $Restart = Set-CASetting -Key 'ValidityPeriod' -Value $ValidityPeriod -InputFlag $Restart

                # Set Crl Distribution Point (CDP)
                $Restart = Set-CASetting -Key 'CRLPublicationURLs' -Value $CRLPublicationURLs -InputFlag $Restart

                # Set Authority Information Access (AIA)
                $Restart = Set-CASetting -Key 'CACertPublicationURLs' -Value $CACertPublicationURLs -InputFlag $Restart

                # Set CRL settings
                $Restart = Set-CASetting -Key 'CRLPeriodUnits' -Value $CRLPeriodUnits -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CRLPeriod' -Value $CRLPeriod -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CRLOverlapUnits' -Value $CRLOverlapUnits -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CRLOverlapPeriod' -Value $CRLOverlapPeriod -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CRLDeltaPeriodUnits' -Value $CRLDeltaPeriodUnits -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CRLDeltaPeriod' -Value $CRLDeltaPeriod -InputFlag $Restart

                # Set auditing
                $Restart = Set-CASetting -Key 'AuditFilter' -Value $AuditFilter -InputFlag $Restart
            }

            #############
            # Enterprise
            #############

            if ($ParameterSetName -match 'Enterprise')
            {
                # Add logging for changes to templates
                $Restart = Set-CASetting -Type Policy -Key 'EditFlags' -Value '+EDITF_AUDITCERTTEMPLATELOAD' -InputFlag $Restart
            }

            #############
            # Standalone
            #############

            if ($ParameterSetName -match 'Standalone')
            {
                # Check if DSConfigDN should be set
                if ($AddDomainConfig)
                {
                    # Add domain configuration for standalone ca
                    $Restart = Set-CASetting -Key 'DSDomainDN' -Value $BaseDn -InputFlag $Restart
                    $Restart = Set-CASetting -Key 'DSConfigDN' -Value "CN=Configuration,$BaseDn" -InputFlag $Restart
                }
                else
                {
                    # Remove domain configuration for standalone ca
                    $Restart = Set-CASetting -Key 'DSDomainDN' -Remove -InputFlag $Restart
                    $Restart = Set-CASetting -Key 'DSConfigDN' -Remove -InputFlag $Restart
                }

                if ($ParameterSetName -match 'Subordinate' -or $OCSPHost)
                {
                    # Enable ocsp extension requests
                    $Restart = Set-CASetting -Type Policy -Key 'EnableRequestExtensionList' -Value '+1.3.6.1.5.5.7.48.1.5' -InputFlag $Restart

                    # Enable ocsp no revocation check for standalone ca
                    $Restart = Set-CASetting -Type Policy -Key 'EditFlags' -Value '+EDITF_ENABLEOCSPREVNOCHECK' -InputFlag $Restart
                }
            }
        }

        ##########
        # Restart
        ##########

        # Check if running
        if ((Get-Service -Name CertSvc | Select-Object -ExpandProperty Status) -ne 'Running')
        {
            Write-Warning -Message "CA not running..."
            $Restart = $true
        }

        if ($Restart)
        {
            Restart-CertSvc
            Start-Sleep -Seconds 3

            if ($Result.Contains('CertificateInstalled'))
            {
                Write-Warning -Message "Certificate installed, waiting a bit extra for CA..."
                Start-Sleep -Seconds 7
            }
        }

        ############
        # Get CA CN
        ############

        if (-not $CACommonName)
        {
            $CACommonName = TryCatch { certutil -getreg CA\CommonName } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "CommonName REG_SZ = (.*)$"
            } | ForEach-Object { "$($Matches[1])" }

            if (-not $CACommonName)
            {
                Write-Warning -Message "Can't get CACommonName."
            }
        }

        ######################
        # Standalone Auditing
        ######################

        if ($ParameterSetName -match 'Standalone')
        {
            # Check auditing
            if ((((auditpol /get /subcategory:"Certification Services") -join '') -notmatch 'Success and Failure') -and
                (ShouldProcess @WhatIfSplat -Message "Enabling Object Access Certification Services Success and Failure auditing." @VerboseSplat))
            {
                TryCatch { auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable } > $null
            }
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

        # ████████╗███████╗███╗   ███╗██████╗ ██╗      █████╗ ████████╗███████╗███████╗
        # ╚══██╔══╝██╔════╝████╗ ████║██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝
        #    ██║   █████╗  ██╔████╔██║██████╔╝██║     ███████║   ██║   █████╗  ███████╗
        #    ██║   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║     ██╔══██║   ██║   ██╔══╝  ╚════██║
        #    ██║   ███████╗██║ ╚═╝ ██║██║     ███████╗██║  ██║   ██║   ███████╗███████║
        #    ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝

        if ($ParameterSetName -match 'Enterprise' -and
            $PublishTemplates.IsPresent)
        {
            # Get AD templates
            $ADTemplates = TryCatch { certutil -ADTemplate } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "^($DomainNetbiosName.*?):.*"
            } | ForEach-Object { "$($Matches[1])" }

            # Get CA templates
            $CATemplates = TryCatch { certutil -CATemplates } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "^(.*?):.*"
            } | ForEach-Object { "$($Matches[1])" }

            foreach($Template in $ADTemplates)
            {
                if ($Template -notin $CATemplates -and
                    (ShouldProcess @WhatIfSplat -Message "Adding template `"$Template`" to issue." @VerboseSplat))
                {
                    TryCatch { certutil -SetCATemplates "+$Template" } > $null
                }
            }
        }

        #  ██████╗██████╗ ██╗
        # ██╔════╝██╔══██╗██║
        # ██║     ██████╔╝██║
        # ██║     ██╔══██╗██║
        # ╚██████╗██║  ██║███████╗
        #  ╚═════╝╚═╝  ╚═╝╚══════╝

        if ($PublishCRL.IsPresent -and
            (ShouldProcess @WhatIfSplat -Message "Publishing CRL..." @VerboseSplat))
        {
            TryCatch { certutil -crl } > $null
        }

        # ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███╗   ██╗
        # ██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║
        # ██████╔╝█████╗     ██║   ██║   ██║██████╔╝██╔██╗ ██║
        # ██╔══██╗██╔══╝     ██║   ██║   ██║██╔══██╗██║╚██╗██║
        # ██║  ██║███████╗   ██║   ╚██████╔╝██║  ██║██║ ╚████║
        # ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

        # Itterate CA files under certenroll
        foreach($file in (Get-Item -Path "$CertEnrollDirectory\*$CACommonName*" -ErrorAction SilentlyContinue))
        {
            $Result.Add($file, (Get-Content -Path $file.FullName -Raw))
        }

        if ($ExportCertificate.IsPresent)
        {
            # Export CA certificate
            Backup-CARoleService -KeyOnly -Path "$env:TEMP" -Password $CertFilePassword

            # Inform
            Write-Warning -Message "Using password `"$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertFilePassword)))`" for `"$CACommonName.p12`""

            # Get p12
            $CACertificateP12 = Get-Item -Path "$env:TEMP\$CACommonName.p12"

            # Add p12
            $Result.Add($CACertificateP12, (Get-Content -Path $CACertificateP12.FullName -Raw))

            # Cleanup
            Remove-Item -Path "$env:TEMP\$CACommonName.p12"
        }

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
            # f_ShouldProcess.ps1 loaded in Begin
            . $PSScriptRoot\f_CopyDifferentItem.ps1
            # f_CheckContinue.ps1 loaded in begin
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
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CheckContinue.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_GetBaseDN.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetCASetting.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_RestartCertSvc.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_WriteRequest.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat      = $Using:VerboseSplat
            $WhatIfSplat       = $Using:WhatIfSplat
            $AlwaysPromptSplat = $Using:AlwaysPromptSplat
            $Force             = $Using:Force
            $AlwaysPrompt      = $Using:AlwaysPrompt
            $ParameterSetName  = $Using:ParameterSetName

            # Standalone/Root/Enterprise/Subordinate
            $CAType = $Using:CAType

            # CertFile
            $CertFile = $Using:CertFile
            $CertFilePassword = $Using:CertFilePassword

            # Certificate Key Container Name
            $KeyContainerName = $Using:KeyContainerName

            # Certificate Authority CN
            $CACommonName = $Using:CACommonName

            # Ignore Unicode
            $IgnoreUnicode = $Using:IgnoreUnicode

            # DN Suffix
            $CADistinguishedNameSuffix = $Using:CADistinguishedNameSuffix

            # Policy OID
            $PolicyOID = $Using:PolicyOID

            # Policy URL
            $PolicyURL = $Using:PolicyURL

            $CAPolicy = $Using:CAPolicy

            # Root CA certificate validity period
            $RootValidityPeriodUnits = $Using:RootValidityPeriodUnits
            $RootValidityPeriod = $Using:RootValidityPeriod

            # Parent CA
            $ParentCACommonName = $Using:ParentCACommonName
            $ParentCAFiles = $Using:ParentCAFiles
            $ParentCAResponseFiles = $Using:ParentCAResponseFiles

            # Crypto params
            $HashAlgorithmName = $Using:HashAlgorithmName
            $KeyLength = $Using:KeyLength
            $CryptoProviderName = $Using:CryptoProviderName

            # Path length
            $PathLength = $Using:PathLength

            # Directory locations
            $LogDirectory = $Using:LogDirectory
            $DatabaseDirectory = $Using:DatabaseDirectory
            $CertEnrollDirectory = $Using:CertEnrollDirectory

            # Validity period of issued certificates
            $ValidityPeriodUnits = $Using:ValidityPeriodUnits
            $ValidityPeriod = $Using:ValidityPeriod

            # Set host for OCSP
            $OCSPHost = $Using:OCSPHost

            # Set host for AIA
            $AIAHost = $Using:AIAHost

            # Set host for CDP
            $CDPHost = $Using:CDPHost

            # Crl publishing locations
            $CRLPublishAdditionalPaths = $Using:CRLPublishAdditionalPaths

            # Crl Distribution Point (CDP)
            $CRLPublicationURLs = $Using:CRLPublicationURLs

            # Authority Information Access (AIA)
            $CACertPublicationURLs = $Using:CACertPublicationURLs

            # CRL settings
            $CRLPeriodUnits = $Using:CRLPeriodUnits
            $CRLPeriod = $Using:CRLPeriod
            $CRLOverlapUnits = $Using:CRLOverlapUnits
            $CRLOverlapPeriod = $Using:CRLOverlapPeriod
            $CRLDeltaPeriodUnits = $Using:CRLDeltaPeriodUnits
            $CRLDeltaPeriod = $Using:CRLDeltaPeriod
            $CRLDeltaOverlapUnits = $Using:CRLDeltaOverlapUnits
            $CRLDeltaOverlapPeriod = $Using:CRLDeltaOverlapPeriod

            # Set log level
            $AuditFilter = $Using:AuditFilter

            # DSConfigDN / DSDomainDN
            $AddDomainConfig = $Using:AddDomainConfig

            ###########
            # Switches
            ###########

            $UseDefaultSettings = $Using:UseDefaultSettings
            $UsePolicyNameConstraints = $Using:UsePolicyNameConstraints
            $PublishTemplates = $Using:PublishTemplates
            $PublishCRL = $Using:PublishCRL
            $ExportCertificate = $Using:ExportCertificate
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
                . $PSScriptRoot\f_GetBaseDN.ps1
                . $PSScriptRoot\f_SetCASetting.ps1
                . $PSScriptRoot\f_RestartCertSvc.ps1
                . $PSScriptRoot\f_WriteRequest.ps1
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

                    # Check if certificate or crl
                    if ($file.Key.Extension -eq '.crt' -or $file.Key.Extension -eq '.crl')
                    {
                        # Convert to pem
                        TryCatch { certutil -f -encode "$env:TEMP\$($file.Key.Name)" "$env:TEMP\$($file.Key.Name)" } > $null
                    }

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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU585e+xIzQuC5M4XuYTcoaJ7F
# nQ2gghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUgiIJp3jN
# 85BlBzh/2vYL48YvOJ8wDQYJKoZIhvcNAQEBBQAEggIAoK1LTw6LMVujwP2bGZlz
# bNMZkyaCaLOLd4TSm4CvP+Le3UHFHMsazm0sXuVVSKHTFFN6foqYDwexlNqCAGZy
# TIZ7hwNXgirNycJW4qi+pJSZzhtpKo4+1dYDf46+x4NMVcmVc7rz12ZGt5kL29IP
# 6EbJiJLOltCKs3GgKHSqsx0o7FzrEjKo9nfcuHzsb60ATTB6pRWaFfvIlZ/IdSKV
# OiazpTH+VD1/C0A5b5ypRvQ9pt3VNg79fSsx2V9aOslaLJTbBHobnBcVcAY5kwNr
# P5UESuZ8sq1DeHZTkvb6mlXS9ZWEL3CMVdF2VwPNdY6eCjOViOXnWZLDpqJ9PyUO
# Ki54TN1q6S5QBMjLlRzNV7kr4/ZEhUmH8EvPRi46iqLqfr7mb0VHWtJ5nuZM43jJ
# LDoGXuM2RNRxRFWHfVwpXfNYsP7DsLpCmiQbf9ZFG+DlspvfryCFpqG6I+FhW8yw
# tLR2+n+47S4WRn+DnjdKVEdmWgb6wv0038aXNeaepkNGfrnWEJLoEHnzdOIY9Ret
# DuyTNXGkENnrkhg4xCs+nSq8H7yGuQh3SOssUevjJqERaN708DOrT1DO8AkUYZvi
# 4u3o5MqrLLCnwcjfZr4EdlUVek4JzRbhdTC2nvUsyMRNhU4pe6km91V+e8Os91gi
# 6NebpM46A3+9SybByhQyi0yhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwMTEwMTgwMDAy
# WjAvBgkqhkiG9w0BCQQxIgQgnr1WjRJVF5hIVw9Amc2YE9Jf+ERwYt7do1YwL1Z+
# bUUwDQYJKoZIhvcNAQEBBQAEggIAbQP9z5eaj0SGDJflRvkLkCvIPhzJVcgFMqin
# ID/H25Mwc3Lp9SYe2vzLxof9dGeOkgWlwmFDCM7U3HrL9yzfLzFX3qoQSmgwlkSc
# wWKGEcubmZ7QOnTRuwfe5NMxPbDEvGv1wv6s0l4q2IPGPZMmDCyxN+hvqnH+gx5l
# 21QFRHPQqakVdR0sw7iGl4+WUR4o04BqVQ0HOhZUzK4839G2GU7QS6SvswigTONa
# 0hRgAK1DdWXC4JcQZuVySaGW8wnHaCh4syzOLlpXLE2jXFIPWMZrs6vEJbcT2op1
# xbrfUju92EMmnRH+zRrLKbsQ29M8P9jyvsZ/GFVfKu8ML0HSj6ozVWzo9W14l5bI
# 2oVcm6/OFW3SD/MC3gKWBGFRi3b5nTtXHZ9AHglCSBRFmYYN1rH6zQmW0JzFS96F
# apcKPwYLvjcJszjKnDE+9Uruf4DdiKNM5XmP6z6h17R1yWZOBv5cvGSvwNyxKYEJ
# ZUSBHpJSQkRMp2o8Tnjf0WqSDtPsiwNj5QX5tmRFqd5cDf6cN1wNlJfQ+mVLFfaf
# 5ag/t35D4UpoiQokz7n1OLMm9My9uC5ma2NjdhCvCwqO64kY9UeU58E0CfbyjrO/
# +CyhYsLlgLEENtsoL7dj69bRpKuTclwOxJKDA+D/YuTdj8+7EFyb95E9bz7pMMr6
# /QL1Gkg=
# SIG # End signature block
