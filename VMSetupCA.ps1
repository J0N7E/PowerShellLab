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

    # Certificate key container name
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA', Mandatory=$true)]
    [String]$KeyContainerName,

    # Certificate authority common name
    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA', Mandatory=$true)]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA', Mandatory=$true)]
    [String]$CACommonName,

    # DN suffix
    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA')]
    [String]$CADistinguishedNameSuffix,

    # DSConfigDN / DSDomainDN
    [Parameter(ParameterSetName='CertFile_StandaloneRootCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA')]
    [String]$DomainName,

    # Root CA common name
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA', Mandatory=$true)]
    [String]$RootCACommonName,

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

    # Issuance policies
    [Parameter(ParameterSetName='CertFile_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='CertFile_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA')]
    [Array]$IssuancePolicies,

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

    # Alternate Signature Algorithm
    [String]$AlternateSignatureAlgorithm = 0,

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

    # Crl Distribution Point (CDP)
    [String]$CRLPublicationURLs,

    # Crl publishing locations
    [Array]$PublishAdditionalPaths,

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

    ###########
    # Switches
    ###########

    [Switch]$UseDefaultSettings,
    [Switch]$UsePolicyNameConstraints,

    [Parameter(ParameterSetName='NewKey_EnterpriseRootCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneRootCA')]
    [Parameter(ParameterSetName='NewKey_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='NewKey_StandaloneSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneRootCA')]
    [Parameter(ParameterSetName='KeyContainerName_EnterpriseSubordinateCA')]
    [Parameter(ParameterSetName='KeyContainerName_StandaloneSubordinateCA')]
    [Switch]$IgnoreUnicode,

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
        @{ Name = 'IssuancePolicies';          Type = [Array]        },
        @{ Name = 'PublishAdditionalPaths'; Type = [Array]        }

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
            . $PSScriptRoot\f_TryCatch.ps1
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

    ################
    # Always prompt
    ################

    # Initialize alwaysprompt
    $AlwaysPromptSplat = @{}

    # Check alwaysprompt
    if ($AlwaysPrompt.IsPresent)
    {
        # Set alwaysprompt splat
        $AlwaysPromptSplat.Add('AlwaysPrompt', $true)
    }

    ######################
    # Get parent ca files
    ######################

    # Initialize
    $ParentCAFiles = @{}
    $ParentCAResponseFiles = @{}

    if ($ParameterSetName -match 'NewKey.*Subordinate')
    {
        ######################
        # Get parent response
        # for Subordinate CA
        ######################

        if (Test-Path -Path "$PSScriptRoot\$CACommonName-Request*.csr")
        {
            # Itterate all posbile parent ca responses
            foreach($file in (Get-Item -Path "$PSScriptRoot\*" -Include '*.cer'))
            {
                # Check issuer
                if ($CACommonName -eq ((certutil -dump $file | Out-String) | Where-Object {
                        $_ -match "Subject:\r\n.*CN=(.*)\r\n"
                    } | ForEach-Object { "$($Matches[1])" }))
                {
                    Write-Verbose -Message "Getting parent CA response file: $($file.Name)" @VerboseSplat

                    # Get file content
                    $ParentCAResponseFiles.Add($file, (Get-Content @GetContentSplat -Path $file.FullName))
                }
            }
        }

        #########################
        # Get parent certificate
        # for Standalone CA
        #########################

        if ($ParameterSetName -eq 'NewKey_StandaloneSubordinateCA')
        {
            # Itterate all posbile parent ca certificates
            foreach($file in (Get-Item -Path "$PSScriptRoot\*" -Include '*.crt'))
            {
                # Check subject
                if ($RootCACommonName -eq ((certutil -dump $file | Out-String) | Where-Object {
                        $_ -match "Subject:\r\n.*CN=(.*)\r\n"
                    } | ForEach-Object { "$($Matches[1])" }))
                {
                    Write-Verbose -Message "Getting parent CA certificate: $($file.Name)" @VerboseSplat

                    # Get file content
                    $ParentCAFiles.Add($file, (Get-Content @GetContentSplat -Path $file.FullName))
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
                throw "No parent certificate for `"$RootCACommonName`" found, aborting..."
            }
        }
    }

    ###########
    # CertFile
    ###########

    if ($ParameterSetName -match 'CertFile' -and
        (Test-Path -Path $CertFile -ErrorAction SilentlyContinue))
    {
        $CertFile = Get-Content @GetContentSplat -Path $CertFile
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
        $Result = @()

        ##############
        # Check admin
        ##############

        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {
            throw "Must be administrator to setup Certficate Authority."
        }

        ##################
        # Get/Set Content
        ##################

        if ($PSVersionTable.PSVersion.Major -ge 7)
        {
            $GetContentSplat =
            @{
                Raw = $true
                AsByteStream = $true
            }
            $SetContentSplat = @{ AsByteStream = $true }
        }
        else
        {
            $GetContentSplat =
            @{
                Raw = $true
                Encoding = 'Byte'
            }
            $SetContentSplat = @{ Encoding = 'Byte' }
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
        # FIX Switch to DomainName, remove AddDomainConfig
        elseif (-not $DomainName)
        {
            Check-Continue -Message "-DomainName parameter not specified, DSDomainDN and DSConfigDN will not be set."
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

        # ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗
        # ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║
        # ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║
        # ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║
        # ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
        # ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

        # Install CA feature
        if (-not $CAInstalled -and
            (ShouldProcess @WhatIfSplat -Message "Installing ADCS-Cert-Authority." @VerboseSplat))
        {
            Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools -Restart > $null
        }

        #  █████╗ ██╗ █████╗     ██╗ ██████╗██████╗ ██████╗
        # ██╔══██╗██║██╔══██╗   ██╔╝██╔════╝██╔══██╗██╔══██╗
        # ███████║██║███████║  ██╔╝ ██║     ██║  ██║██████╔╝
        # ██╔══██║██║██╔══██║ ██╔╝  ██║     ██║  ██║██╔═══╝
        # ██║  ██║██║██║  ██║██╔╝   ╚██████╗██████╔╝██║
        # ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝     ╚═════╝╚═════╝ ╚═╝

        ######
        # AIA
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831574(v=ws.11)#publish-the-aia-extension
        # CSURL_SERVERPUBLISH -- 1
        # CSURL_ADDTOCERTCDP  -- 2
        # CSURL_ADDTOCERTOCSP -- 32
        ######

        # Check if exist
        if (-not $CACertPublicationURLs)
        {
            ########
            # Local
            ########

            $CACertPublicationURLs = "1:$CertEnrollDirectory\%3%4.crt"

            #########
            # Add to
            #########

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

            #########
            # Remote
            #########

            if ($PublishAdditionalPaths)
            {
                foreach ($Item in $PublishAdditionalPaths)
                {
                    # Add publishing paths
                    $CACertPublicationURLs += "\n1:$Item\%3%4.crl"
                }
            }
            elseif ($ParameterSetName -match 'Subordinate')
            {
                Check-Continue -Message "-PublishAdditionalPaths parameter not specified, CRT will not be published remotely."
            }

            #######
            # OCSP
            #######

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
        # CSURL_SERVERPUBLISH      -- 1
        # CSURL_ADDTOCERTCDP       -- 2
        # CSURL_ADDTOFRESHESTCRL   -- 4
        # CSURL_SERVERPUBLISHDELTA -- 64
        ######

        # Check if exist
        if (-not $CRLPublicationURLs)
        {
            ########
            # Local
            ########

            $CRLPublicationURLs = "65:$env:SystemRoot\System32\CertSrv\CertEnroll\%3%8%9.crl"

            if ($CertEnrollDirectory -ne "$env:SystemRoot\System32\CertSrv\CertEnroll")
            {
                # Add custom CertEnroll directory
                $CRLPublicationURLs += "\n65:$CertEnrollDirectory\%3%8%9.crl"
            }

            #########
            # Add to
            #########

            # Check if exist
            if ($CDPHost)
            {
                # Add CDP url
                $CRLPublicationURLs += "\n6:http://$CDPHost/%3%8%9.crl"
            }
            elseif ($DomainName)
            {
                Check-Continue -Message "-CDPHost parameter not specified, using `"pki.$DomainName`" as CDPHost."

                # Add default CDP url
                $CRLPublicationURLs += "\n6:http://pki.$DomainName/%3%8%9.crl"
            }
            else
            {
                Check-Continue -Message "-CDPHost parameter not specified, no CDP will be used."
            }

            #########
            # Remote
            #########

            if ($PublishAdditionalPaths)
            {
                foreach ($Item in $PublishAdditionalPaths)
                {
                    # Add publishing paths
                    $CRLPublicationURLs += "\n65:$Item\%3%8%9.crl"
                }
            }
            elseif ($ParameterSetName -match 'Subordinate')
            {
                Check-Continue -Message "-PublishAdditionalPaths parameter not specified, CRL will not be published remotely."
            }
        }

        # ██████╗  ██████╗ ██╗     ██╗ ██████╗██╗   ██╗
        # ██╔══██╗██╔═══██╗██║     ██║██╔════╝╚██╗ ██╔╝
        # ██████╔╝██║   ██║██║     ██║██║      ╚████╔╝
        # ██╔═══╝ ██║   ██║██║     ██║██║       ╚██╔╝
        # ██║     ╚██████╔╝███████╗██║╚██████╗   ██║
        # ╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝   ╚═╝

        $CAPolicy =
        @(
            "[Version]",
            "Signature=`"`$Windows NT$`"",
            ""
        )

        if ($CAType -match 'Subordinate')
        {
            $CAPolicy +=
            @(
                "[BasicConstraintsExtension]",
                "PathLength=$PathLength",
                "Critical=Yes",
                ""
            )
        }

        $CAPolicy +=
        @(
            "[Certsrv_Server]",
            "AlternateSignatureAlgorithm=$AlternateSignatureAlgorithm",
            "RenewalKeyLength=$KeyLength"
        )

        if ($CAType -match 'Root')
        {
            $CAPolicy +=
            @(
                "RenewalValidityPeriodUnits=$RootValidityPeriodUnits",
                "RenewalValidityPeriod=$RootValidityPeriod"
            )
        }

        if (-not $UseDefaultSettings.IsPresent)
        {
            $CAPolicy +=
            @(
                "CRLPeriodUnits=$CRLPeriodUnits",
                "CRLPeriod=$CRLPeriod",
                "CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits",
                "CRLDeltaPeriod=$CRLDeltaPeriod"
            )
        }

        if ($CAType -match 'Enterprise')
        {
            $CAPolicy += "LoadDefaultTemplates=0"
        }

        if ($UsePolicyNameConstraints.IsPresent -and
            $CAType -match 'Enterprise' -and
            $DomainName -and
            $BaseDn)
        {
            $CAPolicy +=
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

        ##################
        # Issuance policy
        ##################

        if ($ParameterSetName -match 'Subordinate')
        {
            if (-not $IssuancePolicies)
            {
                $IssuancePolicies =
                @(
                    @{ Name = 'All issuance policy';  OID = '2.5.29.32.0';  }
                )
            }

            $PolicyStatementExtension = 'Policies='
            $PolicySection = @('')

            for ($i=1; $i -le $IssuancePolicies.Count; $i++)
            {
                $Policy = $IssuancePolicies[$i-1]

                if ($Policy.ContainsKey('Name') -and $Policy.ContainsKey('OID'))
                {
                    $PolicyStatementExtension += "`"$($Policy.Name)`""

                    if ($i -lt $IssuancePolicies.Count)
                    {
                          $PolicyStatementExtension += ', '
                    }

                    $PolicySection +=
                    @(
                        "[$($Policy.Name)]",
                        "OID=$($Policy.OID)"
                    )

                    if ($Policy.URL)
                    {
                        $PolicySection += "URL=$($Policy.URL)"
                    }

                    $PolicySection += ""
                }
                else
                {
                    ShouldProcess @WhatIfSplat -Message "IssuancePolicies hashtable in wrong format, skipping policy." -WriteWarning > $null
                }
            }

            if ($PolicySection.Count -gt 0)
            {
                $CAPolicy +=
                @(
                    "",
                    "[PolicyStatementExtension]",
                    $PolicyStatementExtension,
                    "Critical=No"
                )

                $CAPolicy += $PolicySection
            }
        }

        if (-not $CAConfigured)
        {
            #############
            # Set policy
            #############

            # Save CA policy to temp
            Set-Content -Path "$env:TEMP\CAPolicy.inf" -Value (Get-Variable -Name "CAPolicy").Value

            # Move to systemroot if different
            Copy-DifferentItem -SourcePath "$env:TEMP\CAPolicy.inf" -RemoveSourceFile -TargetPath "$env:SystemRoot\CAPolicy.inf" -BackupTargetFile @VerboseSplat
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
            $RootCertificateHashArray = TryCatch { certutil -store root "$RootCACommonName" } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "Cert Hash\(sha1\): (.*)$"
            } | ForEach-Object { "$($Matches[1])" }

            #############
            # Save files
            #############

            # Create temp Directory
            New-Item -ItemType Directory -Path "$env:TEMP" -Name $RootCACommonName -Force > $null

            # Itterate all files
            foreach($file in $ParentCAFiles.GetEnumerator())
            {
                # Save file to temp
                Set-Content @SetContentSplat -Path "$env:TEMP\$RootCACommonName\$($file.Key.Name)" -Value $file.Value -Force

                # Set original timestamps
                Set-ItemProperty -Path "$env:TEMP\$RootCACommonName\$($file.Key.Name)" -Name CreationTime -Value $file.Key.CreationTime
                Set-ItemProperty -Path "$env:TEMP\$RootCACommonName\$($file.Key.Name)" -Name LastWriteTime -Value $file.Key.LastWriteTime
                Set-ItemProperty -Path "$env:TEMP\$RootCACommonName\$($file.Key.Name)" -Name LastAccessTime -Value $file.Key.LastAccessTime
            }

            ######
            # Add
            ######

            # Initialize arrays
            $ParentFileCertificateHashArray = @()

            # Itterate all parent ca files
            foreach($file in (Get-Item -Path "$env:TEMP\$RootCACommonName\*"))
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
            Remove-Item -Path "$env:TEMP\$RootCACommonName" -Force -Recurse
        }

        # ██████╗  █████╗ ████████╗██╗  ██╗███████╗
        # ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝
        # ██████╔╝███████║   ██║   ███████║███████╗
        # ██╔═══╝ ██╔══██║   ██║   ██╔══██║╚════██║
        # ██║     ██║  ██║   ██║   ██║  ██║███████║
        # ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝

        # Check if directories exist
        foreach ($Directory in ($CertEnrollDirectory, $DatabaseDirectory, $LogDirectory))
        {
            if ($Directory -and -not (Test-Path -Path $Directory) -and
                (ShouldProcess @WhatIfSplat -Message "Creating `"$Directory`"" @VerboseSplat))
            {
                New-Item -ItemType Directory -Path $Directory > $null
            }
        }

        #  ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗ ██╗   ██╗██████╗ ███████╗
        # ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ ██║   ██║██╔══██╗██╔════╝
        # ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗██║   ██║██████╔╝█████╗
        # ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║██║   ██║██╔══██╗██╔══╝
        # ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝╚██████╔╝██║  ██║███████╗
        #  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝

        # Initialize
        $ADCSCAParams =
        @{
            'CAType' = $CAType
            'AllowAdministratorInteraction' = $true
            'OverwriteExistingKey' = $true
            'OverwriteExistingDatabase' = $true
        }

        # Ignore unicode
        if ($IgnoreUnicode.IsPresent)
        {
            $ADCSCAParams.Add('IgnoreUnicode', $true)
        }

        if ($ParameterSetName -match 'CertFile')
        {
            # Get content
            Set-Content @SetContentSplat -Path "$env:TEMP\CertFile.p12" -Value $CertFile

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

            if ($ParameterSetName -match 'Enterprise' -and $PartOfDomain)
            {
                $ADCSCAParams.Add('OverwriteExistingCAinDS', $true)
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

        if ($AlwaysPrompt)
        {
            ShouldProcess @WhatIfSplat -Message "CAPolicy.inf:" @VerboseSplat > $null

            foreach($Line in $CAPolicy)
            {
                ShouldProcess @WhatIfSplat -Message "$Line" @VerboseSplat > $null
            }

            ShouldProcess @WhatIfSplat -Message "Install-AdcsCertificationAuthority Parameters:" @VerboseSplat > $null

            foreach($Param in $ADCSCAParams.GetEnumerator())
            {
                if ($Param.Value -match " ")
                {
                    $Param.Value = "`"$($Param.Value)`""
                }

                ShouldProcess @WhatIfSplat -Message "-$($Param.Key) $($Param.Value)" @VerboseSplat > $null
            }

            ShouldProcess @WhatIfSplat -Message "Post settings:" @VerboseSplat > $null

            foreach($Setting in (Get-Variable -Name PathLength, Validity*, AuditFilter, CRL*, CACertPublicationURLs))
            {
                if ($Setting.Value)
                {
                    if ($Setting.Value -match " ")
                    {
                        $Setting.Value = "`"$($Setting.Value)`""
                    }

                    ShouldProcess @WhatIfSplat -Message "$($Setting.Name) = $($Setting.Value)" @VerboseSplat > $null
                }
            }
        }

        if (-not $CAConfigured)
        {
            # FIX
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
                    # Save file to temp
                    Set-Content @SetContentSplat -Path "$env:TEMP\$($file.Key.Name)" -Value $file.Value -Force

                    # Check key id hash
                    if ($CsrKeyIdHash -eq (TryCatch { certutil -dump "$env:TEMP\$($file.Key.Name)" } -ErrorAction SilentlyContinue | Where-Object {
                            $_ -match "Key Id Hash\(sha1\): (.*)"
                        } | ForEach-Object { "$($Matches[1])" }))
                    {
                        # Matching key id
                        $ParentCAResponseFileMatch = "$env:TEMP\$($file.Key.Name)"

                        ShouldProcess @WhatIfSplat -Message "Matched CA Request Key Id Hash $CsrKeyIdHash in $ParentCAResponseFileMatch" @VerboseSplat > $null
                    }
                    else
                    {
                        # Remove non-matching file
                        Remove-Item -Path "$env:TEMP\$($file.Key.Name)"

                        ShouldProcess @WhatIfSplat -Message "Response file `"$($file.Key.Name)`" did not match CA Request Key Id Hash $CsrKeyIdHash." -WriteWarning > $null
                    }
                }

                # Check if response file matched
                if ($ParentCAResponseFileMatch -and
                    (ShouldProcess @WhatIfSplat -Message "Installing CA certificate..." @VerboseSplat))
                {
                    # Try installing certificate
                    TryCatch { certutil -f -q -installcert "`"$ParentCAResponseFileMatch`"" } -ErrorAction Stop > $null

                    $Result += @{ CertificateInstalled =  $true }
                    $Restart = $true

                    # Cleanup
                    Remove-Item -Path "$ParentCAResponseFileMatch"
                    Remove-Item -Path "$CsrfilePath"
                }
                else
                {

                    # Get file
                    $CsrFile = Get-Item -Path $CsrfilePath

                    ShouldProcess @WhatIfSplat -Message "Submit `"$($CsrFile.Name)`" and rerun this script to continue..." > $null

                    # Add file, content and set result
                    $Result += @{ File = @{ FileObj = $CsrFile; FileContent = (Get-Content @GetContentSplat -Path $CsrFile.FullName); }}
                    $Result += @{ WaitingForResponse = $true }

                    # Output result
                    Write-Output -InputObject $Result

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

        # Get CA CN
        if (-not $CACommonName)
        {
            $CACommonName = TryCatch { certutil -getreg CA\CommonName } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "CommonName REG_SZ = (.*)$"
            } | ForEach-Object { "$($Matches[1])" }

            if (-not $CACommonName)
            {
                ShouldProcess @WhatIfSplat -Message "Can't get CACommonName." -WriteWarning > $null
            }
        }

        # Get configuration
        $Configuration = Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction SilentlyContinue

        # Check configuration
        if (-not $Configuration)
        {
            ShouldProcess @WhatIfSplat -Message 'Configuration is missing under "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc"' -WriteWarning > $null
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
                $Restart = Set-CASetting -Key 'CA\ValidityPeriodUnits' -Value $ValidityPeriodUnits -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CA\ValidityPeriod' -Value $ValidityPeriod -InputFlag $Restart

                # Set Crl Distribution Point (CDP)
                $Restart = Set-CASetting -Key 'CA\CRLPublicationURLs' -Value $CRLPublicationURLs -InputFlag $Restart

                # Set Authority Information Access (AIA)
                $Restart = Set-CASetting -Key 'CA\CACertPublicationURLs' -Value $CACertPublicationURLs -InputFlag $Restart

                # Set CRL settings
                $Restart = Set-CASetting -Key 'CA\CRLPeriodUnits' -Value $CRLPeriodUnits -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CA\CRLPeriod' -Value $CRLPeriod -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CA\CRLOverlapUnits' -Value $CRLOverlapUnits -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CA\CRLOverlapPeriod' -Value $CRLOverlapPeriod -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CA\CRLDeltaPeriodUnits' -Value $CRLDeltaPeriodUnits -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CA\CRLDeltaPeriod' -Value $CRLDeltaPeriod -InputFlag $Restart

                # Set auditing
                $Restart = Set-CASetting -Key 'CA\AuditFilter' -Value $AuditFilter -InputFlag $Restart
            }

            #############
            # Enterprise
            #############

            if ($ParameterSetName -match 'Enterprise')
            {
                # Add logging for changes to templates
                $Restart = Set-CASetting -Key 'Policy\EditFlags' -Value '+EDITF_AUDITCERTTEMPLATELOAD' -InputFlag $Restart

                # Set NDES SubjectTemplate configuration
                $Restart = Set-CASetting -Key 'CA\SubjectTemplate' -Value '+UnstructuredName' -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CA\SubjectTemplate' -Value '+UnstructuredAddress' -InputFlag $Restart
                $Restart = Set-CASetting -Key 'CA\SubjectTemplate' -Value '+DeviceSerialNumber' -InputFlag $Restart
            }

            #############
            # Standalone
            #############

            if ($ParameterSetName -match 'Standalone')
            {
                # Check if DSConfigDN should be set
                if ($BaseDn)
                {
                    # Add domain configuration for standalone ca
                    $Restart = Set-CASetting -Key 'CA\DSDomainDN' -Value $BaseDn -InputFlag $Restart
                    $Restart = Set-CASetting -Key 'CA\DSConfigDN' -Value "CN=Configuration,$BaseDn" -InputFlag $Restart
                }

                if ($ParameterSetName -match 'Subordinate' -or $OCSPHost)
                {
                    # Enable ocsp extension requests
                    $Restart = Set-CASetting -Key 'Policy\EnableRequestExtensionList' -Value '+1.3.6.1.5.5.7.48.1.5' -InputFlag $Restart

                    # Enable ocsp no revocation check for standalone ca
                    $Restart = Set-CASetting -Key 'Policy\EditFlags' -Value '+EDITF_ENABLEOCSPREVNOCHECK' -InputFlag $Restart
                }
            }
        }

        ##########
        # Restart
        ##########

        # Check if running
        if ((Get-Service -Name CertSvc | Select-Object -ExpandProperty Status) -ne 'Running')
        {
            ShouldProcess @WhatIfSplat -Message "CA not running..." > $null
            $Restart = $true
        }

        if ($Restart)
        {
            Restart-CertSvc
            Start-Sleep -Seconds 3

            if ($Result.CertificateInstalled)
            {
                ShouldProcess @WhatIfSplat -Message "Certificate installed, waiting a bit extra for CA..." > $null
                Start-Sleep -Seconds 7
            }
            <#
            elseif ($PublishTemplates.IsPresent)
            {
                ShouldProcess @WhatIfSplat -Message "About to load templates, waiting a bit extra for CA..." > $null
                Start-Sleep -Seconds 5
            }
            #>
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
                    if ($Restart -and -not $Result.CertificateInstalled)
                    {
                        ShouldProcess @WhatIfSplat -Message "About to load templates, waiting a bit extra for CA..." > $null
                        Start-Sleep -Seconds 5

                        $Restart = $null
                    }

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

        # Itterate CA files under certenroll
        foreach($file in (Get-Item -Path "$CertEnrollDirectory\*$CACommonName*" -ErrorAction SilentlyContinue))
        {
            $Result += @{ File = @{ FileObj = $file; FileContent = (Get-Content @GetContentSplat -Path $file.FullName); }}
        }

        # Export
        if ($ExportCertificate.IsPresent)
        {
            # Export CA certificate
            Backup-CARoleService -KeyOnly -Path "$env:TEMP" -Password $CertFilePassword

            ShouldProcess @WhatIfSplat -Message "Using password `"$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertFilePassword)))`" for `"$CACommonName.p12`"" > $null

            # Get p12
            $CACertificateP12 = Get-Item -Path "$env:TEMP\$CACommonName.p12"

            # Add p12
            $Result += @{ File = @{ FileObj = $CACertificateP12; FileContent = (Get-Content @GetContentSplat -Path $CACertificateP12.FullName); }}

            # Cleanup
            Remove-Item -Path "$env:TEMP\$CACommonName.p12"
        }

        # ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███╗   ██╗
        # ██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║
        # ██████╔╝█████╗     ██║   ██║   ██║██████╔╝██╔██╗ ██║
        # ██╔══██╗██╔══╝     ██║   ██║   ██║██╔══██╗██║╚██╗██║
        # ██║  ██║███████╗   ██║   ╚██████╔╝██║  ██║██║ ╚████║
        # ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

        if ($Result.Count -gt 0)
        {
            Write-Output -InputObject $Result
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
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CheckContinue.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_GetBaseDN.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetCASetting.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_RestartCertSvc.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_WriteRequest.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat       = $Using:VerboseSplat
            $WhatIfSplat        = $Using:WhatIfSplat
            $Force              = $Using:Force
            $ParameterSetName   = $Using:ParameterSetName
            $AlwaysPrompt       = $Using:AlwaysPrompt
            $AlwaysPromptSplat  = $Using:AlwaysPromptSplat

            # Standalone/Root/Enterprise/Subordinate
            $CAType = $Using:CAType

            # CertFile
            $CertFile = $Using:CertFile
            $CertFilePassword = $Using:CertFilePassword

            # Certificate key container name
            $KeyContainerName = $Using:KeyContainerName

            # Certificate authority common name
            $CACommonName = $Using:CACommonName

            # DN suffix
            $CADistinguishedNameSuffix = $Using:CADistinguishedNameSuffix

            # DSConfigDN / DSDomainDN
            $DomainName = $Using:DomainName

            # Root CA common name
            $RootCACommonName = $Using:RootCACommonName

            # Root CA certificate validity period
            $RootValidityPeriodUnits = $Using:RootValidityPeriodUnits
            $RootValidityPeriod = $Using:RootValidityPeriod

            # Issuance policies
            $IssuancePolicies = $Using:IssuancePolicies

            # Parent CA
            $ParentCAFiles = $Using:ParentCAFiles
            $ParentCAResponseFiles = $Using:ParentCAResponseFiles

            # Crypto params
            $HashAlgorithmName = $Using:HashAlgorithmName
            $KeyLength = $Using:KeyLength
            $CryptoProviderName = $Using:CryptoProviderName

            # Path length
            $PathLength = $Using:PathLength

            # Alternate Signature Algorithm
            $AlternateSignatureAlgorithm = $Using:AlternateSignatureAlgorithm

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

            # Crl Distribution Point (CDP)
            $CRLPublicationURLs = $Using:CRLPublicationURLs

            # Crl publishing locations
            $PublishAdditionalPaths = $Using:PublishAdditionalPaths

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

            ###########
            # Switches
            ###########

            $UseDefaultSettings = $Using:UseDefaultSettings
            $UsePolicyNameConstraints = $Using:UsePolicyNameConstraints
            $IgnoreUnicode = $Using:IgnoreUnicode
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
                # f_CheckContinue.ps1 loaded in begin
                # f_ShouldProcess.ps1 loaded in Begin
                # f_CopyDifferentItem.ps1 loaded in begin
                # f_TryCatch.ps1 loaded in begin
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
        $ResultParsed = @{}

        foreach($Row in $Result)
        {
            if ($Row -is [Hashtable])
            {
                foreach($Item in $Row.GetEnumerator())
                {
                    switch ($Item.Key)
                    {
                        'Host'    { $Item.Value | Write-Host }
                        'Verbose' { $Item.Value | Write-Verbose @VerboseSplat }
                        'Warning' { $Item.Value | Write-Warning }
                        'Error'   { $Item.Value | Write-Error }

                        'File'
                        {
                            # Save in temp
                            Set-Content @SetContentSplat -Path "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -Value $Item.Value.Item('FileContent')

                            # Check if certificate or crl
                            if ($Item.Value.Item('FileObj').Extension -eq '.crt' -or $Item.Value.Item('FileObj').Extension -eq '.crl')
                            {
                                # Convert to pem
                                TryCatch { certutil -f -encode "$env:TEMP\$($Item.Value.Item('FileObj').Name)" "$env:TEMP\$($Item.Value.Item('FileObj').Name)" } > $null
                            }

                            # Set original timestamps
                            Set-ItemProperty -Path "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -Name CreationTime -Value $Item.Value.Item('FileObj').CreationTime
                            Set-ItemProperty -Path "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -Name LastWriteTime -Value $Item.Value.Item('FileObj').LastWriteTime
                            Set-ItemProperty -Path "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -Name LastAccessTime -Value $Item.Value.Item('FileObj').LastAccessTime

                            # Move to script root if different
                            Copy-DifferentItem -SourcePath "$env:TEMP\$($Item.Value.Item('FileObj').Name)" -RemoveSourceFile -TargetPath "$PSScriptRoot\$($Item.Value.Item('FileObj').Name)" @VerboseSplat
                        }

                        default
                        {
                            $ResultParsed.Add($Item.Key, $Item.Value)
                        }
                    }
                }
            }
            else
            {
                Write-Warning -Message 'Unexpected result:'
                Write-Host -Object $Row
            }
        }

        Write-Output -InputObject $ResultParsed
    }
}

End
{
}

# SIG # Begin signature block
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU/3n4TNEUqg/tSb0UH/M+Qiil
# pkygghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSGUzET
# 2jQL+XTiqIMEpQAcvRd3MzANBgkqhkiG9w0BAQEFAASCAgCqerND4K2niB25KutX
# gKUI5Ti4DzK+BMFF92mf8sm4pqGBcrO4xhy21a3dJt408Df+nDvFkuU40l53Q3QY
# 8Cz+bX+2oBfWCvLLYHIVN2crTzLW0ydeobz225FRu53z+Yh4wXHoo8MlaWU+TtoS
# s/BWC2dKdTmn7aE6KOGa0uS7a9MPeUo6QaAIOiHb/D8meV6mf6gsBe53vwXuZVJh
# HRHEsvWd4uqdPQXfQPntH2357OyaenDA374j4MEcr1KTb9j3ge6umwLnf1mLWfSX
# qG5n/115O4mgroa1ziUxiSmEOl+2JJ55HYQtyj4gXySoG3ILIQS9x+lkOaS1Gs1g
# cnTZEPpkbya8umMfF4pTMMRImXZUDKXuqon3+Ho8QB1H/onCETKbtUpibEDM6ddl
# rYhECI9I4TcFOHTt/Dbd4RzKmrfyilhlcmQEtuW7fxJ0ygpvCSaDKP9RL24a2pBo
# 07IXKEPKAK5x8nCMlKM5mP6dwyzs4VvHkrdWLW9mXJPCZqmlVjE6l04EFdxP2hNw
# AmiY5tB+gyMXMZGSug2hob66JHyx0hErQrHr7SRm6FgsNO3Lum5xpR/ueLAlD1sD
# 1PEgffv0UFgtFqolPGBNgxq1aisiYSi7+0Mev580uNzpP5pvMyb1ltAGro+W2MEy
# pUykPmMZjPH4X2ugAu6fAUSlB6GCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNDAzMDYxNDAw
# MDRaMC8GCSqGSIb3DQEJBDEiBCA567mW4Xic56rr5UZfp989u+WtZM5WbTACnqeL
# HJh5rTANBgkqhkiG9w0BAQEFAASCAgAe6C8+Os05kNO9vO6cQ6rV1vliXiqB+4lN
# BbvKgYGFMvdcDA9coZMB5aCdt+kmgnebJQ9PEBSZNoimLpDLmNzUx17B7eqmUS06
# XWjSFv6elzRbHP5wuKf7sGDFso0GxTzQ2fkdV0/DU27xGmrWHkpEzEEB0Pz/xALY
# U9NluWi0pdpX9Pw7wJMHejgEUN8QvN9ZlST9Y7rlSCpYwU/Z/tB31qxphbZPjf94
# m9/qyqXxLxtJWFn7IsGxJt1Bs5ksGlyfBDVHo64Ip0viJTM6kho7ZbqNNaXzzONB
# AbTAO7KZzy4+agNSa9nico3XM2qwiSEjA15ULawmzzWM4EHYvUfnZ7F38W4Ljl7q
# 9iBtewE6OJfK9IOMQuWZfUguKsdUU+SVMLrlGQZ3Wtb2edkQKIMmfrWao/iydIxc
# 3FmdwCzF/mh7Ly6vWi41oYSqiQ8+GmMDgnvLeivkoftdltojxZYryyuGAdCAfaph
# OZ/G7tY5sZKkREmKgndfY5rrIQhIDfnruoIURq5hnoTrnjHpefN7M7Md0u5bpKSi
# iB/J09soCHXTbp/+Gn2AQe3ro5t5I5/xR7Za8A2L9lChdulYUTiwodPLxV3NYnkX
# ThlbmiP5MYv2H+PDsMrElpuMwklCmYeJV2tKLxjRg5EstEbT+wKrVA1ENi9g0irr
# qjQAb/icbw==
# SIG # End signature block
