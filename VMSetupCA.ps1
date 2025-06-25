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
            CRLOverlapUnits = 90                        # 0
            CRLOverlapPeriod = 'Days'                   # Hours
            CRLDeltaPeriodUnits = 0                     # 1
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

            # CRL settings                              # Default
            CRLPeriodUnits = 10                         # 1
            CRLPeriod = 'Days'                          # Weeks
            CRLOverlapUnits = 5                         # 0
            CRLOverlapPeriod = 'Days'                   # Hours
            CRLDeltaPeriodUnits = 0                     # 1
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

            # CRL settings                              # Default
            CRLPeriodUnits = 10                         # 1
            CRLPeriod = 'Days'                          # Weeks
            CRLOverlapUnits = 5                         # 0
            CRLOverlapPeriod = 'Days'                   # Hours
            CRLDeltaPeriodUnits = 0                     # 1
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
            CRLPeriodUnits = 10                         # 1
            CRLPeriod = 'Days'                          # Weeks
            CRLOverlapUnits = 5                         # 0
            CRLOverlapPeriod = 'Days'                   # Hours
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

            foreach($Setting in (Get-Variable -Name PathLength, ValidityPeriodUnits, AuditFilter, CRLPeriod*,  CRLOverlap*, CRLPublicationURLs, CACertPublicationURLs))
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

        if (($PublishCRL.IsPresent -or
            (-not $CAConfigured -and $ParameterSetName -match 'Root')) -and
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
# MIIesgYJKoZIhvcNAQcCoIIeozCCHp8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBRu2R7i5MwPk8M
# hSQ6sdobgBDS0GOQy5WnPWzNuuUvfKCCGA4wggUHMIIC76ADAgECAhB0XMs0val9
# mEnBo5ekK6KYMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBUowTjdFMB4XDTIz
# MDkwNzE4NTk0NVoXDTI4MDkwNzE5MDk0NFowEDEOMAwGA1UEAwwFSjBON0UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRw1gJO1wnpdRIbqVo1gfsnMV8
# kxOJBp/FDV1XxyN0njKwlcA6zyudii33AqXYWUojp4xPoXzBGkVuoqqZOkSXHMz5
# /OScP3fe4QEtIC6X9vSQuWvo9jaih0kLbRUEBTG2EVRiHsVyeLR3DPgSNckbGJ54
# MMtlhFPchHo/N7BpaGrUtdjd+F59hDVDaeoe6VVYPVaC5yAgUR9QkJZw69+YkET4
# S+Q09WgoCoXEnrVnnjPzLq0iN0rdSOrhuBE5CouwUwr6YgjU6pwtEoyBaRUhL2cd
# 8UXLzVUgy9+Bo6mhJUtq1ujECc6afx26wkDYMwfo4vTdIgFv8XATvrvWyO0a4ZGn
# 6eU+eS+hWoURP2iVlYPGUY555F1NzeOVwQ9v1cumIaOVB8x+TjJxLCtomqfVxgO9
# JeHcrqW/Q55Itr9VBGUSk6a20oEQj94UwrvoNmkbEW+/XE6DWmHf7TWEJug5d4+7
# 2pI2TmGcisERv16qSzevlkN+uUTCMVSF32Qt7ZQoRocrscj37fHVaFOA1EpbMrOp
# RwX1pWWkNBGmWptQwkTMzHNFQiTTU0OrDjqCNRh63pWcg+qdAB7ZstaoMx4vdfo/
# twAfHDTnI403nUyrIEV1gLUyJ5i5Tgw6gh8g3ozq8Qaftq+PD1rhel+ByG23LZ42
# AhGD4q4ndfG13VEONQIDAQABo10wWzAOBgNVHQ8BAf8EBAMCBaAwKgYDVR0lBCMw
# IQYIKwYBBQUHAwMGCSsGAQQBgjdQAQYKKwYBBAGCNwoDBDAdBgNVHQ4EFgQUWNAE
# eD3ij461l5HFCgfSYoXMwCkwDQYJKoZIhvcNAQELBQADggIBAFKCUuzQ8KfuDfqI
# ZG+peeD9+r7qcvdlIt4tRdIOgVcqEncrrAVKIcEm0Fi1Zzs6cchsiDUUUUCLkYg/
# nowzCY3g2hjQOsE3QaWHgmr+WG6JqHnOz/2/9pS+3C8EPg1VfQb/Am5G5fr3tRBm
# u2RaeKcHjoEw9T6ASDVy2fRXjNDd9rOtyYmoP3EjAqU5ey/E4A7k4nnW5x2y5sPp
# CQlr77hsZ3keGgLz87XybHPphhqA6ddYk5vJuTB2QML0xSPLnBk0C/jwORQz44Ct
# t8zdml9wBVOcOt+7Omg4pORx2Bs37hVckL+XLUP3x/4ikQ7DVQi1fweDrtZ9T2xd
# whj5+CHMc8cXzri+nYX8bvmLTYyip5Gl47eC7C6bcNsoKQq2zlLVBecTumZ6p7hT
# n3mMJWEQt4HqJ+u+PS6VKU5TkYS3A1jlUvRPdwd6AGa1BcV9ChPq9ugXqb0juRWU
# oZPhYjwz9RBgJDZk/cdON1Ie31RwmyUYyoPGFuQYsfj0RI/mCFtF12WXbh2zDR0X
# 3qU4gSaEHTVQ0jPjROietordyS4l2euH/Z8dhvJwYeOSjCIxQlBqKFtkFEq8EeGs
# zs65D3oz2DwaTZEIip1fSU7yfbJLx+fMShZ7wVXATluADk3CXqJh2izO5tiCH6yJ
# Ux7YQVpSHQNdeltDcnGMwZ7mpUrXMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKR
# N6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZz
# lm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1Oco
# LevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH
# 92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRA
# p8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+g
# GkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU
# 8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/
# FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwj
# jVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQ
# EgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUae
# tdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftw
# ig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalW
# zxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQm
# h2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScb
# qyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLaf
# zYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbD
# Qc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0K
# XzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm
# 8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9
# gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8a
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrwwggSk
# oAMCAQICEAuuZrxaun+Vh8b56QTjMwQwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0y
# NDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5NTlaMEIxCzAJBgNVBAYTAlVTMREwDwYD
# VQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+anOf9pUhq5Ywultt5lmj
# tej9kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/i+utMeV5bUlYYSuuM4vQngvQepVH
# VzNLO9RDnEXvPghCaft0djvKKO+hDu6ObS7rJcXa/UKvNminKQPTv/1+kBPgHGlP
# 28mgmoCw/xi6FG9+Un1h4eN6zh926SxMe6We2r1Z6VFZj75MU/HNmtsgtFjKfITL
# utLWUdAoWle+jYZ49+wxGE1/UXjWfISDmHuI5e/6+NfQrxGFSKx+rDdNMsePW6FL
# rphfYtk/FLihp/feun0eV+pIF496OVh4R1TvjQYpAztJpVIfdNsEvxHofBf1BWka
# dc+Up0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZIqi6viEk3RIySho1XyHLIAOJfXG5
# PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj5KGg4YuiYx3e
# Ym33aebsyF6eD9MF5IDbPgjvwmnAalNEeJPvIeoGJXaeBQjIK13SlnzODdLtuThA
# LhGtyconcVuPI8AaiCaiJnfdzUcb3dWnqUnjXkRFwLtsVAxFvGqsxUA2Jq/WTjbn
# NjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi6n2PzP0nVepsFk8nlcuWfyZLzBaZ
# 0MucEdeBiXL+nUOGhCjl+QIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WM
# aiCPnshvMB0GA1UdDgQWBBSfVywDdw4oFZBmpWNe7k+SH3agWzBaBgNVHR8EUzBR
# ME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSB
# gzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsG
# AQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2EdubTggd0ShPz9Pce4FLJl6reNKLkZd5
# Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9NJxUl4JlKwyjUkKhk3aYx7D8vi2mpU1t
# KlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz57yFq6laICtKjPICYYf/qgxACHTv
# ypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlWjNlHlFFv/M93748YTeoXU/fFa9hW
# JQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZU1WM6nyw23vT6QSgwX5Pq2m0xQ2V
# 6FJHu8z4LXe/371k5QrN9FQBhLLISZi2yemW0P8ZZfx4zvSWzVXpAb9k4Hpvpi6b
# Ue8iK6WonUSV6yPlMwerwJZP/Gtbu3CKldMnn+LmmRTkTXpFIEB06nXZrDwhCGED
# +8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpPddOFkM2LlTbMcqFSzm4cd0boGhBq
# 7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwXu7nMpFu3mgrlgbAW+BzikRVQ3K2Y
# HcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2QwQ/l4Gxftt/8wY3grcc/nS//TVk
# ej9nmUYu83BDtccHHXKibMs/yXHhDXNkoPIdynhVAku7aRZOwqw6pDGCBfowggX2
# AgEBMCQwEDEOMAwGA1UEAwwFSjBON0UCEHRcyzS9qX2YScGjl6QropgwDQYJYIZI
# AWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgmECwRQRF8ErwdZND9fUi/ia1OMl7pMVh6S87zrHgzA8w
# DQYJKoZIhvcNAQEBBQAEggIAXEvJvNJx0T1J8d8qJRZGc6fYXsYO0pw6e/Cd6W7u
# SlhsWXQXBZkqRhWUZRlarMUpqoHfKUnhG3qHiV6O/0a8xz+mUs0/4Wq/7gSMEzKd
# iUxQHCMPT93obBttsR78vR57nkMSbatif7BUTxkcVuJmhKmJKGtHrTqw8QeV9PHY
# 7X6kNtha5Wep7UvKk5sd3cR8/P63XlOmQ/ER4tsYIamHC8xY0cF/a7XZMEm/TO91
# MgW061IeIvFcEjxilBEzUIqzetVSVqBXYZp78RAbvv7N0bK2gGEUbdKcWJswQ5nj
# miGf6VWAyE2OtbyfvdtRbPULt8Cnf2U33p7o+WV0jZKngIPQcgfpFdAkIfp7GF0y
# yLpxLAZiIuBkkdOAmYkw3Y0dOBoi9CBD02DO9Wlcgrmi9ui2wfUW/irbiwjaFb25
# 6JZ2o96Y5JdGoJMcDELPB9kWSVQMoHDN3egQidwc96Tcw/m6PREW6qJRCspiJvP4
# NjILieUysF21GHUCoKo8yGWkWsQ5PNaNHnQKwEhgaF1vkye9vKzd6BP6O6XVOsyH
# h2ecTw48cCYhDee5a/3ZaPgd7xEH0J7BuBAB6frJWSj6LKy8xqWUTlvdd6qSPYWM
# 4fwWU3gnVtWv1FFBKlJo+kQneDVwQG0m/GtZ877oDnOsYNhaSADSQ56WzN7mIpas
# 58mhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhALrma8Wrp/
# lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwNjI1MDAxNjE3WjAvBgkqhkiG9w0BCQQx
# IgQgC57xeRPyGBjyChnmmFWaKSPQU0KSVqQkWtbIpMGwDUAwDQYJKoZIhvcNAQEB
# BQAEggIABOj3MChlRmVlMRp5dH/ZXC+2f3aCyKzDk9teg1O11veEFTHkYJDtT00S
# CbgB7sbMF5cbm4+9zjMhreS5ED8wxrkP+kj3DhNh5vv3f92nTiVqvCnstByZbU9a
# 35RYmiZIOVG44Ix3BbL83V8XM2GaIwfH1I4IPR9RZ6/AJhW3Ief7SwPimFC/RZfe
# J8mxtatUaJYxOgvvjB4bEYZh9gjtCSpqrIT7aT7Q9D0Yo7kCR8nnZCrlUURoBzpF
# 5n2c9hjA04EFX6csyr/ISBTN9KoUvVaMBV0lGApnYHhV4Lc+TMqoc62PkBBLPDRG
# sUOhbwXV2diOUXndQ63Euwtis0Flmka25A6BXFIoFiE6TU7MvANeq0vnzDZkqERV
# 3QBWYFNxnTZphZC3bZICQENq3A2g2Jrf6x3iT21duJ+xX7bstN2vZ8nalmGOtYfo
# oitaEOgFnQDQQrPTPIp1UtzbY2RKCNQbnpe71h2UKPduudbGxg2C4nREDBzC/Qih
# ON4S8l2VN5Qc1vrU1MW+rcm7pGb4H3byR0pjRGwVk88SUUxG8Icl8mxJ/aupmqN8
# Cb3ekj4x5kSe2eNDtKK//5H0p02im9oPkk8K1n4oJVK8qYYLSeVoYpUD1fA3BXWo
# gigWdhvtpdBOluFow3NYB1hmoQoYp+jK86nQFezSekoUvLfzDL4=
# SIG # End signature block
