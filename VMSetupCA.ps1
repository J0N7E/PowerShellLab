<#
 .DESCRIPTION
    Setup and configure Certificate Authority
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

    # Default generic lazy pswd
    # FIX Parameterset for certfile
    $CertFilePassword = (ConvertTo-SecureString -String 'e72d4D6wYweyLS4sIAuKOif5TUlJjEpB' -AsPlainText -Force),

    # Type of CA
    [Parameter(Mandatory=$true)]
    [ValidateSet('StandaloneRootCA', 'EnterpriseRootCA', 'EnterpriseSubordinateCA')]
    [String]$CAType,

    # Certificate Authority CN
    # FIX Parameterset for new key
    [Parameter(Mandatory=$true)]
    [String]$CACommonName,

    # Standalone Root CA domain for DN suffix
    [Parameter(ParameterSetName='StandaloneRootCA', Mandatory=$true)]
    [String]$DomainName,

    # Root CA certificate lifespan
    [Parameter(ParameterSetName='StandaloneRootCA')]
    [Parameter(ParameterSetName='EnterpriseRootCA')]
    [String]$RenewalValidityPeriodUnits = '20',
    [Parameter(ParameterSetName='StandaloneRootCA')]
    [Parameter(ParameterSetName='EnterpriseRootCA')]
    [ValidateSet('Hours', 'Days', 'Weeks', 'Months', 'Years')]
    [String]$RenewalValidityPeriod = 'Years',

    # Subordinate CA installation parameters
    [Parameter(ParameterSetName='EnterpriseSubordinateCA', Mandatory=$true)]
    [String]$ParentCACommonName,

    # Path length
    [String]$PathLength,

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
    # FIX add custom provider
    #[String]$CustomCryptoProviderName,
    #   [Int]$CustomCryptoProviderType,

    # Path to certfile
    # FIX Parameterset for certfile
    [String]$CertFile,

    # CertKeyContainerName
    # FIX Parameterset for key container
    [String]$CertKeyContainerName,

    # Directory locations
    # https://www.sysadmins.lv/blog-en/install-adcscertificationauthority-issue-when-installing-an-offline-certification-authority.aspx
    [String]$LogDirectory = '$env:SystemRoot\System32\CertLog',
    [String]$DatabaseDirectory = '$env:SystemRoot\System32\CertLog',
    [String]$CertEnrollDirectory = '$env:SystemDrive\CertSrv\CertEnroll',

    # Post setup registry settings
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

    [String]$ValidityPeriodUnits,
    [ValidateSet('Hours', 'Days', 'Weeks', 'Months', 'Years')]
    [String]$ValidityPeriod,

    # Set log level
    [String]$AuditFilter = 127,

    # Set uri for publication
    [String]$PublicationURI,

    ###############################
    # Crl Distribution Point (CDP)
    ###############################

    # Add publishing UNCs
    [Array]$PublishingUNCs,

    # Custom CDP
    [String]$CRLPublicationURLs,

    #####################################
    # Authority Information Access (AIA)
    #####################################

    # Set hostname for OCSP
    [String]$OCSPHostName,

    # Custom AIA
    [String]$CACertPublicationURLs,

    ###########
    # Switches
    ###########

    [Switch]$UsePolicyNameConstraints,
    [Switch]$SkipPolicyFile,
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

    #################
    # Define presets
    #################

    $Preset =
    @{
        StandaloneRootCA =
        @{
            # CAPolicy parameters
            PathLength = 'None'

            # Post setup registry settings
            CRLPeriodUnits = 180
            CRLPeriod = 'Days'
            CRLOverlapUnits = 14
            CRLOverlapPeriod = 'Days'
            CRLDeltaPeriodUnits = 0
            CRLDeltaPeriod = 'Days'
            CRLDeltaOverlapUnits = 0
            CRLDeltaOverlapPeriod = 'Minutes'
            ValidityPeriodUnits = 10
            ValidityPeriod = 'Years'
        }

        EnterpriseRootCA =
        @{
            # CAPolicy parameters
            PathLength = 0

            # Post setup registry settings
            CRLPeriodUnits = 1
            CRLPeriod = 'Weeks'
            CRLOverlapUnits = 84
            CRLOverlapPeriod = 'Hours'
            CRLDeltaPeriodUnits = 0
            CRLDeltaPeriod = 'Days'
            CRLDeltaOverlapUnits = 0
            CRLDeltaOverlapPeriod = 'Minutes'
            ValidityPeriodUnits = 1
            ValidityPeriod = 'Years'
        }

        EnterpriseSubordinateCA =
        @{
            # CAPolicy parameters
            PathLength = 0

            # Post setup registry settings
            CRLPeriodUnits = 1
            CRLPeriod = 'Weeks'
            CRLOverlapUnits = 84
            CRLOverlapPeriod = 'Hours'
            CRLDeltaPeriodUnits = 0
            CRLDeltaPeriod = 'Days'
            CRLDeltaOverlapUnits = 0
            CRLDeltaOverlapPeriod = 'Minutes'
            ValidityPeriodUnits = 1
            ValidityPeriod = 'Years'
        }
    }

    # Set preset values for missing parameters
    foreach ($Var in $MyInvocation.MyCommand.Parameters.Keys)
    {
        if ($Preset.Item($CAType).ContainsKey($Var) -and
            -not (Get-Variable -Name $Var).Value)
        {
            Set-Variable -Name $Var -Value $Preset.Item($CAType).Item($Var)
        }
    }

    ##############
    # Deserialize
    ##############

    $Serializable =
    @(
        @{ Name = 'Session';                                  },
        @{ Name = 'Credential';         Type = [PSCredential] },
        @{ Name = 'CertFilePassword';   Type = [SecureString] },
        @{ Name = 'PublishingUNCs';     Type = [Array]        }
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
        }
        catch [Exception]
        {
            throw $_
        }

    } -NoNewScope

    ######################
    # Get parent ca files
    ######################

    # Initialize
    $ParentCAFiles = @{}
    $ParentCAResponseFile = $null

    if ($CAType -match 'Subordinate')
    {
        # Itterate all parent ca files
        foreach($file in (Get-Item -Path "$PSScriptRoot\$ParentCACommonName*"))
        {
            if ($file.Name -notmatch 'Response' -and
                $file.Name -notmatch '.req')
            {
                # Get file content
                $ParentCAFiles.Add($file, (Get-Content -Path $file.FullName -Raw))
            }
        }

        # Check crt
        if (-not $ParentCAFiles.GetEnumerator().Where({$_.Key.Name -match '.crt'}))
        {
            throw "Can't find `"$ParentCACommonName`" crt, aborting..."
        }

        # Check crl
        if (-not $ParentCAFiles.GetEnumerator().Where({$_.Key.Name -match '.crl'}))
        {
            throw "Can't find `"$ParentCACommonName`" crl, aborting..."
        }

        # Check response file
        $ParentCAResponse = Get-Item -Path "$PSScriptRoot\$CACommonName-Response.crt" -ErrorAction SilentlyContinue

        if ($ParentCAResponse -and
            (ShouldProcess @WhatIfSplat))
        {
            # Get file content
            $ParentCAResponseFile = Get-Content -Path $ParentCAResponse.FullName -Raw

            # Remove response file
            Remove-Item -Path $ParentCAResponse.FullName
        }
    }

    ###############
    # Get certfile
    ###############

    if ($CertFile -and (Test-Path -Path $CertFile -ErrorAction SilentlyContinue))
    {
        $CertFile = Get-Content -Path $CertFile -Raw
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
            throw "Must be administrator to setup Certficate Authority."
        }

        ###############
        # Check domain
        ###############

        $PartOfDomain = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty PartOfDomain

        # Check for part of domain
        if ($PartOfDomain)
        {
            $DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain
            $DomainNetbiosName = Get-CimInstance -ClassName Win32_NTDomain | Select-Object -ExpandProperty DomainName
        }
        elseif ($CAType -match 'Enterprise')
        {
            throw "Must be domain joined to setup Enterprise Subordinate CA."
        }

        # Get base dn
        $CADistinguishedNameSuffix = Get-BaseDn -DomainName $DomainName

        #####################
        # Create directories
        #####################

        # Expand vars
        $LogDirectory        = $ExecutionContext.InvokeCommand.ExpandString($LogDirectory)
        $DatabaseDirectory   = $ExecutionContext.InvokeCommand.ExpandString($DatabaseDirectory)
        $CertEnrollDirectory = $ExecutionContext.InvokeCommand.ExpandString($CertEnrollDirectory)

        # Check if directories exist
        foreach ($Directory in ($CertEnrollDirectory, $DatabaseDirectory, $LogDirectory))
        {
            if ($Directory -and -not (Test-Path -Path $Directory) -and
                (ShouldProcess @WhatIfSplat -Message "Creating `"$Directory`"" @VerboseSplat))
            {
                New-Item -ItemType Directory -Path $Directory > $null
            }
        }

# ██████╗  ██████╗ ██╗     ██╗ ██████╗██╗   ██╗
# ██╔══██╗██╔═══██╗██║     ██║██╔════╝╚██╗ ██╔╝
# ██████╔╝██║   ██║██║     ██║██║      ╚████╔╝
# ██╔═══╝ ██║   ██║██║     ██║██║       ╚██╔╝
# ██║     ╚██████╔╝███████╗██║╚██████╗   ██║
# ╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝   ╚═╝

##################
# Standalone Root
##################

$CAPolicy_StandaloneRootCA =
@"
[Version]
Signature="`$Windows NT$"

[BasicConstraintsExtension]
Critical=Yes

[Certsrv_Server]
RenewalKeyLength=$KeyLength
CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits
CRLDeltaPeriod=$CRLDeltaPeriod
AlternateSignatureAlgorithm=0
"@

if ($UsePolicyNameConstraints.IsPresent)
{
$CAPolicy_StandaloneRootCA += @"
[Strings]
szOID_NAME_CONSTRAINTS = "2.5.29.30"

[Extensions]
Critical = %szOID_NAME_CONSTRAINTS%
%szOID_NAME_CONSTRAINTS% = "{text}"

_continue_ = "SubTree=Include&"
_continue_ = "DNS = $DomainName&"
_continue_ = "DirectoryName = $CADistinguishedNameSuffix&"
_continue_ = "UPN = @$DomainName&"
_continue_ = "Email = @$DomainName&"
"@
}

##################
# Enterprise Root
##################

# FIX
# add parameters for issuance policy
# add oid parameter

$CAPolicy_EnterpriseRootCA =
@"
[Version]
Signature="`$Windows NT$"

[PolicyStatementExtension]
Policies=AllIssuancePolicy
Critical=No

[AllIssuancePolicy]
OID=2.5.29.32.0
Notice="All Issuance Policy"

[BasicConstraintsExtension]
Pathlength=$PathLength
Critical=Yes

[Certsrv_Server]
RenewalKeyLength=$KeyLength
CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits
CRLDeltaPeriod=$CRLDeltaPeriod
AlternateSignatureAlgorithm=0
LoadDefaultTemplates=0
"@

if ($UsePolicyNameConstraints.IsPresent)
{
$CAPolicy_StandaloneRootCA += @"
[Strings]
szOID_NAME_CONSTRAINTS = "2.5.29.30"

[Extensions]
Critical = %szOID_NAME_CONSTRAINTS%
%szOID_NAME_CONSTRAINTS% = "{text}"

_continue_ = "SubTree=Include&"
_continue_ = "DNS = $DomainName&"
_continue_ = "DirectoryName = $CADistinguishedNameSuffix&"
_continue_ = "UPN = @$DomainName&"
_continue_ = "Email = @$DomainName&"
"@
}

#########################
# Enterprise Subordinate
#########################

$CAPolicy_EnterpriseSubordinateCA =
@"
[Version]
Signature="`$Windows NT$"

[PolicyStatementExtension]
Policies=AllIssuancePolicy
Critical=No

[AllIssuancePolicy]
OID=2.5.29.32.0
Notice="All Issuance Policy"

[BasicConstraintsExtension]
Pathlength=$PathLength
Critical=Yes

[Certsrv_Server]
RenewalKeyLength=$KeyLength
CRLDeltaPeriodUnits=$CRLDeltaPeriodUnits
CRLDeltaPeriod=$CRLDeltaPeriod
AlternateSignatureAlgorithm=0
LoadDefaultTemplates=0
"@

if ($UsePolicyNameConstraints.IsPresent)
{
@"
[Strings]
szOID_NAME_CONSTRAINTS = "2.5.29.30"

[Extensions]
Critical = %szOID_NAME_CONSTRAINTS%
%szOID_NAME_CONSTRAINTS% = "{text}"

_continue_ = "SubTree=Include&"
_continue_ = "DNS = $DomainName&"
_continue_ = "DirectoryName = $CADistinguishedNameSuffix&"
_continue_ = "UPN = @$DomainName&"
_continue_ = "Email = @$DomainName&"
"@
}
        if (-not $SkipPolicyFile.IsPresent)
        {
            # Save CA policy to temp
            Set-Content -Value (Get-Variable -Name "CAPolicy_$($CAType)").Value -Path "$env:TEMP\CAPolicy.inf"

            # Move to systemroot if different
            Copy-DifferentItem -SourcePath "$env:TEMP\CAPolicy.inf" -Delete -TargetPath "$env:SystemRoot\CAPolicy.inf" @VerboseSplat
        }

        # ██████╗  ██████╗  ██████╗ ████████╗     ██████╗███████╗██████╗ ████████╗██╗███████╗██╗ ██████╗ █████╗ ████████╗███████╗
        # ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝
        # ██████╔╝██║   ██║██║   ██║   ██║       ██║     █████╗  ██████╔╝   ██║   ██║█████╗  ██║██║     ███████║   ██║   █████╗
        # ██╔══██╗██║   ██║██║   ██║   ██║       ██║     ██╔══╝  ██╔══██╗   ██║   ██║██╔══╝  ██║██║     ██╔══██║   ██║   ██╔══╝
        # ██║  ██║╚██████╔╝╚██████╔╝   ██║       ╚██████╗███████╗██║  ██║   ██║   ██║██║     ██║╚██████╗██║  ██║   ██║   ███████╗
        # ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝        ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

        if ($CAType -match 'Subordinate')
        {
            #############
            # Get hashes
            #############

            # Certificate
            $RootCertificateHashArray = TryCatch { certutil -store root "`"$ParentCACommonName`"" } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "Cert Hash\(sha1\): (.*)$"
            } | ForEach-Object { "$($Matches[1])" }

            # Crl
            $RootCrlHashArray = TryCatch { certutil -store root "`"$ParentCACommonName`"" } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "CRL Hash\(sha1\): (.*)$"
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
            $ParentFileCrlHashArray = @()

            # Itterate all parent ca files
            foreach($file in (Get-Item -Path "$env:TEMP\$ParentCACommonName\*"))
            {
                switch($file.Extension)
                {
                    '.crt'
                    {
                        # Get CA certificate hash
                        $ParentFileCertificateHash = TryCatch { certutil -dump "`"$($file.FullName)`"" } -ErrorAction SilentlyContinue | Where-Object {
                            $_ -match "Cert Hash\(sha1\): (.*)"
                        } | ForEach-Object { "$($Matches[1])" }

                        # Add cert hash to array
                        $ParentFileCertificateHashArray += $ParentFileCertificateHash

                        # Check if certificate hash is in root store
                        if ($ParentFileCertificateHash -notin $RootCertificateHashArray -and
                            (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Name)`" ($ParentFileCertificateHash) to root store." @VerboseSplat))
                        {
                            TryCatch { certutil -addstore root "`"$($file.FullName)`"" } -ErrorAction Stop > $null
                        }
                    }

                    '.crl'
                    {
                        # Get CA crl hash
                        $ParentFileCrlHash = TryCatch { certutil -dump "`"$($file.FullName)`"" } -ErrorAction SilentlyContinue | Where-Object {
                            $_ -match "CRL Hash\(sha1\): (.*)"
                        } | ForEach-Object { "$($Matches[1])" }

                        # Add crl hash to array
                        $ParentFileCrlHashArray += $ParentFileCrlHash

                       # Check if crl hash in CDP (Delta)
                        if (($ParentFileCrlHash -notin $RootCrlHashArray) -and
                            (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Name)`" ($ParentFileCrlHash) to root store." @VerboseSplat))
                        {
                            TryCatch { certutil -addstore root "`"$($file.FullName)`"" } -ErrorAction Stop > $null
                        }
                    }
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
                    TryCatch { certutil -delstore root "`"$CertificateHash`"" } > $null
                }
            }

            # Crl
            foreach($CrlHash in $RootCrlHashArray)
            {
                if ($CrlHash -notin $ParentFileCrlHashArray -and
                    (ShouldProcess @WhatIfSplat -Message "Remove crl ($CrlHash) from root store." @VerboseSplat))
                {
                    TryCatch { certutil -delstore root "`"$CrlHash`"" } > $null
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

        # Install CA
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

            if ($CertFile)
            {
                # Get content
                Set-Content -Path "$env:TEMP\$CACommonName.p12" -Value $CertFile

                # Certfile parameters
                $ADCSCAParams +=
                @{
                    'CertFilePassword' = $CertFilePassword
                    'CertFile' = "$env:TEMP\$CACommonName.p12"
                }
            }
            else
            {
                if ($CertKeyContainerName)
                {
                    # KeyContainerName parameters
                    $ADCSCAParams +=
                    @{
                        'KeyContainerName' = $CertKeyContainerName
                        #'IgnoreUnicode' = $true
                    }
                }
                else
                {
                    # Default parameters
                    $ADCSCAParams +=
                    @{
                        'CACommonName' = $CACommonName
                        'KeyLength' = $KeyLength
                    }
                }

                # Common parameters
                $ADCSCAParams +=
                @{
                    'CADistinguishedNameSuffix' = $CADistinguishedNameSuffix
                    'CryptoProviderName' = $CryptoProviderName
                    'HashAlgorithmName' = $HashAlgorithmName
                }

                if ($CAType -match 'Root')
                {
                    $ADCSCAParams +=
                    @{
                        'ValidityPeriod' = $RenewalValidityPeriod
                        'ValidityPeriodUnits' = $RenewalValidityPeriodUnits
                    }
                }

                if ($CAType -match 'Subordinate')
                {
                    $ADCSCAParams.Add('OutputCertRequestFile', "$CertEnrollDirectory\$CACommonName.req")
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

            try
            {
                if (ShouldProcess @WhatIfSplat -Message "Configuring Certificate Authority." @VerboseSplat)
                {
                    Install-AdcsCertificationAuthority @ADCSCAParams -Force > $null
                }

                if ($CAType -match 'Root')
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
                if (Test-Path -Path "$env:TEMP\$CACommonName.p12")
                {
                    Remove-Item -Path "$env:TEMP\$CACommonName.p12"
                }
            }
        }

        #  ██████╗ █████╗      ██████╗███████╗██████╗ ████████╗██╗███████╗██╗ ██████╗ █████╗ ████████╗███████╗
        # ██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝
        # ██║     ███████║    ██║     █████╗  ██████╔╝   ██║   ██║█████╗  ██║██║     ███████║   ██║   █████╗
        # ██║     ██╔══██║    ██║     ██╔══╝  ██╔══██╗   ██║   ██║██╔══╝  ██║██║     ██╔══██║   ██║   ██╔══╝
        # ╚██████╗██║  ██║    ╚██████╗███████╗██║  ██║   ██║   ██║██║     ██║╚██████╗██║  ██║   ██║   ███████╗
        #  ╚═════╝╚═╝  ╚═╝     ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

        if ($CAType -match 'Subordinate')
        {
            # Check if parent CA certificate request exist
            if (Test-Path -Path "$CertEnrollDirectory\*.req")
            {
                # Check if response file exist
                if ($ParentCAResponseFile -and
                    (ShouldProcess @WhatIfSplat -Message "Installing CA certificate..." @VerboseSplat))
                {
                    Set-Content -Path "$CertEnrollDirectory\$CACommonName-Response.crt" -Value $ParentCAResponseFile

                    # Try installing certificate
                    TryCatch { certutil -f -installcert "`"$CertEnrollDirectory\$CACommonName-Response.crt`"" } -ErrorAction Stop > $null

                    Restart-CertSvc

                    # Give CA some time to create certificate and crl
                    Start-Sleep -Seconds 3

                    # Cleanup
                    Remove-Item -Path "$CertEnrollDirectory\*.req"
                    Remove-Item -Path "$CertEnrollDirectory\$CACommonName-Response.crt"
                }
                else
                {
                    # Output requestfile
                    Write-Request -Path $CertEnrollDirectory
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
            # Define restart of service
            $Restart = $false

            ####################
            # Registry settings
            ####################

            # Set CertEnrollDirectory
            if ($Configuration.GetValue('CertEnrollDirectory') -ne $CertEnrollDirectory -and
                (ShouldProcess @WhatIfSplat -Message "Setting CertEnrollDirectory `"$CertEnrollDirectory`"" @VerboseSplat))
            {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name CertEnrollDirectory -Value $CertEnrollDirectory
            }

            $Restart = Set-CASetting -Key 'CRLPeriodUnits' -Value $CRLPeriodUnits -InputFlag $Restart
            $Restart = Set-CASetting -Key 'CRLPeriod' -Value $CRLPeriod -InputFlag $Restart
            $Restart = Set-CASetting -Key 'CRLOverlapUnits' -Value $CRLOverlapUnits -InputFlag $Restart
            $Restart = Set-CASetting -Key 'CRLOverlapPeriod' -Value $CRLOverlapPeriod -InputFlag $Restart
            $Restart = Set-CASetting -Key 'CRLDeltaPeriodUnits' -Value $CRLDeltaPeriodUnits -InputFlag $Restart
            $Restart = Set-CASetting -Key 'CRLDeltaPeriod' -Value $CRLDeltaPeriod -InputFlag $Restart
            $Restart = Set-CASetting -Key 'ValidityPeriodUnits' -Value $ValidityPeriodUnits -InputFlag $Restart
            $Restart = Set-CASetting -Key 'ValidityPeriod' -Value $ValidityPeriod -InputFlag $Restart
            $Restart = Set-CASetting -Key 'AuditFilter' -Value $AuditFilter -InputFlag $Restart

            ######
            # CDP
            # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831574(v=ws.11)#publish-the-cdp-extension
            ######

            # Check if exist
            if (-not $CRLPublicationURLs)
            {
                # Initialize
                $PublishToServer = 0

                if ($CRLPeriodUnits -gt 0)
                {
                    $PublishToServer += 1
                }

                if ($CRLDeltaPeriodUnits -gt 0)
                {
                    $PublishToServer += 64
                }

                # Set default CDP
                $CRLPublicationURLs = "$($PublishToServer):$env:SystemRoot\System32\CertSrv\CertEnroll\%3%8%9.crl"

                if ($CertEnrollDirectory -ne "$env:SystemRoot\System32\CertSrv\CertEnroll")
                {
                    $CRLPublicationURLs += "\n$($PublishToServer):$CertEnrollDirectory\%3%8%9.crl"
                }

                # Itterate unc
                foreach ($Item in $PublishingUNCs)
                {
                    # Add unc
                    $CRLPublicationURLs += "\n$($PublishToServer):$Item\\%3%8%9.crl"
                }

                # Initialize
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
                if ($PublicationURI)
                {
                    # Add CDP url
                    $CRLPublicationURLs += "\n$($AddTo):http://$PublicationURI/%3%8%9.crl"
                }
                else
                {
                    # Add default CDP url
                    $CRLPublicationURLs += "\n$($AddTo):http://pki.$DomainName/%3%8%9.crl"
                }
            }

            # Set Crl Distribution Point (CDP)
            $Restart = Set-CASetting -Key 'CRLPublicationURLs' -Value $CRLPublicationURLs -InputFlag $Restart

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
                if ($OCSPHostName)
                {
                    # Add OCSP url
                    $CACertPublicationURLs += "\n32:http://$OCSPHostName/ocsp"
                }
                elseif ($CAType -match 'Subordinate')
                {
                    # Add default OCSP url
                    $CACertPublicationURLs += "\n32:http://pki.$DomainName/ocsp"
                }

                # Check if exist
                if ($PublicationURI)
                {
                    # Add AIA url
                    $CACertPublicationURLs += "\n2:http://$PublicationURI/%3%4.crt"
                }
                else
                {
                    # Add default AIA url
                    $CACertPublicationURLs += "\n2:http://pki.$DomainName/%3%4.crt"
                }
            }

            # Set Authority Information Access (AIA)
            $Restart = Set-CASetting -Key 'CACertPublicationURLs' -Value $CACertPublicationURLs -InputFlag $Restart

            #############
            # Standalone
            #############

            if ($CAType -match 'Standalone')
            {
                # Add domain configuration for standalone ca
                $Restart = Set-CASetting -Key 'DSConfigDN' -Value "CN=Configuration,$CADistinguishedNameSuffix" -InputFlag $Restart

                if ($OCSPHostName)
                {
                    # Enable ocsp extension requests
                    $Restart = Set-CASetting -Type Policy -Key 'EnableRequestExtensionList' -Value '+1.3.6.1.5.5.7.48.1.5' -InputFlag $Restart

                    # Enable ocsp no revocation check for standalone ca
                    $Restart = Set-CASetting -Type Policy -Key 'EditFlags' -Value '+EDITF_ENABLEOCSPREVNOCHECK' -InputFlag $Restart
                }
            }

            #############
            # Enterprise
            #############

            if ($CAType -match 'Enterprise')
            {
                # Add logging for changes to templates
                $Restart = Set-CASetting -Type Policy -Key 'EditFlags' -Value '+EDITF_AUDITCERTTEMPLATELOAD' -InputFlag $Restart
            }

            ##########
            # Restart
            ##########

            if ($Restart)
            {
                Restart-CertSvc
            }
        }

        ######################
        # Standalone Auditing
        ######################

        if ($CAType -match 'Standalone')
        {
            # Check auditing
            if ((((auditpol /get /subcategory:"Certification Services") -join '') -notmatch 'Success and Failure') -and
                (ShouldProcess @WhatIfSplat -Message "Enabling Object Access Certification Services Success and Failure auditing." @VerboseSplat))
            {
                TryCatch { auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable } > $null
            }
        }

        #######################
        # Enterprise Templates
        #######################

        if ($CAType -match 'Enterprise' -and $PublishTemplates.IsPresent)
        {
            # Get AD templates
            $ADTemplates = TryCatch { certutil -ADTemplate } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "^($DomainNetbiosName.*?):.*"
            } | ForEach-Object { "$($Matches[1])" }

            # Get CA templates
            $CATemplates = (Get-CATemplate).Name

            foreach($Template in $ADTemplates)
            {
                if ($Template -notin $CATemplates -and
                    (ShouldProcess @WhatIfSplat -Message "Adding template `"$Template`" to issue." @VerboseSplat))
                {
                    Add-CATemplate -Name $Template -Confirm:$false
                }
            }
        }

        # ██████╗ ██╗   ██╗██████╗ ██╗     ██╗███████╗██╗  ██╗
        # ██╔══██╗██║   ██║██╔══██╗██║     ██║██╔════╝██║  ██║
        # ██████╔╝██║   ██║██████╔╝██║     ██║███████╗███████║
        # ██╔═══╝ ██║   ██║██╔══██╗██║     ██║╚════██║██╔══██║
        # ██║     ╚██████╔╝██████╔╝███████╗██║███████║██║  ██║
        # ╚═╝      ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝

        if ($PublishCRL.IsPresent -and
            (ShouldProcess @WhatIfSplat -Message "Publishing CRL..." @VerboseSplat))
        {
            TryCatch { certutil -crl } > $null

            # Give CA some time to create crl
            Start-Sleep -Seconds 3
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
            Backup-CARoleService -KeyOnly -Path "$env:TEMP" -Password $CertFilePassword

            # Inform
            Write-Warning -Message "Using password `"$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertFilePassword)))`" for `"$CACommonName.p12`""

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
            # f_ShouldProcess.ps1 loaded in Begin
            . $PSScriptRoot\f_CopyDifferentItem.ps1
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
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CopyDifferentItem.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_GetBaseDN.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetCASetting.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_RestartCertSvc.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_WriteRequest.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Splat
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $ComputerName = $Using:ComputerName

            # Standalone/Root/Enterprise/Subordinate
            $CAType = $Using:CAType

            # Certificate Authority common name
            $CACommonName = $Using:CACommonName

            # Standalone Root CA domain for DN suffix
            $DomainName = $Using:DomainName

            # Root CA certificate lifespan
            $RenewalValidityPeriodUnits = $Using:RenewalValidityPeriodUnits
            $RenewalValidityPeriod = $Using:RenewalValidityPeriod

            # Subordinate CA installation parameters
            $ParentCACommonName = $Using:ParentCACommonName
            $ParentCAFiles = $Using:ParentCAFiles
            $ParentCAResponseFile = $Using:ParentCAResponseFile

            # Path length
            $PathLength = $Using:PathLength

            # Crypto params
            $HashAlgorithmName = $Using:HashAlgorithmName
            $KeyLength = $Using:KeyLength
            $CryptoProviderName = $Using:CryptoProviderName

            # CertFile
            $CertFile = $Using:CertFile
            $CertFilePassword = $Using:CertFilePassword

            $CertKeyContainerName = $Using:CertKeyContainerName

            # Directory locations
            $LogDirectory = $Using:LogDirectory
            $DatabaseDirectory = $Using:DatabaseDirectory
            $CertEnrollDirectory = $Using:CertEnrollDirectory

            # Post setup registry settings
            $CRLPeriodUnits = $Using:CRLPeriodUnits
            $CRLPeriod = $Using:CRLPeriod
            $CRLOverlapUnits = $Using:CRLOverlapUnits
            $CRLOverlapPeriod = $Using:CRLOverlapPeriod
            $CRLDeltaPeriodUnits = $Using:CRLDeltaPeriodUnits
            $CRLDeltaPeriod = $Using:CRLDeltaPeriod
            $CRLDeltaOverlapUnits = $Using:CRLDeltaOverlapUnits
            $CRLDeltaOverlapPeriod = $Using:CRLDeltaOverlapPeriod
            $ValidityPeriodUnits = $Using:ValidityPeriodUnits
            $ValidityPeriod = $Using:ValidityPeriod
            $AuditFilter = $Using:AuditFilter

            # Set uri for publication
            $PublicationURI = $Using:PublicationURI

            ###############################
            # Crl Distribution Point (CDP)
            ###############################

            # Add publishing UNCs
            $PublishingUNCs = $Using:PublishingUNCs

            # Custom CDP
            $CRLPublicationURLs = $Using:CRLPublicationURLs

            #####################################
            # Authority Information Access (AIA)
            #####################################

            # Set hostname for OCSP
            $OCSPHostName = $Using:OCSPHostName

            # Custom AIA
            $CACertPublicationURLs = $Using:CACertPublicationURLs

            ###########
            # Switches
            ###########

            $UsePolicyNameConstraints = $using:UsePolicyNameConstraints
            $SkipPolicyFile = $Using:SkipPolicyFile
            $PublishTemplates = $Using:PublishTemplates
            $PublishCRL = $Using:PublishCRL
            $ExportCertificate = $Using:ExportCertificate
        }

        # Run main
        $Result = Invoke-Command -Session $Session -ScriptBlock $MainScriptBlock
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
# MIIXpgYJKoZIhvcNAQcCoIIXlzCCF5MCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+HULQOMr58E2/OqnP/vTP4eU
# ugCgghI6MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBT68yMvw4Qs+m3GY8u+nP03
# GhsGHzANBgkqhkiG9w0BAQEFAASCAgBP7jOkkUByaZgXrOhxr0PTylPueu2If6jD
# n6e4j2jaK9mgcbvrS2rd9DCPuSSC3EiGgGWJYOCtCM7ovArEsfgvQvbPXMcXUxMz
# IK8u03ejqTEJuBp/EQFI32TDHqErbD0LYnsL8rsofJkuSPMjeHX8Kes4gmRhWErl
# YXpyzNu7Dash168CWLyN7GhiFRh78YRL5Gt86y1exW67sJZweCJlBuinSwNeXrUi
# W1RRTDVJQ4LyIw72k+lPjomnH14PdJYEfjW8S+roM2g1fzcIhgImd6HW1O3CthuO
# JreFfe7AnhGvhFibXxXAz/qgTJEPviJsl8IM71dCJksNfbako5gO0M4sfrmO3egP
# UHr2p4SPGoVOQxpEFeeV8XVZe2BbJNyLmRspftujbSCXTLMSs+7L/KRDdXZxk1og
# 2N9U3QHa+L2q2Q7SRelmXsDCvCpoccUMZwrfyampJkAfTfmHNnYSeD1/RiYSZlHp
# 1zkXuCps5kz1Gonf8z4q6rdsvYAxVvrAncO2IFT0wYqQ9IPiL0J3b2FTUC4W++kq
# dzleS3mHyf4R9VzYslEC1CHEL/lAw1sLEubroVkUanC86Cc19w/zFeNvuEakUXkG
# jUb/1ohZETPgIHSV9DNAHSpTQDEm1YsJJne4L3N+6jVQvY075/9lHtG03LNBlpVJ
# vw2u/IxlNKGCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAxMDEzMTYwMDA1WjAjBgkqhkiG9w0BCQQx
# FgQUpDGdKOgU/K19vmCDhj5rAcGti94wDQYJKoZIhvcNAQEBBQAEggEAOcGSmShW
# UQW++FiBuQujfVOg4l9U+h7vKP87PngQbg3kGKuiHCPbH8rSwsNIIIonPT8rYMs+
# iPuNh3VZxsbi/RtMUkGX0+QGUEy1Ipw7HeKQjGXwF6ziKk7WIQCnt6oNkHAneuJe
# 8EwDKvlTcFbFabUpfV7tAgC/zIgmdxeh/+Xa6C+s1jpi+Dto4lqaXh7Kg4+EIkBl
# U2nFkVe6xxeNCcUnWKr0q9nGoBhaxflqh2/i8+7Zk51LuEl/A8kiZC4ySv7HjNwv
# WfmfBfKo0AhAw8HrrArZU1XgX3jpQaPbBfD0fhLVLxVQIVTyTtX4J0Gx1e7E9m5w
# EftWHHj0Tb1vPw==
# SIG # End signature block
