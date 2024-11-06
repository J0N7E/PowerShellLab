
########
# Paths
########

$HvDrive = "$env:SystemDrive\HvLab"
$OsdPath = "$env:SystemDrive\OSDBuilder"

if (-not $LabPath)
{
    $Paths = @(
       "$env:Documents\WindowsPowerShell\PowerShellLab",
       (Get-Location).Path
    )

    foreach ($Path in $Paths)
    {
        if (Test-Path -Path $Path)
        {
            $LabPath = Set-Location -Path $Path -ErrorAction SilentlyContinue -PassThru | Select-Object -ExpandProperty Path
            break
        }
    }
}

###########
# Settings
###########

# Get domain name
if (-not $DomainName)
{
    do
    {
        $Global:DomainName = Read-Host -Prompt "Choose a domain name (FQDN)"
    }
    until($DomainName -match '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)')

    $Global:DomainNetbiosName = $DomainName.Substring(0, $DomainName.IndexOf('.'))
    $Global:DomainPrefix = $DomainNetBiosName.Substring(0, 1).ToUpper() + $DomainNetBiosName.Substring(1)
}

# Password
$Settings = @{ Pswd = (ConvertTo-SecureString -String 'P455w0rd' -AsPlainText -Force) }

# Credentials
$Settings +=
@{
    Lac   = New-Object -ArgumentList ".\administrator", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    Dac   = New-Object -ArgumentList "$($DomainNetbiosName + '\tdcadm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    Ac0   = New-Object -ArgumentList "$($DomainNetbiosName + '\t0adm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    Ac1   = New-Object -ArgumentList "$($DomainNetbiosName + '\t1adm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    Ac2   = New-Object -ArgumentList "$($DomainNetbiosName + '\t2adm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
}

$Settings +=
@{
    Switches =
    @(
        @{ Name = 'Lab';     Type = 'Private';   NetworkId = '192.168.0';  GW = '192.169.0.1';  DNS = '192.168.0.10' }
    )
    VMs = [ordered]@{

        RootCA = @{ Name = 'CA01';    Domain = $false;  OSVersion = '*Experience x64 21H2*';     Switch = @();       Credential = $Settings.Lac; }
        DC     = @{ Name = 'DC01';    Domain = $false;  OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Dac; }
        SubCA  = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
        AS     = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
        ADFS   = @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Experience x64 21H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
        WIN    = @{ Name = 'WIN11';   Domain = $true;   OSVersion = '*11 Enterprise x64 23H2*';  Switch = @('Lab');  Credential = $Settings.Ac2; }
    }
}

############
# Functions
############

function Serialize
{
    [alias('ser')]
    param
    (
        [Parameter(Position=0, Mandatory=$true)]
        $InputObject
    )

    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([System.Management.Automation.PSSerializer]::Serialize($InputObject)))
}

function Deserialize
{
    [alias('dser')]
    param
    (
        [Parameter(Position=0, Mandatory=$true)]
        $InputObject
    )

    [Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($InputObject)))
}

function Setup-VMs
{
    param
    (
        [switch]$Wait,
        [switch]$NoExit,
        [switch]$Create,
        [switch]$Network,
        [switch]$Rename
    )

    # Check parameters
    if ($NoExit.IsPresent)
    {
        $NoExitStr = '-NoExit '
    }
    else
    {
        $NoExitStr = ''
    }

    if ($Wait.IsPresent)
    {
        $WaitSplat = @{ Wait = $true }
    }
    else
    {
        $WaitSplat = @{ Wait = $false }
    }

    foreach ($VM in $Settings.VMs.GetEnumerator())
    {
        if ($Create.IsPresent)
        {
            # Get latest os media
            $OSMedia = Get-Item -Path "$OsdPath\OSMedia\$($VM.Value.OSVersion)" -ErrorAction SilentlyContinue | Select-Object -Last 1

            # Get latest vhdx
            $OSVhdx = Get-Item -Path "$OsdPath\OSMedia\$($OSMedia.Name)\VHD\OSDBuilder.vhdx" -ErrorAction SilentlyContinue | Select-Object -Last 1

            if (-not $OSVhdx)
            {
                Write-Warning -Message "No VHDX found for `"$($VM.Value.Name)`""
            }
            else
            {
                if ($VM.Value.Switch.Length -gt 0)
                {
                    $VMAdapters = " -VMAdapters $(Serialize $VM.Value.Switch)"
                }

                Start-Process $PowerShell @WaitSplat -ArgumentList `
                @(
                    "$NoExitStr-File $LabPath\LabNewVM.ps1 -Verbose$VMAdapters",
                    "-LabFolder `"$HvDrive`"",
                    "-VMName $($VM.Value.Name)",
                    "-Vhdx `"$OSVhdx`""
                )
            }
        }
        elseif ($VM.Value.Name -ne $Settings.VMs.DC.Name -and (Get-VM -Name $VM.Value.Name -ErrorAction SilentlyContinue).State -eq 'Running')
        {
            if ($Network.IsPresent)
            {
                Start-Process $PowerShell @WaitSplat -ArgumentList `
                @(
                    "$NoExitStr-File $LabPath\VMSetupNetwork.ps1 $Lac -Verbose",
                    "-VMName $($VM.Value.Name)",
                    "-AdapterName Lab",
                    "-DNSServerAddresses $(Serialize @(`"$($Lab.DNS)`"))"
                )
            }
            elseif ($Rename.IsPresent)
            {
                Start-Process $PowerShell @WaitSplat -ArgumentList `
                @(
                    "$NoExitStr-File $LabPath\VMRename.ps1 $Lac -Verbose",
                    "-VMName $($VM.Value.Name) -Restart"
                )
            }
        }
    }
}

function Setup-DC
{
    [cmdletbinding(DefaultParameterSetName='Standard')]
    param
    (
        [String]$VMName,
        [Array]$DomainJoin,

        [Switch]$SetupADDSOnly,

        [Switch]$CopyGpo,
        [Switch]$CopyBaseline,
        [Switch]$CopyTemplates,

        [Switch]$BackupGpo,
        [Switch]$BackupTemplates,
        [Switch]$BackupReplace,

        [Nullable[Bool]]$SetupAdfs,
        [Nullable[Bool]]$RestrictDomain,
        [Nullable[Bool]]$EnableIPSec
    )

    # Initialize
    $NoExitStr = '-NoExit '
    $WaitSplat = @{ Wait = $false }
    $ParamArray = @()

    if (-not $VMName)
    {
        $VMName = 'DC01'
        $PSBoundParameters.Add('VMName', $VMName)
    }

    # Itterate parameters
    foreach ($Param in $PSBoundParameters.GetEnumerator())
    {
        switch ($Param.Key)
        {
            { $_ -eq 'CopyGpo' }
            {
                $ParamArray += "-GPOPath `"$LabPath\Gpo`""
            }

            { $_ -eq 'CopyBaseline' }
            {
                $ParamArray += "-BaselinePath `"$LabPath\Baseline`""
            }

            { $_ -eq 'CopyTemplates' }
            {
                $ParamArray += "-TemplatePath `"$LabPath\Templates`""
            }

            { $_ -match 'BackupReplace' }
            {
                # Open session
                $Session = New-PSSession -VMName $VMName -Credential $Settings.Lac -ErrorAction SilentlyContinue

                $NoExitStr = ''
                $WaitSplat = @{ Wait = $true }
            }

            { ($_ -in @('DomainJoin', 'SetupAdfs', 'RestrictDomain', 'EnableIPSec') -and
               $Param.Value -notlike $null) }
            {
                $ParamArray += "-$($Param.Key) $(Serialize $Param.Value)"
            }

            default
            {
                if ($Param.Value -is [Switch])
                {
                    $ParamArray += "-$($Param.Key)"
                }
                elseif ($Param.Value -notlike $null)
                {
                    $ParamArray += "-$($Param.Key) $($Param.Value)"
                }
            }
        }
    }

    # Default argumentlist
    $Argumentlist =
    @(
        "$NoExitStr-File $LabPath\VMSetupDC.ps1 $Lac -Verbose",
        "-DomainNetworkId $($Lab.NetworkId)",
        "-DomainName $DomainName",
        "-DomainNetbiosName $DomainNetbiosName",
        "-DomainLocalPassword $(Serialize $Settings.Pswd)"
    ) + $ParamArray

    # Invoke with parameters
    Start-Process @WaitSplat -FilePath $PowerShell -ArgumentList $Argumentlist

    # Function retries to remove files in use
    function Retry-Remove
    {
        param
        (
            [string]$Path
        )

        do
        {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue

            if (-not (Test-Path -Path $Path))
            {
                $Removed = $true
            }
            else
            {
                $Removed = $false
                Start-Sleep -Milliseconds 3
            }
        }
        while (-not $Removed)
    }

    if ($BackupReplace.IsPresent -and $Session)
    {
        # Check if to backup gpos
        if ($BackupGpo.IsPresent)
        {
            Retry-Remove -Path "$LabPath\Gpo"

            # Copy gpo backups
            Copy-Item -FromSession $Session -Path "C:\Users\Administrator\AppData\Local\Temp\GpoBackup" -Recurse -Destination "$LabPath\Gpo"
        }

        # Check if to backup templates
        if ($BackupTemplates.IsPresent)
        {
            Retry-Remove -Path "$LabPath\Templates"

            # Copy template backups
            Copy-Item -FromSession $Session -Path "C:\Users\Administrator\AppData\Local\Temp\TemplatesBackup" -Recurse -Destination "$LabPath\Templates"
        }

        # Remove session
        $Session | Remove-PSSession
    }
}

#############
# Initialize
#############

# Switches
foreach ($Switch in $Settings.Switches)
{
    New-Variable -Name $Switch.Name -Value $Switch -Force

    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and
        -not (Get-VMSwitch -Name $Switch.Name -ErrorAction SilentlyContinue))
    {
        New-VMSwitch -Name $Switch.Name -SwitchType $Switch.Type > $null
        Get-NetAdapter -Name "vEthernet ($($Switch.Name))" -ErrorAction SilentlyContinue | Rename-NetAdapter -NewName $Switch.Name
    }
}

# Credential splats
$Settings.GetEnumerator() | Where-Object { $_.Value -is [PSCredential] } | ForEach-Object {

    New-Variable -Name $_.Name -Value "-Credential $(Serialize $_.Value)" -Force
}

# VM splats
$Settings.VMs.GetEnumerator() | ForEach-Object {

    New-Variable -Name $_.Name -Value "-VMName $($_.Value.Name)" -Force
}

if ((Invoke-Command -ScriptBlock{ pwsh -version } 2>&1))
{
    $PowerShell = 'pwsh'
}
else
{
    $PowerShell = 'powershell'
}

return

#########
# DC
# Step 1
#########

# Rename
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 $DC $Lac -Verbose -Restart"
)

# Setup network
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 $DC $Lac -Verbose",
    "-AdapterName Lab",
    "-IPAddress `"$($Lab.DNS)`"",
    "-DefaultGateway `"$($Lab.GW)`"",
    "-DNSServerAddresses $(Serialize @(`"$($Lab.DNS)`"))"
)

# Setup DC Step 1
Setup-DC

##########
# Root CA
##########

# Rename
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 $RootCA $Lac -Verbose -Restart"
)

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCA.ps1 $RootCA $Lac -Verbose",
    "-Force",
    #"-AlwaysPrompt",
    "-StandaloneRootCA",
    "-CACommonName `"$DomainPrefix Root $($Settings.VMs.RootCA.Name)`"",
    "-CADistinguishedNameSuffix `"O=$DomainPrefix,C=SE`"",
    "-DomainName $DomainName"
)

<#
    # Remove root CA
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMRemoveCA.ps1 $RootCA $Lac -Verbose",
        "-CACommonName `"$DomainPrefix Root $($Settings.VMs.RootCA.Name)`""
    )
#>

################
# Setup network
################

Setup-VMs -Network

#########
# DC
# Step 2
#########

# Wait for DC to complete step 1 setup before continuing...

# Setup network
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 $DC $Lac -Verbose",
    "-AdapterName Lab",
    "-IPAddress `"$($Lab.DNS)`"",
    "-DefaultGateway `"$($Lab.GW)`"",
    "-DNSServerAddresses $(Serialize @(`"$($Lab.DNS)`", '127.0.0.1'))"
)

# Setup DC Step 2
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupDC.ps1 $DC $Lac -Verbose",
    "-DomainNetworkId $($Lab.NetworkId)",
    "-DomainName $DomainName",
    "-DomainNetbiosName $DomainNetbiosName",
    "-DomainLocalPassword $(Serialize $Settings.Pswd)",
    "-GPOPath `"$LabPath\Gpo`"",
    "-BaselinePath `"$LabPath\Baseline`"",
    "-TemplatePath `"$LabPath\Templates`""
)

# Publish root certificate to domain
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureAD.ps1 $DC $Dac -Verbose",
    "-CAType StandaloneRootCA",
    "-CAServerName $($Settings.VMs.RootCA.Name)",
    "-CACommonName `"$DomainPrefix Root $($Settings.VMs.RootCA.Name)`""
)

<#
    # Remove root certificate from domain
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMRemoveCAFromAD.ps1 $DC $Dac -Verbose",
        "-CAServerName $($Settings.VMs.RootCA.Name)",
        "-CACommonName `"$DomainPrefix Root $($Settings.VMs.RootCA.Name)`""
    )
#>

##############
# Join domain
##############

Setup-VMs -Rename

# Rerun DC setup step 1 to configure AD
Setup-DC

#########
# AS
# Step 1
#########

# Root cdp
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureWebServer.ps1 $AS $Ac0 -Verbose",
    "-Force",
    "-CAConfig `"$($Settings.VMs.RootCA.Name).$DomainName\$DomainPrefix Root $($Settings.VMs.RootCA.Name)`"",
    "-ConfigureIIS",
    "-ShareAccess `"Cert Publishers`""
)

#########
# Sub CA
# Step 1
#########

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCA.ps1 $SubCA $Ac0 -Verbose",
    "-Force",
    #"-AlwaysPrompt",
    "-EnterpriseSubordinateCA",
    "-CACommonName `"$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)`"",
    "-CADistinguishedNameSuffix `"O=$DomainPrefix,C=SE`"",
    "-PublishAdditionalPaths $(Serialize @(`"\\$($Settings.VMs.AS.Name)\wwwroot$`"))",
    "-PublishTemplates",
    #"-CryptoProviderName `"RSA#SafeNet Key Storage Provider`"",
    #"-KeyContainerName `"$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)`"",
    #"-IssuancePolicies $(Serialize (@( @{Name='Policy1'; OID='1.2.3'}, @{Name='Policy2'; OID='4.5.6'})))",
    "-CRLPeriodUnits 180",
    "-CRLPeriod Days",
    "-CRLOverlapUnits 14",
    "-CRLOverlapPeriod Days"
)

<#
    # Remove sub CA
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMRemoveCA.ps1 $SubCA $Ac0 -Verbose",
        "-ParentCACommonName `"$DomainPrefix Root $($Settings.VMs.RootCA.Name)`"",
        "-CACommonName `"$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)`""
    )

    # Remove sub CA certificate from domain
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMRemoveCAFromAD.ps1 $DC $Dac -Verbose",
        "-CAServerName $($Settings.VMs.SubCA.Name)",
        "-CACommonName `"$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)`""
    )

    # Configure sub CA in AD
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMSetupCAConfigureAD.ps1 $DC $Dac -Verbose",
        "-Force",
        "-RemoveOld",
        "-CAType EnterpriseSubordinateCA",
        "-CAServerName $($Settings.VMs.SubCA.Name)",
        "-CACommonName `"$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)`""
    )
#>

##########
# Root CA
##########

# Issue Sub CA
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAIssueCertificate.ps1 -Verbose $RootCA $Lac",
    "-CertificateSigningRequest `"$LabPath\$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)-Request.csr`""
)

#########
# Sub CA
# Step 2
#########

# Rerun sub CA setup step 1 (above) to install certificate

#########
# AS
# Step 2
#########

# Issuing CDP & OCSP
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureWebServer.ps1 $AS $Ac0 -Verbose",
    "-Force",
    "-CAConfig `"$($Settings.VMs.SubCA.Name).$DomainName\$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)`"",
    "-ConfigureOCSP",
    "-OCSPTemplate `"$($DomainPrefix)OCSPResponseSigning`""
)

# NDES
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureWebServer.ps1 $AS $Ac0 -Verbose",
    "-Force",
    "-CAConfig `"$($Settings.VMs.SubCA.Name).$DomainName\$DomainPrefix Enterprise $($Settings.VMs.SubCA.Name)`"",
    "-ConfigureNDES"
 )

######
# RAS
######

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 $RAS $Ac1 -Verbose",
    "-AdapterName LabDmz",
    "-IPAddress `"$($LabDms.NetworkId).200`"",
    "-DefaultGateway `"$($LabDmz.GW)`"",
    "-DNSServerAddresses $(Serialize @(`"$($LabDmz.DNS)`"))"
)

# SIG # Begin signature block
# MIIejQYJKoZIhvcNAQcCoIIefjCCHnoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUzKe2X9+aHaGr6KyeK2xs9qeJ
# Zl+gghgOMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwgga8MIIEpKADAgECAhALrma8Wrp/lYfG+ekE
# 4zMEMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjQwOTI2MDAwMDAwWhcNMzUxMTI1
# MjM1OTU5WjBCMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxIDAeBgNV
# BAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDI0MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvmpzn/aVIauWMLpbbeZZo7Xo/ZEfGMSIO2qZ46XB/QowIEMS
# vgjEdEZ3v4vrrTHleW1JWGErrjOL0J4L0HqVR1czSzvUQ5xF7z4IQmn7dHY7yijv
# oQ7ujm0u6yXF2v1CrzZopykD07/9fpAT4BxpT9vJoJqAsP8YuhRvflJ9YeHjes4f
# duksTHulntq9WelRWY++TFPxzZrbILRYynyEy7rS1lHQKFpXvo2GePfsMRhNf1F4
# 1nyEg5h7iOXv+vjX0K8RhUisfqw3TTLHj1uhS66YX2LZPxS4oaf33rp9HlfqSBeP
# ejlYeEdU740GKQM7SaVSH3TbBL8R6HwX9QVpGnXPlKdE4fBIn5BBFnV+KwPxRNUN
# K6lYk2y1WSKour4hJN0SMkoaNV8hyyADiX1xuTxKaXN12HgR+8WulU2d6zhzXomJ
# 2PleI9V2yfmfXSPGYanGgxzqI+ShoOGLomMd3mJt92nm7Mheng/TBeSA2z4I78Jp
# wGpTRHiT7yHqBiV2ngUIyCtd0pZ8zg3S7bk4QC4RrcnKJ3FbjyPAGogmoiZ33c1H
# G93Vp6lJ415ERcC7bFQMRbxqrMVANiav1k425zYyFMyLNyE1QulQSgDpW9rtvVcI
# H7WvG9sqYup9j8z9J1XqbBZPJ5XLln8mS8wWmdDLnBHXgYly/p1DhoQo5fkCAwEA
# AaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUn1cs
# A3cOKBWQZqVjXu5Pkh92oFswWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRp
# bWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAPa0eH3aZW+M4hBJH
# 2UOR9hHbm04IHdEoT8/T3HuBSyZeq3jSi5GXeWP7xCKhVireKCnCs+8GZl2uVYFv
# Qe+pPTScVJeCZSsMo1JCoZN2mMew/L4tpqVNbSpWO9QGFwfMEy60HofN6V51sMLM
# XNTLfhVqs+e8haupWiArSozyAmGH/6oMQAh078qRh6wvJNU6gnh5OruCP1QUAvVS
# u4kqVOcJVozZR5RRb/zPd++PGE3qF1P3xWvYViUJLsxtvge/mzA75oBfFZSbdakH
# Je2BVDGIGVNVjOp8sNt70+kEoMF+T6tptMUNlehSR7vM+C13v9+9ZOUKzfRUAYSy
# yEmYtsnpltD/GWX8eM70ls1V6QG/ZOB6b6Yum1HvIiulqJ1Elesj5TMHq8CWT/xr
# W7twipXTJ5/i5pkU5E16RSBAdOp12aw8IQhhA/vEbFkEiF2abhuFixUDobZaA0Vh
# qAsMHOmaT3XThZDNi5U2zHKhUs5uHHdG6BoQau75KiNbh0c+hatSF+02kULkftAR
# jsyEpHKsF7u5zKRbt5oK5YGwFvgc4pEVUNytmB3BpIiowOIIuDgP5M9WArHYSAR1
# 6gc0dP2XdkMEP5eBsX7bf/MGN4K3HP50v/01ZHo/Z5lGLvNwQ7XHBx1yomzLP8lx
# 4Q1zZKDyHcp4VQJLu2kWTsKsOqQxggXpMIIF5QIBATAkMBAxDjAMBgNVBAMMBUow
# TjdFAhB0XMs0val9mEnBo5ekK6KYMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEM
# MQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS7ifHWCcAVCxXh
# J4ghvDQJSm1GXTANBgkqhkiG9w0BAQEFAASCAgC44OnfYz3ZwwUfYvWtgdAxP/YU
# ON/519+qQ8hifN0imKj0RF5JleRqbVuj1UQ07xBVetyL/dOsFZZspwoSd8ETPE6d
# dBmzGeKm2v7T6Aq+8D3lEupip25ou45F6H5XnM7YLXtZupsMzm8Vo0k8fJHWgSwq
# +MmiWClR9hDkmLA6xWzUxZpR7HNQBgd/CXgHq3c4GR+L13YYIe6L893V5lMUKqXV
# IpDm7Yfy1KPwhVN9VtbI3/BC0ibXkM1BgOp/wHuzEvP5mtqnaTXFgApiN/CNyN6S
# sJSM0pHItC4HDRNbRIDpki4/ysGyz564h2YysuXWOL5s7NiptgYs2EJVWdsbQhhy
# W40ar0Rn7sUgCyh/ncBHntOnV6qpBieEizXzOwuk1/RUqzqGMhahi6qPT8VjZ6FR
# gcF1iABFU/ThvkBR99o7QTugdv4blJyZE5+SwKElGZNcgo9CPPmPwb7svWtxFEWh
# aDS44jsRkDXGm5tJKcD0uBB7/IFB2N9iFYGPmjqqM2lvIXcf36T5HbeSGwJWxku6
# i8bXaspkh4jIMvwnlUsXAZ8KeMTjKBeyaADJNmzWjOJTDdXhVzGAnDDmXteeaBu7
# fn+JjMp0cxqdV/j5ujOhYWV7S+9FoFCiKo/5MpNtpA9JngHkg2kImxO31yAzCDVX
# 06ozxx55FlMRd/lJ06GCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0ECEAuuZrxaun+Vh8b56QTjMwQwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNDEwMTEwNzAwMDRaMC8G
# CSqGSIb3DQEJBDEiBCDBa1muz5asgBsHtAYvjmY65EKox3eB7H7qJAjtO9gKnDAN
# BgkqhkiG9w0BAQEFAASCAgANTbryvtQHat4HEB9RUyhow+MmnQ+w4H4Nc1jjPsx7
# /6iSOd5jTtnpUYWmXAhmiyjpJ3wOyGyDbGQJBRJv1JWocYx+orMVAwIvBCJjqEm0
# JOIfO6uYKYniX5JMaScmfVH0d5lm4ZL1Gzp9fDqpgq12MBBOqm/eQWj1ZIz7LtFi
# hKnUsxI2bu3bfBbkat06zOmxmho+lOODkWc+YVSESIIhnFjWvnN86rlmXbTtdybR
# 5TcfCNsH857/XMh4HLnm2Gl+xlyEfiaK1wErWqNJGG9BcoH1f5+/PhPIFCBikR+j
# UEVREyvQvBvT2G4oU5vpNfxLXPE67mtrsEnWkKG0gnNFUGYkPABUx3b2SHpSaViM
# C7FT/CGWZaqxY2k2G0o9YWIk+EAR+BvSCFybHRKtMeeg4g7ccdtgw+amI4GFuJie
# MPuDfRDf0KGDDuVNf80ZA9yf7P+rOKNs5AQpUES14j9cJCMsdkNgQeGcV1c5H9Lz
# ktl7Svy2VYk7mo3lntmsOXnX02pnEwPK13n5bMk8McV9gEtsS7/qgvest3SQgMEk
# momWFk7N1pFigU4qm9tv/rRhzK59YZRHMOZZOwKnMZkPYOag2Tl+V5yBetofKLH+
# FTP2zCO7oBkeEomQAYxpTvwgPOdE//IO02rNT3jyBldBjvd5LCLaAhYSI7XujeCs
# tw==
# SIG # End signature block
