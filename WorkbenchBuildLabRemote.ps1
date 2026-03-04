
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
    Dac   = New-Object -ArgumentList "$($DomainNetbiosName + '\admin')",  $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    AcDc  = New-Object -ArgumentList "$($DomainNetbiosName + '\tdcadm')", $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    Ac0   = New-Object -ArgumentList "$($DomainNetbiosName + '\t0adm')",  $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    Ac1   = New-Object -ArgumentList "$($DomainNetbiosName + '\t1adm')",  $Settings.Pswd -TypeName System.Management.Automation.PSCredential
    Ac2   = New-Object -ArgumentList "$($DomainNetbiosName + '\t2adm')",  $Settings.Pswd -TypeName System.Management.Automation.PSCredential
}

$Settings +=
@{
    Switches =
    @(
        @{ Name = 'Lab';     Type = 'Private';   NetworkId = '192.168.0';  GW = '192.169.0.1';  DNS = '192.168.0.10' }
    )
    VMs = [ordered]@{

        RootCA = @{ Name = 'CA01';    Domain = $false;  OSVersion = '*Experience x64 24H2*';     Switch = @();       Credential = $Settings.Lac; }
        DC     = @{ Name = 'DC01';    Domain = $false;  OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Dac; }
        SubCA  = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
        AS     = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
        #ADFS   = @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
        #NPS    = @{ Name = 'NPS01';   Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
        #RAS    = @{ Name = 'RAS01';   Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab', 'HvExt');  Credential = $Settings.Ac0; }
        WIN    = @{ Name = 'WIN11';   Domain = $true;   OSVersion = '*11 Enterprise x64 24H2*';  Switch = @('Lab');  Credential = $Settings.Ac2; }
        #WIN12  = @{ Name = 'WIN12';   Domain = $false;  OSVersion = '*11 Enterprise x64 24H2*';  Switch = @('Lab');  Credential = $Settings.Lac; }
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
        [switch]$Rename,
        [switch]$JoinDomain
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
            if ($Network.IsPresent -and $VM.Value.Switch)
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
            elseif ($JoinDomain.IsPresent -and $VM.Value.Domain)
            {
                Start-Process $PowerShell @WaitSplat -ArgumentList `
                @(
                    "$NoExitStr-File $LabPath\VMRename.ps1 $Lac -Verbose",
                    "-VMName $($VM.Value.Name) -JoinDomain -Restart"
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

#############
# Create VMs
#############

Setup-VMs -Create

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
    "-AlwaysPrompt",
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
# Setup Network
################

Setup-VMs -Network -NoExit

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

# FIX join/restart array

# Domain join
Setup-DC -DomainJoin RAS01, NPS01

# Rename & join domain
Setup-VMs -JoinDomain -NoExit

# Rerun DC setup step 1 to configure AD
Setup-DC

# Restart
Restart-VM -VMName RAS01, NPS01 -Force 

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
    "-AlwaysPrompt",
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
    "-CRLOverlapUnits 180",
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
    "-AdapterName HvExt",
    "-IPAddress `"172.17.2.200`"",
    "-DefaultGateway `"172.17.2.17`"",
    "-DNSServerAddresses $(Serialize @(`"172.17.2.30`"))"
)

# SIG # Begin signature block
# MIIeygYJKoZIhvcNAQcCoIIeuzCCHrcCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUycP80pFI86goQYsVNrfccwtH
# 3gqgghhFMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMCAQIC
# EA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAw
# MDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmW
# gyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzb
# NfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPs
# YfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBK
# S7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmU
# PAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7z
# L2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHK
# S+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4
# /6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogx
# G9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbV
# RSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNT
# AgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK
# 6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUH
# AQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYI
# KwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc
# /gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAz
# aoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q
# 8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntu
# jB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2
# rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z
# 0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVG
# yOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxO
# GLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB
# /8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3
# IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8
# EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43x
# BYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAw
# MDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRp
# bWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7
# C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281m
# HrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUue
# HTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw
# 44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBS
# ai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvh
# DU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5
# J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIU
# bWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJ
# RE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CID
# BbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOC
# AZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPP
# YYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQE
# AwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcw
# AoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYw
# VKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEc
# JwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz
# 9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7
# YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8l
# D8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42
# fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz
# +BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJ
# nzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7
# weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH
# 3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ue
# Iu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6I
# Ls84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIF7zCCBesCAQEwJDAQMQ4wDAYD
# VQQDDAVKME43RQIQdFzLNL2pfZhJwaOXpCuimDAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUd7h6
# JPM++vczd5LjJPPFm2dY23owDQYJKoZIhvcNAQEBBQAEggIAZIh4//lw7sLfhaEx
# WRTI6V8W2zgb600ae9K9rsFP0SVwyYlaPdqaXmTZruFaX9jtEvqe00y63mflyj1k
# hYJfMDnB3D8i0my+kf8ROPyffqkeCqVJ1lBQZWo8ebx7FI6ftvBYL2Wr5zDjGo2B
# WqaMVJqoU2xHJ9v2ntZfU2GDFGM08fhES+1XaigHGmG2PxZeBLtwuPWv4VqfcfOo
# Ac44zeYxt0VhHn5++10VBaTexKIIU5kx/Hywt8JvYul5/oc5X7rtcLHm66kW05y5
# SLUgjT131rzEMOK94v/RJ2cyI7EKqd7Ro8LEOjkm21eg4MsZaUNEZ+XDQeTYHwBG
# XkcF9d6mgj9EEaZiT11UCLPon1ZqgQvdlJ15pg7xh4v2pc5OFbCrP9nSzIKdNwtR
# nO0sAXuPSbq5U6Ten77RhVUlD+0GZgy0/R4A4YI/2RcPDSa/t42Neh3LRQYTL+ct
# rAbzzOLYR8r/GVumT/PgnSlw82cK7S7i9mET6+lGgjNl58gDSJLFrSF2hGIMa3g8
# 01N86IluSRZ87ml5NWCIPx41JidaspCqfJqpqmhRs3eKXGt4QYUo7ZDkXtUoBoHt
# QP29w9cLKD8o+IWSs4/JeVfJw5utifOGqOwOPNzbYFdumtiAi1SYN0AQbSAtA1vC
# CoWjhgmrZQ3p9/fPX+6QSgyQueqhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8C
# AQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYg
# U0hBMjU2IDIwMjUgQ0ExAhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUA
# oGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYw
# MzA0MTcwMDA0WjAvBgkqhkiG9w0BCQQxIgQgIJc5n079IRqXmyanGH792C0OeiJ+
# 4tfIpEGp/SWZus4wDQYJKoZIhvcNAQEBBQAEggIAnBxghtvuTbOwWN7Kvp8sCXZQ
# 1fbKL8p//JiYPGt+km6XcNnCcA8ZrqKfF9lOcDE34AXvEbsYTXEKlNDOCCIjAiie
# TgV7EklcEmo8pcRXyBsLeNHbE7YOTnXwoRMr80cJQb+xjWTGMGk/c/tlLdBnm0uj
# elEGKSmA5zMMBKHL5yfvQivpPZ+xODwCl9agtbhMWIMvOR1fIROktGoeYJx3yoi4
# INbXEPs6BEess8jeml1/qcNAGijK0cFruPtfzm0VWoUBG66a9m2jLALpiko2Qk0d
# nj1bwBSRt39HU4JZ4ySPO5UuSGVA6qrOgIPH7lSk6aq/iINpDBy6e/vkySes09FD
# zHpU5YYFuNK2hT8S6DdibXCkU5rmVog3RHkMAaqrpydbKhatsAgFo4Y87t7Hx97v
# obb/te/8mwHSe7s3TObZ+ZbR95RDGfcrKYH21vACA2J/sPN224T2NQSBcatQJAZp
# S9OOjPgNglx9llXPJHuiiyE6DfQaWZR29JWJZVNOHU11PTEvUhc1FFTULLsN6kkg
# PWLfknha0qFosBOQFomgWs85In3GSOyzbigabVZH0z5Lh47KTzV/pqHmevzvSp3s
# E1EHg2Ik81h9JAwTvjw++BoLsDNreW8RlrKmyB+/8gfI6klvwwJVaPgWAWy2C0/5
# o/diG6T9Rhbc9kRLRTc=
# SIG # End signature block
