
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
}

$DomainNetbiosName = $DomainName.Substring(0, $DomainName.IndexOf('.'))

$Settings =
@{
    DomainName = $DomainName
    DomainNetbiosName = $DomainNetbiosName
    DomainPrefix = $DomainNetBiosName.Substring(0, 1).ToUpper() + $DomainNetBiosName.Substring(1)
}

# Password
$Settings += @{ Pswd = (ConvertTo-SecureString -String 'P455w0rd' -AsPlainText -Force) }

# Credentials
$Settings +=
@{
    Lac    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".\administrator", $Settings.Pswd
    Dac    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\Admin')", $Settings.Pswd
    Ac0    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\Tier0Admin')", $Settings.Pswd
    Ac1    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\Tier1Admin')", $Settings.Pswd
    Ac2    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\Tier2Admin')", $Settings.Pswd
    Jc     = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\JoinDomain')", $Settings.Pswd
}

$Settings +=
@{
    DomainNetworkId   = '192.168.0'
    DmzNetworkId      = '10.1.1'
    Switches          =
    @(
        @{ Name = 'LabDmz';  Type = 'Internal' }
        @{ Name = 'Lab';     Type = 'Private'  }
    )
    VMs               =
    [ordered]@{
        RootCA = @{ Name = 'CA01';    Domain = $false;  OSVersion = '*Desktop Experience x64 21H2*';  Switch = @();                 Credential = $Settings.Lac; }
        DC     = @{ Name = 'DC01';    Domain = $false;  OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab');            Credential = $Settings.Dac; }
        SubCA  = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*Standard x64 21H2*';            Switch = @('Lab');            Credential = $Settings.Ac0; }
        AS     = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab');            Credential = $Settings.Ac0; }
        ADFS   = @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';  Switch = @('Lab');            Credential = $Settings.Ac0; }
        WAP    = @{ Name = 'WAP01';   Domain = $true;   OSVersion = '*Standard x64 21H2*';            Switch = @('Lab', 'LabDmz');  Credential = $Settings.Ac1; }
        WIN    = @{ Name = 'WIN11';   Domain = $true;   OSVersion = '*Windows 11 Enterprise x64*';    Switch = @('Lab');            Credential = $Settings.Ac2; }
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

function Create-VMs
{
    param
    (
        [switch]$Wait,
        [switch]$NoExit
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

            Start-Process @WaitSplat -FilePath $PowerShell -ArgumentList `
            @(
                "$NoExitStr-File $LabPath\LabNewVM.ps1 -Verbose$VMAdapters",
                "-LabFolder `"$HvDrive`"",
                "-VMName $($VM.Value.Name)",
                "-Vhdx `"$OSVhdx`"",
                "-Start"
            )
        }
    }
}

function Setup-DC
{
    [cmdletbinding(DefaultParameterSetName='Standard')]
    param
    (
        [Switch]$CopyGpo,
        [Switch]$CopyBaseline,
        [Switch]$CopyTemplates,

        [ValidateSet($true, $false, $null)]
        [Object]$RestrictDomain,

        [ValidateSet($true, $false, $null)]
        [Object]$EnableIPSec,

        [ValidateSet($true, $false, $null)]
        [Object]$SetupAdfs,

        [Switch]$BackupGpo,
        [Switch]$BackupTemplates,
        [Switch]$BackupReplace,

        [Switch]$RemoveAuthenticatedUsersFromUserGpos
    )

    # Initialize
    $NoExitStr = '-NoExit '
    $WaitSplat = @{ Wait = $false }
    $ParamArray = @()

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

            { $_ -in @('RestrictDomain', 'EnableIPSec', 'SetupAdfs') -and $Param.Value -notlike $null }
            {
                $ParamArray += "-$($Param.Key) $($Param.Value)"
            }

            { $_ -match 'BackupReplace' }
            {
                # Open session
                $Session = New-PSSession -VMName $Settings.VMs.DC.Name -Credential $Settings.Lac -ErrorAction SilentlyContinue

                $NoExitStr = ''
                $WaitSplat = @{ Wait = $true }
            }

            default
            {
                $ParamArray += "-$($Param.Key)"
            }
        }
    }

    # Default argumentlist
    $Argumentlist =
    @(
        "$NoExitStr-File $LabPath\VMSetupDC.ps1 $DC $Dac -Verbose",
        "-DomainNetworkId $($Settings.DomainNetworkId)",
        "-DomainName $($Settings.DomainName)",
        "-DomainNetbiosName $($Settings.DomainNetBiosName)",
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
            Copy-Item -FromSession $Session -Path "C:\Users\Admin\AppData\Local\Temp\GpoBackup" -Recurse -Destination "$LabPath\Gpo"
        }

        # Check if to backup templates
        if ($BackupTemplates.IsPresent)
        {
            Retry-Remove -Path "$LabPath\Templates"

            # Copy template backups
            Copy-Item -FromSession $Session -Path "C:\Users\Admin\AppData\Local\Temp\TemplatesBackup" -Recurse -Destination "$LabPath\Templates"
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
    if (-not (Get-VMSwitch -Name $Switch.Name -ErrorAction SilentlyContinue))
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

##########
# Root CA
##########

# Rename Root CA
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 $RootCA $Lac -Verbose -Restart"
)

#########
# DC
# Step 1
#########

# Rename DC
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 $DC $Lac -Verbose -Restart"
)

# Setup network DC
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 $DC $Lac -Verbose",
    "-AdapterName Lab",
    "-IPAddress `"$($Settings.DomainNetworkId).10`"",
    "-DefaultGateway `"$($Settings.DomainNetworkId).1`"",
    "-DNSServerAddresses $(Serialize @(`"$($Settings.DmzNetworkId).1`"))"
)

# Setup DC Step 1
Setup-DC

##########
# Root CA
##########

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCA.ps1 $RootCA $Lac -Verbose",
    "-Force",
    #"-AlwaysPrompt",
    "-StandaloneRootCA",
    "-CACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)`"",
    "-CADistinguishedNameSuffix `"O=$($Settings.DomainPrefix),C=SE`"",
    "-DomainName $($Settings.DomainName)"
)

<#
    # Remove root CA
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMRemoveCA.ps1 $RootCA $Lac -Verbose",
        "-CACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)`""
    )
#>

#########
# DC
# Step 2
#########

# Wait for DC to complete step 1 setup before continuing...

# Setup DC network Step 2
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 $DC $Lac -Verbose",
    "-AdapterName Lab",
    "-IPAddress `"$($Settings.DomainNetworkId).10`"",
    "-DefaultGateway `"$($Settings.DomainNetworkId).1`"",
    "-DNSServerAddresses $(Serialize @(`"$($Settings.DomainNetworkId).10`", '127.0.0.1'))"
)

# Setup DC Step 2
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupDC.ps1 $DC $Lac -Verbose",
    "-DomainNetworkId $($Settings.DomainNetworkId)",
    "-DomainName $($Settings.DomainName)",
    "-DomainNetbiosName $($Settings.DomainNetBiosName)",
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
    "-CACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)`""
)

<#
    # Remove root certificate from domain
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMRemoveCAFromAD.ps1 $DC $Dac -Verbose",
        "-CAServerName $($Settings.VMs.RootCA.Name)",
        "-CACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)`""
    )
#>

############
# Sub CA/AS
############

# Domain join and rename Sub CA
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 $SubCA $Lac -Verbose",
    "-JoinDomain $($Settings.DomainName)",
    "-DomainCredential $(Serialize $Settings.Jc)"
)

# Domain join and rename AS
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 $AS $Lac -Verbose",
    "-JoinDomain $($Settings.DomainName)",
    "-DomainCredential $(Serialize $Settings.Jc)"
)

# Rerun DC setup step 1 to configure Sub CA in AD
Setup-DC

# Restart Sub CA
Invoke-Command -VMName $Settings.VMs.SubCA.Name -Credential $Settings.Lac -ScriptBlock { Restart-Computer -Force }

# Restart AS
Invoke-Command -VMName $Settings.VMs.AS.Name -Credential $Settings.Lac -ScriptBlock { Restart-Computer -Force }

#########
# AS
# Step 1
#########

# Root cdp
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureWebServer.ps1 $AS $Ac0 -Verbose",
    "-Force",
    "-CAConfig `"$($Settings.VMs.RootCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)`"",
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
    "-CACommonName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)`"",
    "-CADistinguishedNameSuffix `"O=$($Settings.DomainPrefix),C=SE`"",
    "-PublishAdditionalPaths $(Serialize @(`"\\$($Settings.VMs.AS.Name)\wwwroot$`"))",
    "-PublishTemplates",
    #"-CryptoProviderName `"RSA#SafeNet Key Storage Provider`"",
    #"-KeyContainerName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)`"",
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
        "-ParentCACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.RootCA.Name)`"",
        "-CACommonName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)`""
    )

    # Remove sub CA certificate from domain
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMRemoveCAFromAD.ps1 $DC $Dac -Verbose",
        "-CAServerName $($Settings.VMs.SubCA.Name)",
        "-CACommonName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)`""
    )

    # Configure sub CA in AD
    Start-Process $PowerShell -ArgumentList `
    @(
        "-NoExit -File $LabPath\VMSetupCAConfigureAD.ps1 $DC $Dac -Verbose",
        "-Force",
        "-RemoveOld",
        "-CAType EnterpriseSubordinateCA",
        "-CAServerName $($Settings.VMs.SubCA.Name)",
        "-CACommonName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)`""
    )
#>

##########
# Root CA
##########

# Issue Sub CA
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAIssueCertificate.ps1 -Verbose $RootCA $Lac",
    "-CertificateSigningRequest `"$LabPath\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)-Request.csr`""
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
    "-CAConfig `"$($Settings.VMs.SubCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)`"",
    "-ConfigureOCSP",
    "-OCSPTemplate `"$($Settings.DomainPrefix)OCSPResponseSigning`""
)

# NDES
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureWebServer.ps1 $AS $Ac0 -Verbose",
    "-Force",
    "-CAConfig `"$($Settings.VMs.SubCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SubCA.Name)`"",
    "-ConfigureNDES"
 )

######
# WIN
######

# Domain join and rename workstation
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 $Win $Lac -Verbose",
    "-JoinDomain $($Settings.DomainName)",
    "-DomainCredential $(Serialize $Settings.Jc)",
    "-Restart"
)

######
# WAP
######

# Set up network Lab adapter
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 $WAP $Lac -Verbose",
    "-AdapterName Lab",
    "-IPAddress `"$($Settings.DomainNetworkId).250`"",
    "-DNSServerAddresses $(Serialize @(`"$($Settings.DomainNetworkId).10`"))"
)

# Set up network LabDmz adapter
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 $WAP $Lac -Verbose",
    "-AdapterName LabDmz",
    "-IPAddress `"$($Settings.DmzNetworkId).250`"",
    "-DefaultGateway `"$($Settings.DmzNetworkId).1`"",
    "-DNSServerAddresses $(Serialize @(`"$($Settings.DmzNetworkId).1`"))"
)

# Set WAP
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupWAP.ps1 $WAP $Ac1 -Verbose",
    #"-EnrollAcmeCertificates",
    "-ADFSPfxFile `"$($Settings.DomainPrefix)AdfsCertificate.pfx`"",
    "-ADFSTrustCredential $(Serialize $Settings.Ac0)"
)

# SIG # Begin signature block
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWzNag9KajpONOeq/DyGFu68Q
# cZOgghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQs8UBS
# lKDx7tYUP4VfVUlSMwxRhjANBgkqhkiG9w0BAQEFAASCAgCXNQ/renZpxks2ZRNZ
# WtSzKCT+TNrwXhSyoYAp7YUHHHykWI6CetCJ/ddC2W2jemnI1nSGfxQqqPkxgX4G
# zBN+O/Ii0B51J09HjSzpp7I0Cla+LhTfE+R8As8o4sehWCODYE9KWWOIx/29oLpG
# RE6+Jn0MKlUAyqGzy+vAv0/ioQuiBrxCbzXaJVWLQplR67JrMXUUPRdkvVKFTNmm
# A5hGJONhMHkqx+KFBX5n1p6VezpXHkXYI0KZSEPwwXyh7ZJX/WG9bYw5Ne8fYfyC
# BNf7F04ji0rFLsNfNs1F5Bvci2Qqh4G4mDMOjKFZ1GA5n0VQRH0pa6hlheC4TDpn
# B7u1ixcLhWQMgnFLYKM5ckko1ZyHHq58BVocChvWaAGoRSpKcdIowe3zjRAR3Ol3
# QbhewvN/PaetkxntiKmGDSYmD6MtmaKSwMQCVvQXhZokWieunVG7x7o0p27NUZDs
# Wc+2i1NF4VNFsUKsW0MP8ZbNWzfDt9pTbB+y8rc98VUya46kyYTq3gCJ1G13ts15
# CvJbi99LTM/hDI23anxlZHuYemBMaTKwyGSK9TqMflwqCyPIoraim4oHAGHiJxSV
# YqZzBZo+fLnIDQSvJi5GTnEtAQejC1+4vrV6FInobkAIzbH92scxXEX5wv+VU7xK
# P0161+X9vLwHz06nKYlh5QjMYqGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzEwMTIxMjAw
# MDJaMC8GCSqGSIb3DQEJBDEiBCDX+Duf5RkVPr5JL8WA6C0uO5Gzjxkih9AXmfAO
# AU90MTANBgkqhkiG9w0BAQEFAASCAgAIM2vNhGeG1GXLxkuG70qVXAoZrkoWVqDj
# da9gFs19AgaEEM8NTDRVMlhr/QGAYHebrPg1nWUQoaEJYsAYB12NVBzBDFmzMjeR
# Uk43mKFJ49M/qRS5TO8ZK3OjgC1Mx2id4mu019l4RJ62en/oVK/BHZHwN2QFo3Fj
# o0vMM9bL8vIZyKjk4+Tlmc86WJX/J1zkNv6YRmDsshejxvODHrmOiDomMHkFtmOi
# SJWYYwQJTbShvEXO7j1BWIoUBez77QQU+puQtcMWOb4OAHLU6OE52yMF940/cSNr
# xxSJ8IVcixAWv3epOyJAXiR1jmvDHMGzP3BMuK0DM+VBb8P6nBd5kHNcB5nLiJLB
# nF3AdmH8GxOapnUu7cpF265GQQ0A8JRpekWd3dVT63189JTyZnz6erzM2Nku1v/7
# mkVBeJCZg+2qR0/P/VxgK0WxI4dAfGKBAm/Y1ttxYmJh7YG3nUG7IiuU6WNiojHX
# c7tLblu/RY7sSRG8ZAitWxXx0/zqSZAnka0uq6Gqv8TpJPxQhUZEDTsEXc8MmMoZ
# vb/dQnhG9l4eTgY+Ntjmg0L2TQtbCRI7QMtzFL7EIeyhA3p8mF7om0EGQnpTLyVS
# 85Hz8mRMLrpiNRQzuWycPqLup0oKYV+7Yk9rdF6cnm7FItEPVmZWJzs8My8+B+u9
# 0cg+MXJI5Q==
# SIG # End signature block
