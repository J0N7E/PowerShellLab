
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
        NPS    = @{ Name = 'NPS01';   Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab');  Credential = $Settings.Ac0; }
        RAS    = @{ Name = 'RAS01';   Domain = $true;   OSVersion = '*Experience x64 24H2*';     Switch = @('Lab', 'HvExt');  Credential = $Settings.Ac0; }
        WIN    = @{ Name = 'WIN11';   Domain = $true;   OSVersion = '*11 Enterprise x64 24H2*';  Switch = @('Lab');  Credential = $Settings.Ac2; }
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
# MIIesgYJKoZIhvcNAQcCoIIeozCCHp8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBOYMXnentO57qs
# qeWHIJFESpsaHEXwZEuGWaJw/3+Oa6CCGA4wggUHMIIC76ADAgECAhB0XMs0val9
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
# BgkqhkiG9w0BCQQxIgQgKC2KzkHNaSj8ZRCyYX03Q5WhBR+04VwcLMiMfmhLfeUw
# DQYJKoZIhvcNAQEBBQAEggIACWxuQpi84RLbwAhpTWFe42n5Vp7ipA3Ew+nSG8Dk
# 2as/VnIWpZjSaJjoq97MmPEYS1LTNSpp8Yh9KNACNIp7TWXUYhc4wi7sME+mA5gd
# kM6VFmRXY7ypCc1KGNEg+fZ2K79XaCHQUlRVWTTszS721FshwjNQylyUbTVNviRO
# UYosgRVkIsbH8p5f371SC8YrcDjTEKk/St1jf8vYfu1ebCRkGxH9edORrGKZiDjQ
# SAcXDKVFHOBeRLNjfsoVTS0yoK2F69XFmd3FW81cQbbxDJVwfMXae6fAeYMEjSQ/
# cGinJNXQwNbyEj/lJESMCzOzIQ0GxtGJojDbWW97PSCRlK8dyKqV9EYwOeBYYVr8
# iO7rB/1czlRP7jzNDiiOmIPYhfN/3e9TI8OpC3TwIMwO4JexzGXODGcfcp4cXwtk
# Wp72iIrjL/IXlxt9BDNAP530xEuXmFt5OpG5Re86L6HsJq7ewadE4yi2PCfCsT4n
# ZMdxLwycW0kY9fi5mYkuKhapsKI6wizwUpU9vIFcEfHm8hmY+UNg/oa9lADw/ip6
# l4F9eSs0AbzbpSRXZ/NbQl/F2WgY9Ag3qyL0sy2QW7707fBOwZr12g8/s9b2knoB
# /6IpTSrFkLYK/+CjUV718vk2isddclIe3ZkuFp5gUhCMaVdLmv1vq9xvyBlZZELj
# wVmhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhALrma8Wrp/
# lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwNjI1MDAxNjE4WjAvBgkqhkiG9w0BCQQx
# IgQgl2Jj2nLDjujDuZdY9Xm/u2E/bsypmylOuRQ7lD8Qq+wwDQYJKoZIhvcNAQEB
# BQAEggIAFkDME/vDHPWvPtAuYS7+lUht1/k7SBvsPbHzZ0Z2cNpZDBCMIcasFkif
# dJQNbDS0eJT6jWqk3oxQ49E3DD18I8QIBFqKijE2miVY7GdM4lBu4JVz5lIa7ssf
# o9nxZ62iVCxNIse+tEo1+U90KGCfg1iHut/wcg8rPT+SCAVcmap/+zztOBVMTSsW
# Y25rgriPVutOqKicHrSTUjYVO4FjRuokBIBYoZK+QEGQVA6dBQS+MjEB9mlsuKLf
# G+BF4c0LYUaRWuqn1TINxml7TVpuitcQWyN7Ffpmb3/RGEYo4B3ww6hiwYW52v6E
# DXw3pwl8gY0FZkgLVkHPpHuL2Lu9JfcoOZY9xq1jmCtMGtewri1B8u0rd2raZXs5
# xpOLmk+TORIb1C3r+WRfKT1MxCtwDPF70o1G8d0f6Ouayhy4VzCkb8E4xOWtqlFW
# gcRyID3qIj4k4etNIJyUOAFKtZDi9rBc4gDQO5fZTA3a4sz6XxElg9gdX7yyTIY/
# z1+zdrxzSvZL9y80NAl2/Amg6fIMAdNgVT3ntuL6Cm7pIgoNDVcRrq0Y0oLV9O4n
# uiigDrUIXUp2u3jh6CFow5HyJBstjcg3legEynQovgmsnzqGGPPJ10vfrlZbhBcI
# lkMrabhc+979hig3SGGeM7tQVacfjssNyH1Jy+nHPPuigsPqaTM=
# SIG # End signature block
