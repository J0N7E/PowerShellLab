
$HvDrive = "$env:SystemDrive"
$OsdPath = "$env:SystemDrive\OSDBuilder"
$LabPath = "$env:Documents\WindowsPowerShell\PowerShellLab"

if (-not (Test-Path -Path $LabPath))
{
    $LabPath = "$env:USERPROFILE\Documents\WindowsPowerShell\PowerShellLab"
}

Set-Location -Path $LabPath

if ((Invoke-Command -ScriptBlock{ pwsh -version } 2>&1))
{
    $PowerShell = 'pwsh'
}
else
{
    $PowerShell = 'powershell'
}

###########
# Settings
###########

$Settings =
@{
    DomainNetworkId   = '192.168.0'
    DmzNetworkId      = '10.1.1'
    Admin             = 'tier0admin'
    Join              = 'joindomain'
    Pswd              = (ConvertTo-SecureString -String 'P455w0rd' -AsPlainText -Force)
    VMs               =
    [ordered]@{
        ADFS   = @{ Name = 'ADFS01';  Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';   Switch = @('Lab');           }
        AS     = @{ Name = 'AS01';    Domain = $true;   OSVersion = '*Desktop Experience x64 21H2*';   Switch = @('Lab');           }
        ROOTCA = @{ Name = 'CA01';    Domain = $false;  OSVersion = '*Desktop Experience x64 21H2*';   Switch = @();                }
        SUBCA  = @{ Name = 'CA02';    Domain = $true;   OSVersion = '*x64 21H2*';                      Switch = @('Lab');           }
        DC     = @{ Name = 'DC01';    Domain = $false;  OSVersion = '*Desktop Experience x64 21H2*';   Switch = @('Lab');           }
        WAP    = @{ Name = 'WAP02';   Domain = $true;   OSVersion = '*x64 21H2*';                      Switch = @('LabDmz', 'Lab'); }
        WIN11  = @{ Name = 'WIN11';   Domain = $true;   OSVersion = 'Windows 11*';                     Switch = @('Lab');           }
    }
}

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

$Settings +=
@{
    DomainName = $DomainName
    DomainNetbiosName = $DomainNetbiosName
    DomainPrefix = $DomainNetBiosName.Substring(0, 1).ToUpper() + $DomainNetBiosName.Substring(1)
}

# Get credentials
$Settings +=
@{
    Lac    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".\administrator", $Settings.Pswd
    Dac    = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\' + $Settings.Admin)", $Settings.Pswd
    Jc     = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($Settings.DomainNetBiosName + '\' + $Settings.Join)", $Settings.Pswd
}

############
# Functions
############

function Create-VMs
{
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

            Start-Process PowerShell -ArgumentList `
            @(
                #"-NoExit ",
                "-File $LabPath\LabNewVM.ps1 -Verbose$VMAdapters",
                "-LabFolder `"$HvDrive\HvLab`"",
                "-VMName $($VM.Value.Name)",
                "-Vhdx `"$OSVhdx`"",
                "-Start"
            )
        }
    }
}

function Setup-DC
{
    param
    (
        [ValidateSet($true, $false)]
        [String]$RestrictUserRightsAssignment,

        [ValidateSet($true, $false)]
        [String]$UseAuthenticationPolicySilos,

        [Switch]$BackupGpo,
        [Switch]$BackupTemplates,
        [Switch]$RemoveAuthenticatedUsersFromUserGpos
    )

    # Check parameters
    if ($BackupGpo.IsPresent -or $BackupTemplates.IsPresent)
    {
        # Open session
        $Session = New-PSSession -VMName $Settings.VMs.DC.Name -Credential $Settings.Lac

        $NoExit = ''
        $WaitSplat = @{ Wait = $true }
    }
    else
    {
        $NoExit = '-NoExit '
        $WaitSplat = @{ Wait = $false }
    }

    # Argumentlist for setup dc
    $Argumentlist =
    @(
        "$NoExit-File $LabPath\VMSetupDC.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Lac)",
        "-DomainNetworkId $($Settings.DomainNetworkId)",
        "-DomainName $($Settings.DomainName)",
        "-DomainNetbiosName $($Settings.DomainNetBiosName)",
        "-DomainLocalPassword $(Serialize $Settings.Pswd)"
    )

    # Initialize
    $ParamArray = @()

    # Itterate parameters
    foreach ($Param in $PSBoundParameters.GetEnumerator())
    {
        switch ($Param.Key)
        {
            { $_ -in 'RestrictUserRightsAssignment', 'UseAuthenticationPolicySilos'}

            {
                $ParamArray += "-$($Param.Key) $($Param.Value)"        
            }
            default
            {
                $ParamArray += "-$($Param.Key)" 
            }
        }
    }
    
    # Check if any parameters
    if ($ParamArray)
    {
        # Convert param array to string
        $Argumentlist += $ParamArray -join ' '
    }

    # Invoke setup dc with parameters
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
    if ($BackupGpo.IsPresent -or $BackupTemplates.IsPresent)
    {
        # Remove session
        $Session | Remove-PSSession
    }
}

return

##########
# Root CA
##########

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 -Verbose -VMName $($Settings.VMs.ROOTCA.Name) -Credential $(Serialize $Settings.Lac) -Restart"
)

#########
# DC
# Step 1
#########

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Lac) -Restart"
)

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Lac)",
    "-AdapterName Lab",
    "-IPAddress `"$($Settings.DomainNetworkId).10`"",
    "-DefaultGateway `"$($Settings.DomainNetworkId).1`"",
    "-DNSServerAddresses $(Serialize @(`"$($Settings.DmzNetworkId).1`"))"
)

# DC Step 1
Setup-DC

##########
# Root CA
##########

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCA.ps1 -Verbose -VMName $($Settings.VMs.ROOTCA.Name) -Credential $(Serialize $Settings.Lac)",
    "-Force",
    #"-AlwaysPrompt",
    "-StandaloneRootCA",
    "-CACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)`"",
    "-CADistinguishedNameSuffix `"O=$($Settings.DomainPrefix),C=SE`"",
    "-DomainName $($Settings.DomainName)"
)

<# Remove root CA
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRemoveCA.ps1 -Verbose -VMName $($Settings.VMs.ROOTCA.Name) -Credential $(Serialize $Settings.Lac)",
    "-CACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)`""
)
#>

#########
# DC
# Step 2
#########

# Wait for DC to setup domain

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupNetwork.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Lac)",
    "-AdapterName Lab",
    "-IPAddress `"$($Settings.DomainNetworkId).10`"",
    "-DefaultGateway `"$($Settings.DomainNetworkId).1`"",
    "-DNSServerAddresses $(Serialize @(`"$($Settings.DomainNetworkId).10`", '127.0.0.1'))"
)

# Step 2
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupDC.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Lac)",
    "-DomainNetworkId $($Settings.DomainNetworkId)",
    "-DomainName $($Settings.DomainName)",
    "-DomainNetbiosName $($Settings.DomainNetBiosName)",
    "-DomainLocalPassword $(Serialize $Settings.Pswd)",
    "-GPOPath `"$LabPath\Gpo`"",
    "-BaselinePath `"$LabPath\Baseline`"",
    "-TemplatePath `"$LabPath\Templates`""
)

#########
# Sub CA
#########

# Publish root certificate to domain
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureAD.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Dac)",
    "-CAType StandaloneRootCA",
    "-CAServerName $($Settings.VMs.ROOTCA.Name)",
    "-CACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)`""
)

<# Remove root certificate from domain
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRemoveCAFromAD.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Dac)",
    "-CAServerName $($Settings.VMs.ROOTCA.Name)",
    "-CACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)`""
)
#>

# Domain join and rename Sub CA
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 -Verbose -VMName $($Settings.VMs.SUBCA.Name) -Credential $(Serialize $Settings.Lac)",
    "-JoinDomain $($Settings.DomainName)",
    "-DomainCredential $(Serialize $Settings.Jc)"
)

# Rerun DC setup step 1 to configure Sub CA in AD
Setup-DC

# Restart Sub CA
Invoke-Command -VMName $Settings.VMs.SUBCA.Name -Credential $Settings.Lac -ScriptBlock { Restart-Computer -Force }

#########
# AS
# Step 1
#########

# Domain join and rename AS
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRename.ps1 -Verbose -VMName $($Settings.VMs.AS.Name) -Credential $(Serialize $Settings.Lac)",
    "-JoinDomain $($Settings.DomainName)",
    "-DomainCredential $(Serialize $Settings.Jc)"
)

# Rerun DC setup step 1 to configure AS in AD
Setup-DC

# Restart AS
Invoke-Command -VMName $Settings.VMs.AS.Name -Credential $Settings.Lac -ScriptBlock { Restart-Computer -Force }

# AS Step 1
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureWebServer.ps1 -Verbose -VMName $($Settings.VMs.AS.Name) -Credential $(Serialize $Settings.Dac)",
    "-Force",
    "-CAConfig `"$($Settings.VMs.ROOTCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)`"",
    "-ConfigureIIS",
    "-ShareAccess `"Delegate CRL Publishers`""
)

#########
# Sub CA
# Step 1
#########

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCA.ps1 -Verbose -VMName $($Settings.VMs.SUBCA.Name) -Credential $(Serialize $Settings.Dac)",
    "-Force",
    "-AlwaysPrompt",
    "-EnterpriseSubordinateCA",
    "-CACommonName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)`"",
    "-CADistinguishedNameSuffix `"O=$($Settings.DomainPrefix),C=SE`"",
    "-CRLPublishAdditionalPaths $(Serialize @(`"\\$($Settings.VMs.AS.Name)\wwwroot$`"))",
    "-PublishTemplates",
    #"-CryptoProviderName `"RSA#SafeNet Key Storage Provider`"",
    #"-KeyContainerName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)`"",
    #"-IssuancePolicies $(Serialize (@( @{Name='Policy1'; OID='1.2.3'}, @{Name='Policy2'; OID='4.5.6'})))",
    "-CRLPeriodUnits 180",
    "-CRLPeriod Days",
    "-CRLOverlapUnits 14",
    "-CRLOverlapPeriod Days"
)

<# Remove sub CA
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRemoveCA.ps1 -Verbose -VMName $($Settings.VMs.SUBCA.Name) -Credential $(Serialize $Settings.Dac)",
    "-ParentCACommonName `"$($Settings.DomainPrefix) Root $($Settings.VMs.ROOTCA.Name)`"",
    "-CACommonName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)`""
)
#>

<# Remove sub CA certificate from domain
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMRemoveCAFromAD.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Dac)",
    "-CAServerName $($Settings.VMs.SUBCA.Name)",
    "-CACommonName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)`""
)
#>

<# Configure sub CA in AD
Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureAD.ps1 -Verbose -VMName $($Settings.VMs.DC.Name) -Credential $(Serialize $Settings.Dac)",
    #"-RemoveOld",
    "-CAType EnterpriseSubordinateCA",
    "-CAServerName $($Settings.VMs.SUBCA.Name)",
    "-CACommonName `"$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)`""
)
#>

##########
# Root CA
##########

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAIssueCertificate.ps1 -Verbose -VMName $($Settings.VMs.ROOTCA.Name) -Credential $(Serialize $Settings.Lac)",
    "-CertificateSigningRequest `"$LabPath\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)-Request.csr`""
)

#########
# Sub CA
# Step 2
#########

# Rerun sub CA setup step 1 to install certificate

#########
# AS
# Step 2
#########

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureWebServer.ps1 -Verbose -VMName $($Settings.VMs.AS.Name) -Credential $(Serialize $Settings.Dac)",
    "-Force",
    "-CAConfig `"$($Settings.VMs.SUBCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)`"",
    "-ConfigureOCSP",
    "-OCSPTemplate `"$($Settings.DomainPrefix)OCSPResponseSigning`""
)

Start-Process $PowerShell -ArgumentList `
@(
    "-NoExit -File $LabPath\VMSetupCAConfigureWebServer.ps1 -Verbose -VMName $($Settings.VMs.AS.Name) -Credential $(Serialize $Settings.Dac)",
    "-Force",
    "-CAConfig `"$($Settings.VMs.SUBCA.Name).$($Settings.DomainName)\$($Settings.DomainPrefix) Enterprise $($Settings.VMs.SUBCA.Name)`"",
    "-ConfigureNDES"
 )

# SIG # Begin signature block
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUNfBdF3bSWdxYVzwzlZfq9vnk
# wNKgghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUI45V1DKT
# uAeefJSz/TW6AO1gQXcwDQYJKoZIhvcNAQEBBQAEggIAPUMmbKUeF3MpROQjv/3E
# x3EE6sKk8so0sfiq9Rk7CCZWYJ7jR4OXeKnlmPl4GtoSUzAVGHzH9SUHt6a/t7gF
# CU3IeZg83gT6S/fYi0cNXbS5YoYHjS9JKh3rE6lf7sBNwOrLJ2yknPUbQ9TD+DkE
# zXoVJswT84mw5u9WaK6gPy3o5O7M8wuVLfu+MIux76hbXgSXAMUp0bD+bcqJS6mx
# pP1rvb/Z869ZzWG0kUTyOBPOHg5x7ktaLaVTKwQwp318gUkcTjlYkFhM5xuRNhWx
# 1K36yWUcBvWv1jd4Q7pXsePaB2eszPwF9zuI8UTWxp2FVn1JSLva1sarU1JQ1a5m
# OyCr1RUqxgzAcIx8T3oLSK1OQXlU1Jf1Nwc6IP1pSISBO49FRrTeYr9gVz5mEdCQ
# Yac8d2AaZlvWbP2hvggYNNh56ZsSm9/r1D+3t3SQUguCMU6/E3vCV6v/uaZO4llB
# Nw5gqg3JKz+a9dkeNwG1LCQ92WZYT+YBuBdcl0lY76y/HZKaXLV3ZVxJ0Xzoiplw
# NjUxRY6MNOY+iIYbw9j62JIhXkvxTZPARkvXEpEgz/p7puAOj9yFdNy3AqEhjXeo
# A73xZfwDpUXu4vGZql1lhDtgBnNQsPMmsFRv717+K2Zbf7VBgBtvoxFWIG02084Y
# GY9WtCnH/O/7L8kui/KS7gahggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwNDE4MTEwMDAy
# WjAvBgkqhkiG9w0BCQQxIgQgdp+Qn3wBSNJLL4Gj0+Wk7CrMp9GqVooHkbmdv64D
# m+0wDQYJKoZIhvcNAQEBBQAEggIAW09fhgZWke4zuLv3CzeDaqntcBGfS0CkY1TR
# DufKX6X3Ahu2mj14Ip9tZPsFGhya49NU52dNFKDUjMuQAciJ2L3OhbuyPJT3un0H
# hhfD2kei2Zmliq5QGFKR5fdtCUzLrP69VOv3T4ZP3vMloz5SN73fpYsaXxMYK7Su
# x2u1brucYHI5m/BcKVbmmhC39XO4bQw6MMzlwk1n5EgvGjbUc3rXbdsxzqRvgZjQ
# Mtw0HoSdzvKFA5Brj92aSCuIWDuc3ElNE3ce7eyqF/CjcyuujZO56O+QStdMjXAV
# 592v+EpwJzEWfadGJgmwd9m4QMo5MaFXOD+RK6VzM1nFgBwdJkW9wSG1UnuVERsj
# ZSi+QyZma3a9uxrqDqjLTr2A+l8lQF47qvSeElOPoC54E30C8NBs4HQxMwxFKHzM
# A/DNGnhAo4WGmM0om6+85hiHL0WqNuCd+PQ7Gqf5AG3UhlTj7mVLObeAjBIWxP+Z
# ZH1vBnm4IcGnE/E8ZD7BunNurx+xfo75BZNXRbXcB4wiRnzO5/DujypO04EUHrEF
# Dk7cqqaPefhzL+BjaOIzJH8uk82ihs8nTdPb91T1UOtO7NN48zt8pc+odZ2dMxR8
# BiLNk7Lh1GhWyhqQhc0yUZL9Cv7y9Ff3yQHZKOArhMulsFbg74o8CH1NfOBYcyDO
# F78bGzg=
# SIG # End signature block
