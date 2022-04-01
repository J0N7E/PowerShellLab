<#
 .DESCRIPTION
    Setup new VM
 .NOTES
    AUTHOR Jonas Henriksson
 .LINK
    https://github.com/J0N7E
#>

[cmdletbinding(DefaultParameterSetName='Standard')]

Param
(
    # Name of virtual machine
    [Parameter(Mandatory=$true)]
    [String]$VMName,

    # Path to labfolder
    [Parameter(Mandatory=$true)]
    [String]$LabFolder,

    # Path to VHDX file.
    [Parameter(Mandatory=$true)]
    [String]$Vhdx,

    # Network adapters
    $VMAdapters,

    # Start virtual machine
    [Switch]$Start,

    # Processors
    [Parameter(ParameterSetName='Standard')]
    [Int64]$ProcessorCount = 2,

    # Memory (dynamic)
    [Parameter(ParameterSetName='Standard')]
    [Int64]$MemoryStartupBytes = 512MB,

    # Setup for hosting cluster
    [Parameter(ParameterSetName='Cluster', Mandatory=$true)]
    [Switch]$Cluster=$false,

    # Cluster Processors
    [Parameter(ParameterSetName='Cluster')]
    [Int64]$ClusterProcessorCount = 4,

    # Cluster Memory (static)
    [Parameter(ParameterSetName='Cluster')]
    [Int64]$ClusterMemoryStartupBytes = 4GB,

    # Cluster disk
    [Parameter(ParameterSetName='Cluster')]
    [Int]$ClusterDisks = 10,

    # Cluster disk size (dynamic) (minimum 4GB)
    [Parameter(ParameterSetName='Cluster')]
    [Int64]$ClusterDiskSize = 4GB
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
        @{ Name = 'VMAdapters';     Type = [Array] }
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

    # Check if lab folder exist
    if (-not (Test-Path -Path "$LabFolder" -PathType Container))
    {
        New-Item -Path "$LabFolder" -ItemType Directory > $null
    }

    # Check if Vhdx exist
    if (-not (Test-Path -Path $Vhdx))
    {
        throw "$Vhdx don't exist"
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

    # Check if vm exist
    if (-not (Get-VM -Name $VMName -ErrorAction SilentlyContinue))
    {
        Write-Verbose -Message "Adding vm $VMName..." @VerboseSplat
        New-VM -Name $VMName -Path "$LabFolder" -Generation 2 > $null
        Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false
        Get-VM -Name $VMName | Remove-VMNetworkAdapter

        New-Item -ItemType Directory -Path "$LabFolder\$VMName\Virtual Hard Disks" -ErrorAction SilentlyContinue > $null

        if ($Cluster.IsPresent)
        {
            Set-VM -Name $VMName -StaticMemory -MemoryStartupBytes $ClusterMemoryStartupBytes -ProcessorCount $ClusterProcessorCount
            Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true

            for ($i = 1; $i -le $ClusterDisks; $i++)
            {
                $VHDPath = "$LabFolder\$VMName\Virtual Hard Disks\$VMName-JBOD$i.vhdx"

                New-VHD -Path $VHDPath -SizeBytes $ClusterDiskSize -Dynamic > $null
                Add-VMHardDiskDrive -VMName $VMName -Path $VHDPath
            }
        }
        else
        {
            Set-VM -Name $VMName -DynamicMemory -MemoryStartupBytes $MemoryStartupBytes -ProcessorCount $ProcessorCount
            Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $false
        }
    }

    # Copy vhdx
    if (-not (Test-Path -Path "$LabFolder\$VMName\Virtual Hard Disks\$VMName.vhdx" -PathType Leaf))
    {
        Write-Verbose -Message "Copying vhdx to vm folder..." @VerboseSplat
        Copy-Item -Path $Vhdx -Destination "$LabFolder\$VMName\Virtual Hard Disks\$VMName.vhdx"
    }

    # Add vhdx to vm
    if (-not (Get-VMHardDiskDrive -VMName $VMName -ErrorAction SilentlyContinue | Where-Object { $_.Path -match "$VMName.vhdx" }))
    {
        Write-Verbose -Message "Adding vhdx to vm..." @VerboseSplat
        Add-VMHardDiskDrive -VMName $VMName -Path "$LabFolder\$VMName\Virtual Hard Disks\$VMName.vhdx"
        Set-VMFirmware -VMName $VMName -FirstBootDevice (Get-VMHardDiskDrive -VMName $VMName | Where-Object { $_.Path -match "$VMName.vhdx" })
    }

    # Adapters
    if ($VMAdapters)
    {
        foreach($Adapter in $VMAdapters)
        {
            # Check if switch exist
            if (-not (Get-VMSwitch -Name $Adapter -ErrorAction SilentlyContinue))
            {
                $SwitchType = 'Private'

                if ($Adapter -match 'Dmz')
                {
                    $SwitchType = 'Internal'
                }

                Write-Verbose -Message "Adding $SwitchType switch $Adapter..." @VerboseSplat
                New-VMSwitch -SwitchType $SwitchType -Name $Adapter > $null
                Get-NetAdapter -Name 'vEthernet ($Adapter)' | Rename-NetAdapter -NewName $Adapter
            }

            # Check if adapter exist
            if (-not (Get-VMNetworkAdapter -VMName $VMName | Where-Object { $_.SwitchName -eq $Adapter}))
            {
                Write-Verbose -Message "Adding network adapter $Adapter..." @VerboseSplat
                Add-VMNetworkAdapter -VMName $VMName -SwitchName $Adapter -Name $Adapter
            }

            if ($Cluster.IsPresent)
            {
                Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing On -AllowTeaming On -DeviceNaming On
            }
            else
            {
                Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing Off -AllowTeaming Off -DeviceNaming On
            }
        }
    }
    else
    {
        Get-VMNetworkAdapter -VMName $VMName | Remove-VMNetworkAdapter
    }

    # Start vm
    if ($Start.IsPresent -and (Get-VM -Name $VMName).State -eq 'Off')
    {
        Write-Verbose -Message "Starting vm $VMName..." @VerboseSplat
        Start-VM -VMName $VMName > $null

        # Return
        Write-Output -InputObject @{ StartedVM = $VMName }
    }
}

End
{
}

# SIG # Begin signature block
# MIIY9AYJKoZIhvcNAQcCoIIY5TCCGOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVOG90ds8wNfbk7a+fbPt34Qa
# lwagghJ3MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# u5VPaG2W3eV3Ay67nBLvifkIP9Y1KTF5JS+wzJoYKvZ2MIIGrjCCBJagAwIBAgIQ
# BzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAw
# MDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5
# NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYR
# oUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CE
# iiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCH
# RgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5K
# fc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDni
# pUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2
# nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp
# 88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1C
# vwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+
# 0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl2
# 7KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOC
# AV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaa
# L3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcw
# AoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+
# ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvX
# bYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tP
# iix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCy
# Xen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpF
# yd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3
# fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t
# 5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejx
# mF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxah
# ZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAA
# zV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vup
# L0QVSucTDh3bNzgaoSv27dZ8/DCCBsYwggSuoAMCAQICEAp6SoieyZlCkAZjOE2G
# l50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYg
# U0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAwMDBaFw0zMzAzMTQy
# MzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEk
# MCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0M+7MXGzj4CUu0jHk
# PECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pGbumjS0joiUF/DbLW
# +YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzrsvGD0Z/NCcW5QWpF
# QiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJfD1De1FksRHTAMkcZ
# W+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU4S8D7n+FAsmG4dUY
# FLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g7a5/KC7CnuALS8gI
# 0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtDich+X7Aa3Rm9n3RB
# Cq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0MdI1DNkdcvnfv8zbHB
# p8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/H+gr5BSyFtaBocra
# MJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw40KV6J67m0uy4rZB
# Peevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTngIspQnL3ebLdhOon
# 7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsG
# CWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNV
# HQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMwUTBPoE2gS4ZJaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5
# NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEADS0j
# dKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZiz9d5YZPvpM63io5
# WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZy6HC6kx2yqHcoSuW
# uJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiKn+8RyTFKWLbfOHzL
# +lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB89Bemh2RPPkaJFmMg
# a8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5PELkwNuTzqmkJqIt+
# ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV41pj+VG1/calIGnjd
# RncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKOKGukzp123qlzqkhq
# WUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+NbTmtQyimaXXFWs1
# DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px38qXsdhH6hyF4EVO
# EhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX4IvTnMxttQ2uR2M4
# RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwxggXnMIIF4wIBATAiMA4xDDAK
# BgNVBAMMA2JjbAIQJoAlxDS3d7xJEXeERSQIkTAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUhS2m
# TWlbzn2IWzuWrwHarB8J1d4wDQYJKoZIhvcNAQEBBQAEggIAo+dxA2xK6YyZTCG2
# BiwEKO9FmtYls4xAX34qgjqzMipa0uTqmC53s0rVX3Ex80cijcYXrXrGYHGz468+
# B+kpJDwNrJBW9637+lkjJStx8dPFDg8c0qimTheFL4e5Z9+KeThICB41j13I3D/z
# tJ217nTITnAO5c8yVuI9HWMcaGiqmRVPO5C93nqTPMaWYJTjFl8cgEEACM2Uo9Dt
# Hmjsbsq4klLBdAnVkr8aAhAY2rjAW1kXPZGfsNgifHYlSj+SJl6Vw9O9x2bF//Bi
# 2t+IUgwgDqbjAGNRkD+G06dwx3RTd8Kgu+XoOyH9G+257m1pZhOUOJAzLOM1IgyP
# f4Wao4ATtHyUFZ+D14FFGQ+iWH+O/4mOIxdlnSRCu6kKp7V76/KfU0EbSlTo86es
# C8WAQZTQHV+qN0k6rH6woiMylBwSEaWkumqxLx/Eg7ewDKa96Kjm5oyvdg1gJzNi
# j21UROvXUKBZn/ecbbxPB9FjsptJqHurMBx4LGV2LdORT6ay/Cvox5lr8E5S0J+K
# +N35hkJ9mUnIXpNq3U7hsb4+Epzc35111OZwy5gXsKJyBNgQxzy3F2DAd3qzyDRl
# sqf2D5zieS46ttraGI1haFbi3OvVZ3vqxU8Henz13kFGW6ueLxEWen98wzwikML3
# kjI+CyGdhvqB6VKPUD637bZVKHahggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkC
# AQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0
# YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJ
# KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNDAxMjMw
# MDAzWjAvBgkqhkiG9w0BCQQxIgQgLJpTFuEfq0K6XIQ7EcCbvIihHGYs0z5XEVi9
# bZat878wDQYJKoZIhvcNAQEBBQAEggIAqTDH1AgIBzVvOO0sjrKCruSLwJ+cnGb+
# tV6SyU+mRzRygCVWG4L/Gca7OePh0t1Bqm6sD4+9CAGk0MW7AmUnzDp/seP1K019
# lF9/625YuE0UAow27LKe/Z3WQmcC3rV4aIEj8epLPY+zfDpTpHGbdceoAVDMIuJe
# QCBxvv5CG7myE10fxX3vfU/I2So4JQIRIdLV6+SAdpNtgTTJ4YjpIsAhdXFq4OiU
# SgKSlbuxa8wR9iYxWFW4sYMoPmILLBnaRLVk1NdXWSC9TTRytjCiY/bhS4wJjofF
# OVtytFtYlnxvnMiNIqTT0LZFQXGnynIlRVYQc8mPJo2n1k4SD5xjmr5b7YDj1N+g
# Oa281iG0a4zGJUdeyAnJlq6zHlQ022zwbtKyUDWY9aZxALKUwoQIfGiHP8stU5Eb
# PO5xgZWngoNZskOUSxBstBfRhE3GT6sHEk5qvDfyerW+JFT8XXa+1Rl5SP7eNNqH
# GXoaGOURcyNvZv9MfV0r1xQ9b2kkkBPZGuP1jI6U//CgnK3O4k0jE7+K9E3c3ZCe
# K26MHEwgrYrwU0FQhSclGx4KKbCTCt0LU1bCKRNV3rnbtqIaNiZftJ6Dl0OnCS1r
# ZR/fEcumH/UGoBUXrpU+GFZEIVA6Ewm21z5F9FIbQBdW9FXXtFlJaFUJoTvyXhxS
# Ev/lFfGqFbg=
# SIG # End signature block
