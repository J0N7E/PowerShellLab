<#
 .DESCRIPTION
    Setup new VM
 .NOTES
    AUTHOR Jonas Henriksson
 .LINK
    https://github.com/J0N7E
#>

[cmdletbinding()]

Param
(
    # Path to labfolder
    [Parameter(Mandatory=$true)]
    [String]$LabFolder,

    # Name of switch
    [Parameter(Mandatory=$true)]
    [String]$LabSwitch,

    # Name of virtual machine
    [Parameter(Mandatory=$true)]
    [String]$VMName,

    # Path to VHDX file.
    [Parameter(Mandatory=$true)]
    [String]$Vhdx,

    # Start virtual machine
    [Switch]$Start,

    # Processors
    [Parameter(ParameterSetName='Standard')]
    [Int64]$ProcessorCount = 2,

    # Memory (dynamic)
    [Parameter(ParameterSetName='Standard')]
    [Int64]$MemoryStartupBytes = 512MB,

    # Setup for hosting cluster
    [Parameter(Mandatory=$true)]
    [Parameter(ParameterSetName='Cluster')]
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

    #####################
    # Verbose Preference
    #####################

    # Initialize verbose
    $VerboseSplat = @{}

    # Check verbose
    if ($VerbosePreference -ne 'SilentlyContinue')
    {
        # Reset verbose preference
        $VerbosePreference = 'SilentlyContinue'

        # Set verbose splat
        $VerboseSplat.Add('Verbose', $true)
    }

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

    # Verbose with timestamp output
    function Write-TimeStamp
    {
        Param
        (
            [Parameter(Mandatory=$true)]
            [String]$Message
        )

        Write-Verbose -Message "[$(Get-Date -Format "HH:mm:ss")] $Message" @VerboseSplat
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

    # Check if switch exist
    if (-not (Get-VMSwitch -Name $LabSwitch -ErrorAction SilentlyContinue))
    {
        Write-TimeStamp -Message "Adding $LabSwitch Switch..."
        New-VMSwitch -SwitchType Private -Name $LabSwitch > $null
    }

    # Check if vm exist
    if (-not (Get-VM -Name $VMName -ErrorAction SilentlyContinue))
    {
        Write-TimeStamp -Message "Adding vm $VMName..."
        New-VM -Name $VMName -Path "$LabFolder" -SwitchName $LabSwitch -Generation 2 > $null
        Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false
        New-Item -ItemType Directory -Path "$LabFolder\$VMName\Virtual Hard Disks" -ErrorAction SilentlyContinue > $null

        if (-not $Cluster.IsPresent)
        {
            Set-VM -Name $VMName -DynamicMemory -MemoryStartupBytes $MemoryStartupBytes -ProcessorCount $ProcessorCount
            Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $false
            Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing Off -AllowTeaming Off
        }
        else
        {
            Set-VM -Name $VMName -StaticMemory -MemoryStartupBytes $ClusterMemoryStartupBytes -ProcessorCount $ClusterProcessorCount
            Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true

            Add-VMNetworkAdapter -VMName $VMName -SwitchName $LabSwitch
            Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing On -AllowTeaming On

            for ($i = 1; $i -le $ClusterDisks; $i++)
            {
                $VHDPath = "$LabFolder\$VMName\Virtual Hard Disks\$VMName-JBOD$i.vhdx"

                New-VHD -Path $VHDPath -SizeBytes $ClusterDiskSize -Dynamic > $null
                Add-VMHardDiskDrive -VMName $VMName -Path $VHDPath
            }
        }
    }

    # Copy vhdx
    if (-not (Test-Path -Path "$LabFolder\$VMName\Virtual Hard Disks\$VMName.vhdx" -PathType Leaf))
    {
        Write-TimeStamp -Message "Copying vhdx to vm folder..."
        Copy-Item -Path $Vhdx -Destination "$LabFolder\$VMName\Virtual Hard Disks\$VMName.vhdx"
    }

    # Add vhdx to vm
    if (-not (Get-VMHardDiskDrive -VMName $VMName -ErrorAction SilentlyContinue | Where-Object { $_.Path -match "$VMName.vhdx" }))
    {
        Write-TimeStamp -Message "Adding vhdx to vm..."
        Add-VMHardDiskDrive -VMName $VMName -Path "$LabFolder\$VMName\Virtual Hard Disks\$VMName.vhdx"
        Set-VMFirmware -VMName $VMName -FirstBootDevice (Get-VMHardDiskDrive -VMName $VMName | Where-Object { $_.Path -match "$VMName.vhdx" })
    }

    # Start vm
    if ($Start.IsPresent -and (Get-VM -Name $VMName).State -eq 'Off')
    {
        Write-TimeStamp -Message "Starting vm..."
        Start-VM -VMName $VMName > $null
    }
}

End
{
}

# SIG # Begin signature block
# MIIUrwYJKoZIhvcNAQcCoIIUoDCCFJwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7HsaPz8ey915y0q8opASq/P4
# HbKggg8yMIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# u5VPaG2W3eV3Ay67nBLvifkIP9Y1KTF5JS+wzJoYKvZ2MIIE/jCCA+agAwIBAgIQ
# DUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5n
# IENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEwNjAwMDAwMFowSDELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBU
# aW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMLm
# YYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQtSYQ/h3Ib5FrDJbnGlxI70Tlv5th
# zRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4bbx9+cdtCT2+anaH6Yq9+IRdHnbJ
# 5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOKfF1FLUuxUOZBOjdWhtyTI433UCXo
# ZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlKXAwxikqMiMX3MFr5FK8VX2xDSQn9
# JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYervnpbCiAvSwnJlaeNsvrWY4tOpXIc
# 7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0MA4GA1UdDwEB/wQEAwIHgDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEEGA1UdIAQ6MDgwNgYJ
# YIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29t
# L0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLkYaWyoiWyyBc1bjAdBgNVHQ4EFgQU
# NkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0fBGowaDAyoDCgLoYsaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwMqAwoC6GLGh0dHA6
# Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMIGFBggrBgEF
# BQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBP
# BggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOC
# AQEASBzctemaI7znGucgDo5nRv1CclF0CiNHo6uS0iXEcFm+FKDlJ4GlTRQVGQd5
# 8NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4eTZ6J7fz51Kfk6ftQ55757TdQSKJ
# +4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2hF3MN9PNlOXBL85zWenvaDLw9MtAb
# y/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1FUL1LTI4gdr0YKK6tFL7XOBhJCVP
# st/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6Xt/Q/hOvB46NJofrOp79Wz7pZdmGJ
# X36ntI5nePk2mOHLKNpbh6aKLzCCBTEwggQZoAMCAQICEAqhJdbWMht+QeQF2jaX
# whUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGln
# aUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTE2MDEwNzEyMDAwMFoXDTMxMDEw
# NzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hB
# MiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnFOVQoV7YjSsQOB0UzURB90Pl9TWh+
# 57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQAOPcuHjvuzKb2Mln+X2U/4Jvr40ZH
# BhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhisEeTwmQNtO4V8CdPuXciaC1TjqAlx
# a+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQjMF287DxgaqwvB8z98OpH2YhQXv1m
# blZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+fMRTWrdXyZMt7HgXQhBlyF/EXBu89
# zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW/5MCAwEAAaOCAc4wggHKMB0GA1Ud
# DgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCB
# gQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBQBgNVHSAESTBHMDgG
# CmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
# Y29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggEBAHGVEulRh1Zp
# ze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafDDiBCLK938ysfDCFaKrcFNB1qrpn4
# J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6HHssIeLWWywUNUMEaLLbdQLgcseY
# 1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4H9YLFKWA1xJHcLN11ZOFk362kmf7
# U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHKeZR+WfyMD+NvtQEmtmyl7odRIeRY
# YJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIoxhhWz0E0tmZdtnR79VYzIi8iNrJL
# okqV2PWmjlIxggTnMIIE4wIBATAiMA4xDDAKBgNVBAMMA2JjbAIQJoAlxDS3d7xJ
# EXeERSQIkTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUMGdpNdUBO8R4i/pTHw3Pk8OKu68wDQYJ
# KoZIhvcNAQEBBQAEggIADgmlIcQbIZXPyjNFxjH92eyNeCVo9UD3ZaCoFr/zq2Ud
# kYRpx7nCEPwukWnth7XAtBy77h4zVDNe8hphgfECKy/Hekz9NIx0M4eOyuJrQZzX
# OEA92LgXk9F0l8lgTCWCHUHcuTOFlN5YWe0yNtO8W++hWjlJ0xjvZk09RmBvF397
# LnqQSepFYbmqt/kVBTZriIUo11rK9usgyzyCqiznbZXzeFeDclTJH9dkKp+vTGgq
# dvXbgi01fEQGbcK+5xgtYDbxNkPaGWvtMTeRExHz5cmZo9jlE8un95Of86jgKSuA
# lmCKF/0CNjf833mLBzrk9RFDj4OusWqEsEY5T5Pr7w2rI71XIx7CnuPmRef6gXot
# ibeNsCVT3Rqu/Foxv0zSs/k80UYgtRIQQ8P2BJO9I+4320s614/48k4yCNlONWGQ
# ++caZhEqtgl96HLTFFYDV5XB1uBuQCwXL5yqlclDMFUx+JKi01WXS0aZnoyRDtR/
# Q9INHkw4JyURyAltugHaOrpvQ2Y6qBMUSmws75dnIypBa3+idItRzviq+v4cWU3w
# lq40W3KxB4nhjZaxKgWA5WSDJR2ATKkUN2nx5Bd5n+P74inE3f8E7mD8jOlYfjl+
# b99bPtOzydvOKLS2M8Ng7ONWIjI2YCNAW02ETWYRoWZ3T6WSo44KdwyTPEvur8uh
# ggIgMIICHAYJKoZIhvcNAQkGMYICDTCCAgkCAQEwgYYwcjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGlu
# ZyBDQQIQDUJK4L46iP9gQCHOFADw3TAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjEwMjA0MjE0NTQ0WjAjBgkq
# hkiG9w0BCQQxFgQUTaXDWMal94i1OdJoDb2x+yLnrNQwDQYJKoZIhvcNAQEBBQAE
# ggEAdtD/Ke6TG3Gn/V5wjjftfykVAzZG/EEqKsGan90nyIQPqGf2bT7D9l73E/Hb
# hLnUvf6RZsym2vjsJKcLie/Lt0Y5nUNeS6gYNTYWdRsKixkFPWGNUE+O7y/q1fbQ
# gFe71O5bvgSsp1ec6CgJAeYYuNW8w1AyOsT2/7Jqqk6c87wLjOEs0Mi5Kr/DxPQR
# b9/4SexwApM1oFwA/RMSbnok+Q7P41okNDsZD6rRf/UfxFF1L6Pr8U5iuJbecR9E
# qhuO3y0OQtI/vf/X17n1xYb6+2DgslZxkBGrLlbHnmIymSMCZnGm1suMOOkceQPi
# bk035nQTVXjGXn/G8XZkTp//8Q==
# SIG # End signature block
