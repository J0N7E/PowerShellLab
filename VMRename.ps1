<#
 .DESCRIPTION
    Set computer name or join domain.
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

    # Serializable parameters
    $Session,
    $Credential,
    $DomainCredential,

    # New name to set
    [String]$NewName,
    # Name of domain to join
    [String]$JoinDomainName
)

Begin
{
    # ██████╗ ███████╗ ██████╗ ██╗███╗   ██╗
    # ██╔══██╗██╔════╝██╔════╝ ██║████╗  ██║
    # ██████╔╝█████╗  ██║  ███╗██║██╔██╗ ██║
    # ██╔══██╗██╔══╝  ██║   ██║██║██║╚██╗██║
    # ██████╔╝███████╗╚██████╔╝██║██║ ╚████║
    # ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝

    # Check if new name exist
    if (-not $NewName)
    {
        if ($VMName)
        {
            $NewName = $VMName
        }
        elseif ($ComputerName)
        {
            $NewName = $ComputerName
        }
    }

    ##############
    # Deserialize
    ##############

    $Serializable =
    @(
        @{ Name = 'Session';                                  },
        @{ Name = 'Credential';         Type = [PSCredential] },
        @{ Name = 'DomainCredential';   Type = [PSCredential] }
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

    # ███╗   ███╗ █████╗ ██╗███╗   ██╗
    # ████╗ ████║██╔══██╗██║████╗  ██║
    # ██╔████╔██║███████║██║██╔██╗ ██║
    # ██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    # ██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    # ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

    $MainScriptBlock =
    {
        # Define reboot of machine
        $Reboot = $false

        # Setup splat if to rename computer
        if ($NewName -and $NewName -ne $env:COMPUTERNAME)
        {
            $RenameComputerSplat =
            @{
                NewName = $NewName
            }
        }

        # Check if domain credentials exist
        if ($DomainCredential)
        {
            $Win32ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem

            # Check if to join domain
            if ($JoinDomainName -and $Win32ComputerSystem.Domain -ne $JoinDomainName)
            {
                if ($Win32ComputerSystem.PartOfDomain -and
                    (ShouldProcess @WhatIfSplat -Message "Removing `"$ENV:ComputerName`" from domain `"$($Win32ComputerSystem.Domain)`"." @VerboseSplat))
                {
                    Remove-Computer -WorkgroupName 'WORKGROUP' -Force
                }

                if (ShouldProcess @WhatIfSplat -Message "Adding `"$ENV:ComputerName`" to domain `"$JoinDomainName`"." @VerboseSplat)
                {
                    try
                    {
                        Add-Computer -DomainName $JoinDomainName -Credential $DomainCredential -ErrorAction Stop

                        # Give AD some time to sync
                        Start-Sleep -Seconds 3

                        $Reboot = $true
                    }
                    catch [Exception]
                    {
                        Write-Warning -Message $_
                    }
                }

            }

            # Add credential to rename splat
            if ($RenameComputerSplat)
            {
                $RenameComputerSplat.Add('DomainCredential', $DomainCredential)
            }
        }

        # Check if to rename computer
        if ($RenameComputerSplat -and
            (ShouldProcess @WhatIfSplat -Message "Renaming computer to `"$NewName`"" @VerboseSplat))
        {
            try
            {
                Rename-Computer @RenameComputerSplat -ErrorAction Stop
                $Reboot = $true
            }
            catch [Exception]
            {
                Write-Warning -Message $_
            }
        }

        # Check if to reboot
        if ($Reboot)
        {
            Read-Host -Prompt "Press <enter> to reboot"
            Restart-Computer -Force
            break
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

    # Load functions
    Invoke-Command -ScriptBlock `
    {
        try
        {
            . $PSScriptRoot\f_CheckContinue.ps1
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
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_CheckContinue.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            # Mandatory parameters
            $NewName = $Using:NewName
            $JoinDomainName = $Using:JoinDomainName
            $DomainCredential = $Using:DomainCredential
        }

        # Run main
        $Result = Invoke-Command -Session $Session -ScriptBlock $MainScriptBlock
    }
    else # Locally
    {
        Check-Continue -Message "Invoke locally?"

        # Load functions
        Invoke-Command -ScriptBlock `
        {
            try
            {
                . $PSScriptRoot\f_TryCatch.ps1
                . $PSScriptRoot\f_ShouldProcess.ps1
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
            foreach($Row in $Result.GetEnumerator())
            {
                Write-Host -Object "$($Row.Key) = $($Row.Value)"
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
# MIIUvwYJKoZIhvcNAQcCoIIUsDCCFKwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULId9fp6eg8Opz5aiEpFy16gU
# QKyggg8yMIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# okqV2PWmjlIxggT3MIIE8wIBATAiMA4xDDAKBgNVBAMMA2JjbAIQJoAlxDS3d7xJ
# EXeERSQIkTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUbPFsmUEjNCPLNIKqODmscef6a20wDQYJ
# KoZIhvcNAQEBBQAEggIAozrbiLiVA9d5wrvbbAw3j98anxuZ122GM52QseXU/jCT
# QG2/ldetjaYzGG//GF0Ni9oTcB5QZ9JdLKj0N9sLmRsJbQdARMtJIAHWHybF1yLt
# vDayO5rGkWc+iWU2ZxLR5Lm/paHUkK6frwH7uItGrvChgQrCqTJdZGqc26DhzSXI
# NST5LlVF5f8XbP+3NzO2aGnbLO49Ck13BtyClr3gyJyg+ggHqYOCyq187uQpFFtz
# i6PiF/+60bAMmPiO0D/ROJWlMHUMx9mTL9csCFNR2OKdVQgwfDpbK+P+uMN3mNxc
# yhjAlU2K9IxH9mlT9nypGemVAI6wio6Mf9mAUiTnFyDLjCQNaoyNmdOCuwuL6WVS
# ywDFh1Cjwsuf+oO7FZyRHXgStLfnjc8Nq8/49NI7VHnbtFpzHyJZ7UW2JW75sQIY
# ro+aBGjAJfHs/2KFnok8qLfJ1ppsV2nU6sghBABu2WObt/jkHJteZ6vK29VwWq3c
# Zr6ePI2AV9aAY4fqb8XAavLzqK0jFNUnn+m0StMftSRIvdjlwzledqqIBiJPbWve
# X9ckw72X/mK4M1Ms5yuNigzx/O7UdWm7RV1hbJUNyy2zhJNqOtwSgfusJAqATzKp
# 4bA5b/lSxE820qxCdzLprs0pZ2e+z6ps0WiUpeHVxDUPVnYZENJCDl9q2lHOkVuh
# ggIwMIICLAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGlu
# ZyBDQQIQDUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDMxODIzMDAwM1ow
# LwYJKoZIhvcNAQkEMSIEIFWQ+iK/o5Wwy7SgbzXxN9ENHslgH0UXRGsyJWY8jeo/
# MA0GCSqGSIb3DQEBAQUABIIBALUAqtOUSq55Rr9GHE3ZaFxmvKYYpnT2CAR016A6
# EClclQ/zumAwrdvqQY0w/W33hVqjCAuB3TdzGkbCKmP+5eVqp5ajHz+RL6i2N7jy
# 7zBeVtXyUlPGc/cb52dNiDAzuRiczrIy0/ZggLG/QyHgmLtNWb+JLxhQruDtnLfB
# HOxTF87bjgrr2AfG+d4h8RvEBv7lTqcxx2EPK1GiGH3OWZ3LjoSkc/CGjDYL71tC
# E024oJDILKO5fOBrtNbJB4ERW2eyNBAmI8loPVSAH64fxJFcJ40M7Df7exYqHM6h
# 0IEXdZCTWMeb4xhYADc6KVeKPQCpI3qFwbbij7/hLUK3Bkk=
# SIG # End signature block
