<#
 .DESCRIPTION
    Enter description
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

    $EnvDataDrive = 'C:'
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
        @{ Name = 'Session';                              },
        @{ Name = 'Credential';     Type = [PSCredential] }
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
        $Admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        # FIX
        # make importable
        function SetRegistry
        {
            [cmdletbinding(SupportsShouldProcess=$true)]

            param
            (
                [Array]$Settings
            )

            foreach ($Setting in $Settings)
            {
                if ($Setting.Path.StartsWith('HKEY_CURRENT_USER') -or ($Setting.Path.StartsWith('HKEY_LOCAL_MACHINE') -and $Admin))
                {
                    $ItemValue = [microsoft.win32.registry]::GetValue($Setting.Path, $Setting.Name, $null)

                    #https://docs.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvaluekind?view=dotnet-plat-ext-3.1
                    switch ($Setting.PropertyType)
                    {
                        'String'
                        {
                            $ValueKind    = 1
                            $ValueDiffers = $ItemValue -ne $Setting.Value
                        }
                        'ExpandString'
                        {
                            $ValueKind    = 2
                            $ValueDiffers = $ItemValue -ne $Setting.Value
                        }
                        'Binary'
                        {
                            $ValueKind    = 3
                            $ValueDiffers = @(Compare-Object -ReferenceObject $Setting.Value -DifferenceObject $ItemValue -SyncWindow 0).Length -ne 0
                        }
                        'DWord'
                        {
                            $ValueKind    = 4
                            #$ValueDiffers = $ItemValue -ne [Convert]::ToInt64($Setting.Value,16)
                            $ValueDiffers = $ItemValue -ne $Setting.Value
                        }
                    }

                    if ($ValueDiffers)
                    {
                        if ($Setting.Name -in @('Value', 'Start', 'Enabled', 'Disabled'))
                        {
                            $DisplayName = $Setting.Path.SubString($Setting.Path.LastIndexOf('\') + 1)
                        }
                        else
                        {
                            $DisplayName = $Setting.Name
                        }

                        if (ShouldProcess @WhatIfSplat -Message "Setting `"$DisplayName`" to `"$($Setting.Value)`"" @VerboseSplat)
                        {
                            [microsoft.win32.registry]::SetValue($Setting.Path, $Setting.Name, $Setting.Value, $ValueKind)
                        }
                    }
                }
            }
        }

        # ███████╗ ██████╗ ██╗     ██████╗ ███████╗██████╗ ███████╗
        # ██╔════╝██╔═══██╗██║     ██╔══██╗██╔════╝██╔══██╗██╔════╝
        # █████╗  ██║   ██║██║     ██║  ██║█████╗  ██████╔╝███████╗
        # ██╔══╝  ██║   ██║██║     ██║  ██║██╔══╝  ██╔══██╗╚════██║
        # ██║     ╚██████╔╝███████╗██████╔╝███████╗██║  ██║███████║
        # ╚═╝      ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝

        $Folders =
        @(
            "$EnvDataDrive\Desktop",
            "$EnvDataDrive\Downloads"
        )

        foreach ($Folder in $Folders)
        {
            # Check if folder exist
            if (-not (Test-Path -Path $Folder) -and
               (ShouldProcess @WhatIfSplat -Message "Creating `"$Folder`" directory." @VerboseSplat))
            {
                New-Item -Path $Folder -ItemType Directory > $null
            }
        }

        # ███████╗███╗   ██╗██╗   ██╗
        # ██╔════╝████╗  ██║██║   ██║
        # █████╗  ██╔██╗ ██║██║   ██║
        # ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝
        # ███████╗██║ ╚████║ ╚████╔╝
        # ╚══════╝╚═╝  ╚═══╝  ╚═══╝

        $EnvironmentVariables =
        @(
           @{ Name = 'DataDrive';          Value =  $EnvDataDrive },
           @{ Name = 'Dropbox';            Value = "$EnvDataDrive\Dropbox" },
           @{ Name = 'Documents';          Value = "$EnvDataDrive\Dropbox\Documents" },
           @{ Name = 'Pictures';           Value = "$EnvDataDrive\Dropbox\Pictures" },
           @{ Name = 'Music';              Value = "$EnvDataDrive\Dropbox\Music" },
           @{ Name = 'Desktop';            Value = "$EnvDataDrive\Desktop" },
           @{ Name = 'Downloads';          Value = "$EnvDataDrive\Downloads" },
           @{ Name = 'SendTo';             Value = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name 'SendTo').SendTo },
           @{ Name = 'StartMenu';          Value = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name 'Start Menu').'Start Menu' },
           @{ Name = 'AllUsersStartMenu';  Value = "$env:ProgramData\Microsoft\Windows\Start Menu" }
           @{ Name = 'OPENSSL_CONF';       Value = "$EnvDataDrive\Dropbox\BAT\bin\openssl\openssl.cnf" }
        )

        foreach ($Var in $EnvironmentVariables)
        {
            # $env:
            if ((Get-Item -Path "env:$($Var.Name)" -ErrorAction SilentlyContinue).Value -ne $Var.Value -and
               (ShouldProcess @WhatIfSplat -Message "Setting `$env:$($Var.Name) to `"$($Var.Value)`"" @VerboseSplat))
            {
                Set-Item -Path "env:$($Var.Name)" -Value $Var.Value
            }

            # Set
            if ([Environment]::GetEnvironmentVariable($Var.Name, "User") -ne $Var.Value -and
               (ShouldProcess @WhatIfSplat -Message "Setting user variable $($Var.Name) to `"$($Var.Value)`"" @VerboseSplat))
            {
                [Environment]::SetEnvironmentVariable($Var.Name, $Var.Value, "User")
            }
        }

        # ███████╗██╗  ██╗███████╗██╗     ██╗         ███████╗ ██████╗ ██╗     ██████╗ ███████╗██████╗ ███████╗
        # ██╔════╝██║  ██║██╔════╝██║     ██║         ██╔════╝██╔═══██╗██║     ██╔══██╗██╔════╝██╔══██╗██╔════╝
        # ███████╗███████║█████╗  ██║     ██║         █████╗  ██║   ██║██║     ██║  ██║█████╗  ██████╔╝███████╗
        # ╚════██║██╔══██║██╔══╝  ██║     ██║         ██╔══╝  ██║   ██║██║     ██║  ██║██╔══╝  ██╔══██╗╚════██║
        # ███████║██║  ██║███████╗███████╗███████╗    ██║     ╚██████╔╝███████╗██████╔╝███████╗██║  ██║███████║
        # ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝    ╚═╝      ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝

        $ShellFolders =
        @(
            @{ Name = 'Desktop';                                 Value = "$EnvDataDrive\Desktop";            PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = 'Personal';                                Value = "$EnvDataDrive\Dropbox\Documents";  PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = '{F42EE2D3-909F-4907-8871-4C22FC0BF756}';  Value = "$EnvDataDrive\Dropbox\Documents";  PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = '{374DE290-123F-4565-9164-39C4925E467B}';  Value = "$EnvDataDrive\Downloads";          PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = '{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}';  Value = "$EnvDataDrive\Downloads";          PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = 'My Pictures';                             Value = "$EnvDataDrive\Dropbox\Pictures";   PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = '{0DDD015D-B06C-45D5-8C4C-F59713854639}';  Value = "$EnvDataDrive\Dropbox\Pictures";   PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' }
            @{ Name = 'My Music';                                Value = "$EnvDataDrive\Dropbox\Music";      PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = '{A0C69A99-21C8-4671-8703-7934162FCF1D}';  Value = "$EnvDataDrive\Dropbox\Music";      PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' }
        )

        SetRegistry -Settings $ShellFolders

        ################################
        # Remove namespace from this pc
        ################################

        if ($Admin)
        {
            $NameSpaces =
            @(
                @{ Name = '3DObjects';  Guid = '{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}' },
                @{ Name = 'Music';      Guid = '{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}' },
                @{ Name = 'Downloads';  Guid = '{088E3905-0323-4B02-9826-5D99428E115F}' },
                @{ Name = 'Pictures';   Guid = '{24AD3AD4-A569-4530-98E1-AB02F9417AA8}' },
                @{ Name = 'Videos';     Guid = '{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}' },
                @{ Name = 'Documents';  Guid = '{D3162B92-9365-467A-956B-92703ACA08AF}' },
                @{ Name = 'Desktop';    Guid = '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' }
            )

            foreach ($Item in $NameSpaces)
            {
                $Paths =
                @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\$($Item.Guid)",
                    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\$($Item.Guid)"
                )

                foreach ($Path in $Paths)
                {
                    if ((Get-Item -Path $Path -ErrorAction SilentlyContinue) -and
                        (ShouldProcess @WhatIfSplat -Message "Removing `"$($Item.Name)`"" @VerboseSplat))
                    {
                        Remove-Item -Path $Path
                    }
                }
            }
        }

        # ██████╗  █████╗ ████████╗██╗  ██╗
        # ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
        # ██████╔╝███████║   ██║   ███████║
        # ██╔═══╝ ██╔══██║   ██║   ██╔══██║
        # ██║     ██║  ██║   ██║   ██║  ██║
        # ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝

        $Bin = Get-ChildItem -Path "$env:Dropbox\Bat\bin" -ErrorAction SilentlyContinue

        if ($Bin)
        {
            $UserPaths =
            @(
                "$env:Dropbox\Bat"
            )

            # Add all paths under bin
            foreach($Dir in $Bin)
            {
                $UserPaths += -join("$env:Dropbox\Bat\bin\", $Dir.ToString())
            }

            # Add lib
            if (Test-Path -Path "$env:Dropbox\Bat\lib")
            {
                $UserPaths += "$env:Dropbox\Bat\lib"
            }

            # Add all paths
            foreach($Path in $UserPaths)
            {
                $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")

                if($CurrentPath -notmatch [Regex]::Escape($Path) -and
                  (ShouldProcess @WhatIfSplat -Message "Adding path `"$Path`"" @VerboseSplat))
                {
                    [Environment]::SetEnvironmentVariable("Path", -join($CurrentPath, $Path, ';'), "User")
                }
            }
        }

        # ██████╗  ██████╗ ██╗    ██╗███████╗██████╗
        # ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗
        # ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝
        # ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗
        # ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║
        # ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝

        # Type ac = plugged, dc = battery
        $PowerSetting =
        @(
            @{ FriendlyName = 'Turn off hard disk after';  Value = '0x00000000';  Type = 'AC';  SubgroupSetting = "0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e" },
            @{ FriendlyName = 'Sleep after';               Value = '0x00000000';  Type = 'AC';  SubgroupSetting = "238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da" },
            @{ FriendlyName = 'Hibernate after';           Value = '0x00000000';  Type = 'AC';  SubgroupSetting = "238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364" },
            @{ FriendlyName = 'Turn off display after';    Value = '0x00000000';  Type = 'AC';  SubgroupSetting = "7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" }
            #@{ FriendlyName = 'Lid close action';          Value = '0x00000000';  Type = 'AC';  SubgroupSetting = "4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936" }, # 0 = None
            #@{ FriendlyName = 'Lid close action';          Value = '0x00000000';  Type = 'DC';  SubgroupSetting = "4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936" }, # 0 = None
            #@{ FriendlyName = 'Power button action';       Value = '0x00000003';  Type = 'AC';  SubgroupSetting = "4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280" }, # 3 = Shut down
            #@{ FriendlyName = 'Power button action';       Value = '0x00000003';  Type = 'DC';  SubgroupSetting = "4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280" }  # 3 = Shut down
        )

        # Itterate scheme
        foreach ($Scheme in (Invoke-Expression -Command 'powercfg -list' | Where-Object { $_ -match "([a-z0-9-]{36})" } | ForEach-Object { $Matches[1] }))
        {
            foreach ($Setting in $PowerSetting)
            {
                $ValueDec = [Convert]::ToInt64($Setting.Value,16)

                if ($Setting.Value -ne (Invoke-Expression -Command "cmd /c 'powercfg -query $Scheme $($Setting.SubgroupSetting)'" | Where-Object {
                                            $_ -match "Current $($Setting.Type.ToUpper()) Power Setting Index: (.*)$"
                                        } | ForEach-Object { "$($Matches[1])" }) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting `"$($Setting.FriendlyName)`" $($Setting.Type) to `"$ValueDec`"" @VerboseSplat))
                {
                    Invoke-Expression -Command "cmd /c 'powercfg -set$($Setting.Type.ToLower())valueindex $Scheme $($Setting.SubgroupSetting) $ValueDec' 2>&1" > $null
                }
            }
        }

        #  ██████╗███████╗██████╗ ████████╗██╗███████╗██╗ ██████╗ █████╗ ████████╗███████╗
        # ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝
        # ██║     █████╗  ██████╔╝   ██║   ██║█████╗  ██║██║     ███████║   ██║   █████╗
        # ██║     ██╔══╝  ██╔══██╗   ██║   ██║██╔══╝  ██║██║     ██╔══██║   ██║   ██╔══╝
        # ╚██████╗███████╗██║  ██║   ██║   ██║██║     ██║╚██████╗██║  ██║   ██║   ███████╗
        #  ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

        $CertificateStores = @('Cert:\CurrentUser\TrustedPublisher', 'Cert:\CurrentUser\Root')

        foreach($Store in $CertificateStores)
        {
            if (-not (Get-ChildItem -Path "$Store\*" | Where-Object {
                        ($_.DnsNameList.Where({ $_ -eq 'bcl' })) -and
                         $_.Extensions.Where({ $_.Oid.Value -eq "2.5.29.37" -and $_.EnhancedKeyUsages.FriendlyName.Contains('Code Signing')}) }) -and
                (ShouldProcess @WhatIfSplat -Message "Adding bcl Code Signing certificate to $Store" @VerboseSplat))
            {
                Import-Certificate -FilePath "$env:Dropbox\Setup\Certificates\bcl.cer" -CertStoreLocation $Store | Out-Null
            }
        }

        # ██████╗ ███████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗ █████╗ ██╗
        # ██╔══██╗██╔════╝██╔════╝ ██║██╔═══██╗████╗  ██║██╔══██╗██║
        # ██████╔╝█████╗  ██║  ███╗██║██║   ██║██╔██╗ ██║███████║██║
        # ██╔══██╗██╔══╝  ██║   ██║██║██║   ██║██║╚██╗██║██╔══██║██║
        # ██║  ██║███████╗╚██████╔╝██║╚██████╔╝██║ ╚████║██║  ██║███████╗
        # ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝

        # Culture
        if ((Get-Culture).Name -ne 'sv-SE' -and
            (ShouldProcess @WhatIfSplat -Message "Setting culture to sv-SE" @VerboseSplat))
        {
            Set-Culture -CultureInfo sv-SE
        }

        # Location
        if ((Get-WinHomeLocation).GeoId -ne 221 -and
            (ShouldProcess @WhatIfSplat -Message "Setting location to Sweden" @VerboseSplat))
        {
            Set-WinHomeLocation -GeoId 221
        }

        # Language
        if ((Get-WinUserLanguageList).LanguageTag -ne 'sv-SE' -and
            (ShouldProcess @WhatIfSplat -Message "Setting language to sv-SE" @VerboseSplat))
        {
            Set-WinUserLanguageList -LanguageList sv-SE -Force
        }

        # Timezone
        if ((Get-TimeZone).Id -ne 'W. Europe Standard Time' -and
            (ShouldProcess @WhatIfSplat -Message "Setting time zone to `"W. Europe Standard Time`"" @VerboseSplat))
        {
            Set-TimeZone -Name "W. Europe Standard Time"
        }

        # ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██████╗ ███████╗██████╗
        # ██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██╔══██╗██╔════╝██╔══██╗
        # █████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██████╔╝█████╗  ██████╔╝
        # ██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██╗
        # ███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║  ██║███████╗██║  ██║
        # ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

        $AccentPalette = [byte[]](0x9b,0x9a,0x99,0x00,0x84,0x83,0x81,0x00,0x6d,0x6b,0x6a,0x00,0x4c,0x4a,0x48,0x00,0x36,0x35,0x33,0x00,0x26,0x25,0x24,0x00,0x19,0x19,0x19,0x00,0x10,0x7c,0x10,0x00)

        $ExplorerSettings =
        @(
            # Set no sound scheme
            @{ Name = '(Default)';              Value = '.None';     PropertyType = 'String';  Path = 'HKEY_CURRENT_USER\AppEvents\Schemes' },

            # Disable accessibility keys
            @{ Name = 'Flags';                  Value = 122;         PropertyType = 'String';  Path = 'HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response' },
            @{ Name = 'Flags';                  Value = 506;         PropertyType = 'String';  Path = 'HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys' },
            @{ Name = 'Flags';                  Value = 58;          PropertyType = 'String';  Path = 'HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys' },

            # Hide recently used files in quick access
            @{ Name = 'ShowRecent';             Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer' },

            # Hide frequently used folders in quick access
            @{ Name = 'ShowFrequent';           Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer' },

            # Hide recently opened items in jump lists
            @{ Name = 'Start_TrackDocs';        Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Set accent color
            @{ Name = 'AccentPalette';      Value = $AccentPalette;  PropertyType = 'Binary';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' },
            @{ Name = 'StartColorMenu';     Value = 0xff333536;      PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' },
            @{ Name = 'AccentColorMenu';    Value = 0xff484a4c;      PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' },

            # Show hidden files
            @{ Name = 'Hidden';                 Value = 1;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Show file extensions
            @{ Name = 'HideFileExt';            Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Open file explorer to this pc
            @{ Name = 'LaunchTo';               Value = 1;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Disable snap assist
            @{ Name = 'SnapAssist';             Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Hide task view button
            @{ Name = 'ShowTaskViewButton';     Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Hide search icon
            @{ Name = 'SearchboxTaskbarMode';   Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search' },

            # Show taskbar buttons where window is open
            @{ Name = 'MMTaskbarMode';          Value = 2;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Use dark theme
            @{ Name = 'AppsUseLightTheme';      Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' },

            # Set accent color
            @{ Name = 'AccentColor';            Value = 0xff484a4c;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' },
            @{ Name = 'ColorizationColor';      Value = 0xc44c4a48;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' },
            @{ Name = 'ColorizationAfterglow';  Value = 0xc44c4a48;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' }
        )

        SetRegistry -Settings $ExplorerSettings

        # Clear recent
        if ((Get-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*") -and
            (ShouldProcess @WhatIfSplat -Message "Clearing recent." @VerboseSplat))
        {
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse
        }

        # ██████╗ ██████╗ ██╗██╗   ██╗ █████╗  ██████╗██╗   ██╗
        # ██╔══██╗██╔══██╗██║██║   ██║██╔══██╗██╔════╝╚██╗ ██╔╝
        # ██████╔╝██████╔╝██║██║   ██║███████║██║      ╚████╔╝
        # ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══██║██║       ╚██╔╝
        # ██║     ██║  ██║██║ ╚████╔╝ ██║  ██║╚██████╗   ██║
        # ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝   ╚═╝

        $ScheduledTasks =
        @(
            @{ Path = '\Microsoft\Office\';                                           Name = 'Office ClickToRun Service Monitor' },
            @{ Path = '\Microsoft\Office\';                                           Name = 'OfficeTelemetryAgentFallBack2016' },
            @{ Path = '\Microsoft\Office\';                                           Name = 'OfficeTelemetryAgentLogOn2016' },
            @{ Path = '\Microsoft\Windows\Application Experience\';                   Name = 'Microsoft Compatibility Appraiser' },
            @{ Path = '\Microsoft\Windows\Application Experience\';                   Name = 'ProgramDataUpdater' },
            @{ Path = '\Microsoft\Windows\Autochk\';                                  Name = 'Proxy' },
            @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\';  Name = 'Consolidator' },
            @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\';  Name = 'KernelCeipTask' },
            @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\';  Name = 'UsbCeip' },
            @{ Path = '\Microsoft\Windows\DiskDiagnostic\';                           Name = 'Microsoft-Windows-DiskDiagnosticDataCollector' },
            @{ Path = '\Microsoft\Windows\Feedback\Siuf\';                            Name = 'DmClient' },
            @{ Path = '\Microsoft\Windows\Feedback\Siuf\';                            Name = 'DmClientOnScenarioDownload' },
            @{ Path = '\Microsoft\Windows\PI\';                                       Name = 'Sqm-Tasks' },
            @{ Path = '\Microsoft\Windows\Windows Error Reporting\';                  Name = 'QueueReporting' }
        )

        if ($Admin)
        {
            foreach ($Task in $ScheduledTasks)
            {
                $ScheduledTask = Get-ScheduledTask -TaskPath $Task.Path -TaskName $Task.Name -ErrorAction SilentlyContinue

                if ($ScheduledTask -and $ScheduledTask.State -ne 'Disabled' -and
                    (ShouldProcess @WhatIfSplat -Message "Disabling task `"$($Task.Name)`"." @VerboseSplat))
                {
                    Disable-ScheduledTask -TaskPath $Task.Path -TaskName $Task.Name > $null
                }
            }

        }

        # Allow domain PIN login
        #@{ Name = 'ColorizationAfterglow';  Value = '0xc44c4a48';     PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' }

        #  █████╗ ██████╗ ██████╗ ██╗  ██╗
        # ██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝
        # ███████║██████╔╝██████╔╝ ╚███╔╝
        # ██╔══██║██╔═══╝ ██╔═══╝  ██╔██╗
        # ██║  ██║██║     ██║     ██╔╝ ██╗
        # ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝

        # View apps
        #Get-AppxPackage | Where-Object { $_.IsFramework -eq $false -and $_.SignatureKind -eq 'Store' } | Select-Object -ExpandProperty Name | Sort-Object

        # Set apps to remove
        $RemoveApps =
        @(
            'Microsoft.549981C3F5F10', # Cortana
            'Microsoft.BingNews',
            'Microsoft.BingWeather',
            'Microsoft.GetHelp',
            'Microsoft.Getstarted',
            'Microsoft.Messaging',
            'Microsoft.Microsoft3DViewer',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.MixedReality.Portal',
            'Microsoft.MSPaint',
            'Microsoft.Office.OneNote',
            'Microsoft.OneConnect',
            'Microsoft.People',
            'Microsoft.SkypeApp',
            'Microsoft.Windows.Photos',
            'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera',
            'Microsoft.WindowsCommunicationsApps',
            'Microsoft.WindowsFeedbackHub',
            'Microsoft.WindowsMaps',
            'Microsoft.WindowsSoundRecorder',
            'Microsoft.Xbox',
            'Microsoft.Xbox.TCUI',
            'Microsoft.XboxApp',
            'Microsoft.XboxGameOverlay',
            'Microsoft.XboxGamingOverlay',
            'Microsoft.XboxIdentityProvider',
            'Microsoft.XboxSpeechToTextOverlay',
            'Microsoft.ZuneMusic',
            'Microsoft.ZuneVideo',
            'Microsoft.YourPhone'
        )

        foreach($AppName in $RemoveApps)
        {
            # Remove app
            $App = Get-AppxPackage -Name $AppName

            if ($App -and -not $App.NonRemovable -and
               (ShouldProcess @WhatIfSplat -Message "Removing `"$AppName`"." @VerboseSplat))
            {
                $App | Remove-AppxPackage
            }

            # Install app
            #Get-AppxPackage -Name $App -AllUser | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
        }

        #Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
        #Stop-Process -Name "Explorer" -Force -ErrorAction SilentlyContinue
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

    # Remote
    if ($Session)
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Get splat
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $ComputerName = $Using:ComputerName

            $Credential = $Using:Credential
            $Session = $Using:Session

            $EnvDataDrive = $Using:EnvDataDrive
            $EnvDataDrive = $Using:EnvDataDrive
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
# MIIXpgYJKoZIhvcNAQcCoIIXlzCCF5MCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOrdsmwFUZ1XsvHvHTGXfal78
# TBugghI6MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQqJnggIcPpXhlUoRZ/zDIe
# pYN20DANBgkqhkiG9w0BAQEFAASCAgCdvqR0g69NUpYe9Mqjmforp6JKV7M+BtfT
# JZ9wetRtcDPJ25UOKEEgh1fjfJh1fetBDN+amdpDJ8LRgeWqmbJDLxCHhW3FPahR
# 0N5wH+QYDtzzTo8IwJdUUWELwZ7X2PLznMLmKxYn5Jeq/FoFfgzC+b4WBLbjvQeB
# UyuXueVQO7uSFxdOUbYk84irSbdwJ1kwlIQbmnYbbYYLbGdlBOQAjlZYMRGi4P9y
# I9z031AvtDzG8eYw4D3DC0cNnNlHMe4dQC+q4F+I9n7XFRnTbWvtGJx4VJBanOHh
# jlmrvEDrnVGypx5wRchdbyoM3/orswx/zhlq0+xOGCos00iAKuoTE1T7yTrliR89
# +VvN4mB8QwSyavb6GtyfAu7gN9hDMPdiRwO8sctTmt+SYy+xS/p3XAUwvS1dR/hq
# N1yr1oo044gpiblQsFIYCiCjvADTBZLXl0WvSF2jOmD+Q+qB85R5I93Ec+sO1FlT
# T5h6GuOy5r3Kcwetu8tx7Y8yS6LLVo+hrxeHdAS5W+sD2FPblITEi020w1ICOscP
# uxGlp/VsuJTPkSAcsyMNMlBdWByeSkPqGDkh8D9HeUHPG4CJHm5IIVXJa00MQeM8
# eVIgsfqkIYtALWVYFstdsQAaqazxzTr9ovkeUhWgLqKyenUmR/eV0XNtTx6gC4lH
# KJTwaAODsKGCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAxMjA2MDAwMDA0WjAjBgkqhkiG9w0BCQQx
# FgQU8qZ+fz7mcjARoU2aNFEmbYcDeZIwDQYJKoZIhvcNAQEBBQAEggEAj5wp2tKm
# QA5+1fUyT6aLOwdfMOAFavYfw/cIAifWcb4hH0dEDEAsG/Bb6K7K7HUFbotTh53d
# UnF7okaSAqIXpSjxyqPbfTjGOlW7f79K4RlPqdZR3n/qs1kKj5/iewgF4JZHJcOV
# wnucd8AYUQ46JpLoKcD3hZXO65VYTzcay8YGgL92IcGAXi1M2lIUXVfdmY5umIhr
# HI4rbypGYcyY18ztkeUsH2Nu4pEiswQMF55mWmmdzrmYRnY+HnKbVtdecpK9Mjb3
# X43o+QHcOvPVx4msHHwTl5ZWj1L2B9fgyEx+XOVVlzOOKPZv+um/UN5eovMD5OUW
# G6RIftp1v+spsQ==
# SIG # End signature block
