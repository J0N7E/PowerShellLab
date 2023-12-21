<#
 .DESCRIPTION
    Enter description
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

    $DataDrive = 'E:'
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
            . $PSScriptRoot\f_CheckContinue.ps1
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

        # ███████╗ ██████╗ ██╗     ██████╗ ███████╗██████╗ ███████╗
        # ██╔════╝██╔═══██╗██║     ██╔══██╗██╔════╝██╔══██╗██╔════╝
        # █████╗  ██║   ██║██║     ██║  ██║█████╗  ██████╔╝███████╗
        # ██╔══╝  ██║   ██║██║     ██║  ██║██╔══╝  ██╔══██╗╚════██║
        # ██║     ╚██████╔╝███████╗██████╔╝███████╗██║  ██║███████║
        # ╚═╝      ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝

        $Folders =
        @(
            "$DataDrive\Desktop",
            "$DataDrive\Downloads"
        )

        if (-not (Test-Path -Path $DataDrive\Dropbox))
        {
            $Folders +=
            @(
                "$DataDrive\Documents",
                "$DataDrive\Pictures",
                "$DataDrive\Music"
            )
        }

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
           @{ Name = 'DataDrive';          Value =  $DataDrive },
           @{ Name = 'Desktop';            Value = "$DataDrive\Desktop" },
           @{ Name = 'Downloads';          Value = "$DataDrive\Downloads" },
           @{ Name = 'SendTo';             Value = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name 'SendTo').SendTo },
           @{ Name = 'StartMenu';          Value = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name 'Start Menu').'Start Menu' },
           @{ Name = 'AllUsersStartMenu';  Value = "$env:ProgramData\Microsoft\Windows\Start Menu" }
        )

        if (-not (Test-Path -Path $DataDrive\Dropbox))
        {
            $EnvironmentVariables +=
            @(
               @{ Name = 'Documents';          Value = "$DataDrive\Documents" },
               @{ Name = 'Pictures';           Value = "$DataDrive\Pictures" },
               @{ Name = 'Music';              Value = "$DataDrive\Music" }
            )
        }
        else
        {
            $EnvironmentVariables +=
            @(
               @{ Name = 'Dropbox';            Value = "$DataDrive\Dropbox" },
               @{ Name = 'Documents';          Value = "$DataDrive\Dropbox\Documents" },
               @{ Name = 'Pictures';           Value = "$DataDrive\Dropbox\Pictures" },
               @{ Name = 'Music';              Value = "$DataDrive\Dropbox\Music" },
               @{ Name = 'OPENSSL_CONF';       Value = "$DataDrive\Dropbox\BAT\bin\openssl\bin\openssl.cfg" }
            )
        }

        foreach ($Var in $EnvironmentVariables)
        {
            if (Test-Path -Path $Var.Value)
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
            else
            {
                Write-Warning -Message "Skipping `"$($Var.Value)`", path dont exist."
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
            @{ Name = 'Desktop';                                 Value = "$DataDrive\Desktop";            PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = '{374DE290-123F-4565-9164-39C4925E467B}';  Value = "$DataDrive\Downloads";          PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
            @{ Name = '{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}';  Value = "$DataDrive\Downloads";          PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' }
        )

        if (-not (Test-Path -Path $DataDrive\Dropbox))
        {
            $ShellFolders +=
            @(
                @{ Name = 'Personal';                                Value = "$DataDrive\Documents";  PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = '{F42EE2D3-909F-4907-8871-4C22FC0BF756}';  Value = "$DataDrive\Documents";  PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = 'My Pictures';                             Value = "$DataDrive\Pictures";   PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = '{0DDD015D-B06C-45D5-8C4C-F59713854639}';  Value = "$DataDrive\Pictures";   PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = 'My Music';                                Value = "$DataDrive\Music";      PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = '{A0C69A99-21C8-4671-8703-7934162FCF1D}';  Value = "$DataDrive\Music";      PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' }
            )
        }
        else
        {
            $ShellFolders +=
            @(
                @{ Name = 'Personal';                                Value = "$DataDrive\Dropbox\Documents";  PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = '{F42EE2D3-909F-4907-8871-4C22FC0BF756}';  Value = "$DataDrive\Dropbox\Documents";  PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = 'My Pictures';                             Value = "$DataDrive\Dropbox\Pictures";   PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = '{0DDD015D-B06C-45D5-8C4C-F59713854639}';  Value = "$DataDrive\Dropbox\Pictures";   PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = 'My Music';                                Value = "$DataDrive\Dropbox\Music";      PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
                @{ Name = '{A0C69A99-21C8-4671-8703-7934162FCF1D}';  Value = "$DataDrive\Dropbox\Music";      PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' }
            )
        }

        foreach ($Folder in $ShellFolders)
        {
            if (Test-Path -Path $Folder.Value)
            {
                Set-Registry -Settings $ShellFolders
            }
            else
            {
                Write-Warning -Message "Skipping `"$($Folder.Value)`", path dont exist."
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
            @{ FriendlyName = 'Turn off display after';    Value = '0x0000012c';  Type = 'AC';  SubgroupSetting = "7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" }
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
                $ValueDec = [Convert]::ToInt64($Setting.Value, 16)

                if ($Setting.Value -ne (Invoke-Expression -Command "cmd /c 'powercfg -query $Scheme $($Setting.SubgroupSetting)'" | Where-Object {
                                            $_ -match "Current $($Setting.Type.ToUpper()) Power Setting Index: (.*)$"
                                        } | ForEach-Object { "$($Matches[1])" }) -and
                   (ShouldProcess @WhatIfSplat -Message "Setting `"$($Setting.FriendlyName)`" $($Setting.Type) to `"$ValueDec`"" @VerboseSplat))
                {
                    Invoke-Expression -Command "cmd /c 'powercfg -set$($Setting.Type.ToLower())valueindex $Scheme $($Setting.SubgroupSetting) $ValueDec' 2>&1" > $null
                }
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

        Set-Registry -Settings @(

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

            # Hide chat button
            @{ Name = 'TaskbarMn';              Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Hide widgets button
            @{ Name = 'TaskbarDa';              Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Hide search icon
            @{ Name = 'SearchboxTaskbarMode';   Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search' },

            # Show taskbar buttons where window is open
            @{ Name = 'MMTaskbarMode';          Value = 2;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Use dark theme
            @{ Name = 'SystemUsesLightTheme';   Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' },
            @{ Name = 'AppsUseLightTheme';      Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' },

            # Set accent color
            @{ Name = 'AccentColor';            Value = 0xff484a4c;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' },
            @{ Name = 'ColorizationColor';      Value = 0xc44c4a48;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' },
            @{ Name = 'ColorizationAfterglow';  Value = 0xc44c4a48;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' }
        )

        # Clear recent
        if ((Get-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*") -and
            (ShouldProcess @WhatIfSplat -Message "Clearing recent." @VerboseSplat))
        {
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse
        }

        # Stop explorer
        Stop-Process -Name "Explorer" -Force -ErrorAction SilentlyContinue
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

    # Initialize
    $InvokeSplat = @{}

    # Setup remote
    if ($Session -and $Session.State -eq 'Opened')
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetRegistry.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            $DataDrive = $Using:DataDrive
        }

        # Set remote splat
        $InvokeSplat.Add('Session', $Session)
    }
    else # Setup locally
    {
        Check-Continue -Message "Invoke locally?"

        # Load functions
        Invoke-Command -ScriptBlock `
        {
            try
            {
                . $PSScriptRoot\f_ShouldProcess.ps1
                . $PSScriptRoot\f_SetRegistry.ps1
            }
            catch [Exception]
            {
                throw $_
            }

        } -NoNewScope

        # Set local splat
        $InvokeSplat.Add('NoNewScope', $true)
    }

    # Invoke
    try
    {
        # Run main
        Invoke-Command @InvokeSplat -ScriptBlock $MainScriptBlock -ErrorAction Stop
    }
    catch [Exception]
    {
        throw "$_ $( $_.ScriptStackTrace)"
    }
}

End
{
}

# SIG # Begin signature block
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvc8p6TKvWU+cBQLyrJJ5+V2+
# abagghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQrZlPy
# uBuUWVaKV7Qbr6llaGMLGzANBgkqhkiG9w0BAQEFAASCAgBMO4/QoKISBSTFH8Qi
# paDM9asp/shiwpmnVg6TQaYFBe3M8KCbmYCzpuvpMza1xUVCNdCoWhZQwRt2s4cX
# rki5O93k6WwNtDqcnZYqIWQwR5EWn9zfT08FmeoPo3pVdugCQ3zih2H0eRoNAR+O
# ZE2Kkc1HFSn7r2M0S0N5B2WVALjTpMORouL/6WBN9dHRavHyzpi9+HCKheyGDtdL
# c5LPWGtOJw/4kji+oGksZPg9ZqsHs8nqwwX0ma0zZ9lfP9pSlh7CAqidddJVMzEA
# B37e8GQDTOvAKd0LR+jBadTOyxaG8i81pPCmJltN1v7ZqaCUEkQZ7l9MBOFhFJ7u
# IieYTBrLue2S8nSayTTE6X+wovXUndMeA3KUpDPJvfV/YvuYLAihYjaP2OViPI7x
# togfDkyE/GYvOc9eC73JkXG575Clq2BXz5IE5COpa1qrv8QvidTwuWtlTGvKZh87
# igf/Up3lYPheYqN4rKDbe5MaYGU3M+Ad+19y291MIKi27RzRNWJkhSns4y5sVpui
# MhKIigOO1xZgeJHa4yNIFWycz89rNje/B/Hp/z1b605tCIGZVeoA/TS85qCOIQtv
# mahAtENbE1okjeO4SjMM64NzXfzi7zuz72jiGlT5yTRCxgNpx4mgFliuwxHrQptr
# tWRsWNRkr3RkzgbOLBh+97aXuaGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzEyMjExNjAw
# MDBaMC8GCSqGSIb3DQEJBDEiBCBLCuVH1qNoQ7JHRKIvJXqFpVPKoKNr95GG0Vds
# r6ZBgzANBgkqhkiG9w0BAQEFAASCAgCGeC2la+GP2xRi4CS0QVxqP/zk+9+PodBV
# krpmQA8D/lLsTyybYgnkOkjA/rWZDjsMjZnyZzyAqcqQbxdb5o30oQ38ZqnArQTM
# vv2yqvSsHTrwMb/+J7m4wSwMahWc7xhxo90Hjz/AmHu13WL0orqTYA4lqozgFHw/
# mrc/38fVT7wfKERfc7zzsrucYUkDa+keBFPoOi5K0HuBmTSFD7HVXVu/hFtPOWwn
# O5EA/2nECaeg7nsNTQ5krt6T/cpL/tYGVo5Rdh+ZIR9+1ZRAIlmT+lWLejW1e6ap
# fzUkYk2YIasUS5CZ2yYcwEMytXCtCQjE4Z8UAODK7VN51HnAz/c1L0Dn0fhyvpVe
# 1lFpbq/WAJ28F+SE6p4Tjl6/t+i5fKZk+RWHMXBMkFEDCG0IteQBqVFyVpUJdAXJ
# yDw1n2/HIn41IUpAfc8+RcrMuPugwDugBARo4YuiOCjgaDVco3czWySX1OUZ+flk
# KXBpdc96zj7oncorMJF6LgxRjI6GkqGjsLd/cyN8OrPEnF9X7srqYTqyzzSooUOO
# jv41pHGjohMfCTBkj+WAi2L8iMJgequ6UY6kj8YQmQbT2QsiVK14mtWHjCiNbs+f
# k5SM637HOwcA36uVq/GLjLTiW5GSPgyEz0v6oGxx2NJ5368dUXUDdbasIdUywKn4
# 9qXu29rvgA==
# SIG # End signature block
