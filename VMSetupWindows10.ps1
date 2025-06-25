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

    $DataDrive = 'M:'
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
            "C:\Desktop",
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
           @{ Name = 'Desktop';            Value = "C:\Desktop" },
           @{ Name = 'DataDrive';          Value =  $DataDrive },
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
            @{ Name = 'Desktop';                                 Value = "C:\Desktop";                    PropertyType = 'ExpandString';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' },
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
                Set-Registry -Settings $ShellFolders > $null
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
                $UserPaths += $Dir.FullName
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
            @{ FriendlyName = 'Turn off display after';    Value = '0x00000258';  Type = 'AC';  SubgroupSetting = "7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" }
            @{ FriendlyName = 'Lid close action';          Value = '0x00000000';  Type = 'AC';  SubgroupSetting = "4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936" }, # 0 = None
            @{ FriendlyName = 'Lid close action';          Value = '0x00000000';  Type = 'DC';  SubgroupSetting = "4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936" }, # 0 = None
            @{ FriendlyName = 'Power button action';       Value = '0x00000003';  Type = 'AC';  SubgroupSetting = "4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280" }, # 3 = Shut down
            @{ FriendlyName = 'Power button action';       Value = '0x00000003';  Type = 'DC';  SubgroupSetting = "4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280" }  # 3 = Shut down
        )

        # Itterate scheme
        foreach ($Scheme in (Invoke-Expression -Command 'powercfg -list' | Where-Object { $_ -match "([a-z0-9-]{36})" } | ForEach-Object { $Matches[1] }))
        {
            foreach ($Setting in $PowerSetting)
            {
                $OldValue = Invoke-Expression -Command "cmd /c 'powercfg -query $Scheme $($Setting.SubgroupSetting)'" | Where-Object {
                                $_ -match "Current $($Setting.Type.ToUpper()) Power Setting Index: (.*)$"
                            } | ForEach-Object { "$($Matches[1])" }

                if ($OldValue)
                {
                    $NewValueDec = [Convert]::ToInt64($Setting.Value, 16)

                    if ($Setting.Value -ne $OldValue -and
                       (ShouldProcess @WhatIfSplat -Message "Setting `"$($Setting.FriendlyName)`" $($Setting.Type) to `"$NewValueDec`"" @VerboseSplat))
                    {
                        Invoke-Expression -Command "cmd /c 'powercfg -set$($Setting.Type.ToLower())valueindex $Scheme $($Setting.SubgroupSetting) $NewValueDec' 2>&1" > $null
                    }
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
        # FIX Not neccessary?
        <#        if ((Get-Culture).Name -ne 'sv-SE' -and
            (ShouldProcess @WhatIfSplat -Message "Setting culture to sv-SE" @VerboseSplat))
        {
            Set-Culture -CultureInfo sv-SE
        }
        #>

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

        # ██████╗ ███████╗ ██████╗ ██╗███████╗████████╗██████╗ ██╗   ██╗
        # ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝
        # ██████╔╝█████╗  ██║  ███╗██║███████╗   ██║   ██████╔╝ ╚████╔╝
        # ██╔══██╗██╔══╝  ██║   ██║██║╚════██║   ██║   ██╔══██╗  ╚██╔╝
        # ██║  ██║███████╗╚██████╔╝██║███████║   ██║   ██║  ██║   ██║
        # ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝

        $AccentPalette = [byte[]](0x9b,0x9a,0x99,0x00,0x84,0x83,0x81,0x00,0x6d,0x6b,0x6a,0x00,0x4c,0x4a,0x48,0x00,0x36,0x35,0x33,0x00,0x26,0x25,0x24,0x00,0x19,0x19,0x19,0x00,0x10,0x7c,0x10,0x00)

        ###########
        # Display
        # Settings
        ###########

        $Result = Set-Registry -Settings @(

            ###########
            # Explorer
            ###########

            # Hide recently used files in quick access
            @{ Name = 'ShowRecent';             Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer' },

            # Hide frequently used folders in quick access
            @{ Name = 'ShowFrequent';           Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer' },

            # Hide files from Office.com in quick access
            @{ Name = 'ShowCloudFilesInQuickAccess';  Value = 0;     PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer' },

            # Hide recently opened items in Jump Lists
            @{ Name = 'Start_TrackDocs';        Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Open file explorer to this pc
            @{ Name = 'LaunchTo';               Value = 1;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Show hidden files
            @{ Name = 'Hidden';                 Value = 1;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Show file extensions
            @{ Name = 'HideFileExt';            Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            ########
            # Start
            ########

            # Disable recently added
            @{ Name = 'ShowRecentList';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start' }

            # Disable most used
            @{ Name = 'ShowFrequentList';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start' }

            # Disable recommendations
            @{ Name = 'Start_IrisRecommendations';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' }

            #########
            # Search
            #########

            # Disable safe search
            @{ Name = 'SafeSearchMode';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings' }

            # Disable search ms account
            @{ Name = 'IsMSACloudSearchEnabled';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings' }

            # Disable search work/school account
            @{ Name = 'IsAADCloudSearchEnabled';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings' }

            # Disable search history
            @{ Name = 'IsDeviceSearchHistoryEnabled';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings' }

            # Disable app search
            @{ Name = 'IsGlobalWebSearchProviderToggleEnabled';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings' }

            # Disable bing search
            @{ Name = 'Microsoft.BingSearch_8wekyb3d8bbwe!App';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchProviders' }

            ##########
            # Taskbar
            ##########

            # Hide task view button
            @{ Name = 'ShowTaskViewButton';     Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Hide search icon
            @{ Name = 'SearchboxTaskbarMode';   Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search' },

            # Hide chat button
            @{ Name = 'TaskbarMn';              Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Taskbar left
            @{ Name = 'TaskbarAl';              Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Show taskbar buttons where window is open
            @{ Name = 'MMTaskbarMode';          Value = 2;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            ##########
            # Windows
            ##########

            # Disable snap assist
            @{ Name = 'SnapAssist';             Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Disable snap bar
            @{ Name = 'EnableSnapBar';          Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Disable edge snap
            @{ Name = 'DITest';                 Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Disable snap flyout
            @{ Name = 'EnableSnapAssistFlyout'; Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' },

            # Use dark theme
            @{ Name = 'SystemUsesLightTheme';   Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' },
            @{ Name = 'AppsUseLightTheme';      Value = 0;           PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' },

            # Set accent color
            @{ Name = 'AccentPalette';          Value = $AccentPalette; PropertyType = 'Binary';  Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' },
            @{ Name = 'StartColorMenu';         Value = 0xff333536;     PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' },
            @{ Name = 'AccentColorMenu';        Value = 0xff484a4c;     PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' },

            # Set accent color
            @{ Name = 'AccentColor';            Value = 0xff484a4c;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' },
            @{ Name = 'ColorizationColor';      Value = 0xc44c4a48;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' },
            @{ Name = 'ColorizationAfterglow';  Value = 0xc44c4a48;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM' }

            #######
            # Misc
            #######

            # Set nosounds scheme
            @{ Name = '';                       Value = '.None';     PropertyType = 'String';  Path = 'HKEY_CURRENT_USER\AppEvents\Schemes' },

            # Disable accessibility keys
            @{ Name = 'Flags';                  Value = 122;         PropertyType = 'String';  Path = 'HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response' },
            @{ Name = 'Flags';                  Value = 506;         PropertyType = 'String';  Path = 'HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys' },
            @{ Name = 'Flags';                  Value = 58;          PropertyType = 'String';  Path = 'HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys' },

            # Disable prtscr open snipp
            @{ Name = 'PrintScreenKeyForSnippingEnabled';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Control Panel\Keyboard' }

            # Disable game bar
            @{ Name = 'UseNexusForGameBarEnabled';  Value = 0;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Software\Microsoft\GameBar' }

            # Powershell black background
            @{ Name = 'ScreenColors';  Value = 6;  PropertyType = 'DWord';   Path = 'HKEY_CURRENT_USER\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' }

            # Check for publisher's certificate revocation
            #HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\State to 0x00023e00

        )

        if ($Result)
        {
            # Stop explorer
            Stop-Process -Name "Explorer" -Force -ErrorAction SilentlyContinue
        }

        ###########
        # Computer
        # Settings
        ###########

        if ($Admin)
        {
            $InterfaceGuid = Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.NextHop -ne '0.0.0.0' } | Get-NetAdapter | Select-Object -ExpandProperty InterfaceGuid

            Set-Registry -Settings @(

                # Disable metadata signing
                @{ Name = 'PreventDeviceMetadataFromNetwork';  Value = '1';  PropertyType = 'DWord';  Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata' }

                # Enable pin sign-in
                @{ Name = 'AllowDomainPINLogon';  Value = '1';  PropertyType = 'DWord';  Path = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' }

            ) > $null
        }

        # ████████╗ █████╗ ███████╗██╗  ██╗███████╗
        # ╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝██╔════╝
        #    ██║   ███████║███████╗█████╔╝ ███████╗
        #    ██║   ██╔══██║╚════██║██╔═██╗ ╚════██║
        #    ██║   ██║  ██║███████║██║  ██╗███████║
        #    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝

        if ($Admin)
        {
            $Tasks =
            @(
                'Automatic-Device-Join'
                'Cellular'
                'Consolidator'
                'CreateObjectTask'
                'DmClient'
                'DmClientOnScenarioDownload'
                'FODCleanupTask'
                'MapsToastTask'
                'MapsUpdateTask'
                'Microsoft Compatibility Appraiser'
                'Microsoft-Windows-DiskDiagnosticDataCollector'
                'MNO Metadata Parser'
                'MobilityManager'
                'Notifications'
                'QueueReporting'
                'RemoteAssistanceTask'
                'Scheduled'
                'ScheduledDefrag'
                'SilentCleanup'
                'SpeechModelDownloadTask'
                'StartComponentCleanup'
                'StartupAppTask'
                'UpdateLibrary'
                'UsbCeip'
                'WindowsActionDialog'
                'XblGameSaveTask'
            )

            foreach ($Task in @())
            {
                $ScheduledTask = Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue

                if ($ScheduledTask -and $ScheduledTask.State -ne 'Disabled' -and
                   (ShouldProcess @WhatIfSplat -Message "Disabling Scheduled Task `"$Task`"" @VerboseSplat))
                {
                    $ScheduledTask | Disable-ScheduledTask > $null
                }
            }
        }

        # ███████╗███████╗██████╗ ██╗   ██╗██╗ ██████╗███████╗███████╗
        # ██╔════╝██╔════╝██╔══██╗██║   ██║██║██╔════╝██╔════╝██╔════╝
        # ███████╗█████╗  ██████╔╝██║   ██║██║██║     █████╗  ███████╗
        # ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║██║     ██╔══╝  ╚════██║
        # ███████║███████╗██║  ██║ ╚████╔╝ ██║╚██████╗███████╗███████║
        # ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝╚══════╝

        $Services =
        @(
            # Automatic
            @{ Name = 'LanmanWorkstation'; StartType = 'Automatic'; }

            # Manual
            @{ Name = 'CertPropSvc'; StartType = 'Manual'; }
            @{ Name = 'CscService'; StartType = 'Manual'; }
            @{ Name = 'DispBrokerDesktopSvc'; StartType = 'Manual'; }
            @{ Name = 'DPS'; StartType = 'Manual'; }
            @{ Name = 'LanmanServer'; StartType = 'Manual'; }
            @{ Name = 'RasAuto'; StartType = 'Manual'; }
            @{ Name = 'RasMan'; StartType = 'Manual'; }
            @{ Name = 'RemoteRegistry'; StartType = 'Manual'; }
            @{ Name = 'RpcLocator'; StartType = 'Manual'; }
            @{ Name = 'Spooler'; StartType = 'Manual'; }
            @{ Name = 'SCardSvr'; StartType = 'Manual'; }
            @{ Name = 'ScDeviceEnum'; StartType = 'Manual'; }
            @{ Name = 'SCPolicySvc'; StartType = 'Manual'; }
            @{ Name = 'SENS'; StartType = 'Manual'; }
            @{ Name = 'SessionEnv'; StartType = 'Manual'; }
            @{ Name = 'TermService'; StartType = 'Manual'; }
            @{ Name = 'uhssvc'; StartType = 'Manual'; }
            @{ Name = 'UmRdpService'; StartType = 'Manual'; }
            @{ Name = 'WbioSrvc'; StartType = 'Manual'; }
            @{ Name = 'XblAuthManager'; StartType = 'Manual'; }
            @{ Name = 'XblGameSave'; StartType = 'Manual'; }
            @{ Name = 'XboxGipSvc'; StartType = 'Manual'; }
            @{ Name = 'XboxNetApiSvc'; StartType = 'Manual'; }

            # Disable
            @{ Name = 'AdobeARMservice'; StartType = 'Disabled'; }
            @{ Name = 'ALG'; StartType = 'Disabled'; }
            @{ Name = 'fdPHost'; StartType = 'Disabled'; }
            @{ Name = 'FDResPub'; StartType = 'Disabled'; }
            @{ Name = 'iphlpsvc'; StartType = 'Disabled'; }
            @{ Name = 'lmhosts'; StartType = 'Disabled'; }
            @{ Name = 'MapsBroker'; StartType = 'Disabled'; }
            @{ Name = 'NcdAutoSetup'; StartType = 'Disabled'; }
            @{ Name = 'SDRSVC'; StartType = 'Disabled'; }
            @{ Name = 'SSDPSRV'; StartType = 'Disabled'; }
            @{ Name = 'upnphost'; StartType = 'Disabled'; }
            @{ Name = 'WinRM'; StartType = 'Disabled'; }


<#
            @{ Name = 'AJRouter'; StartType = 'Disabled'; }
            @{ Name = 'BcastDVRUserService_*'; StartType = 'Disabled'; }
            @{ Name = 'diagnosticshub.standardcollector.service'; StartType = 'Disabled'; }
            @{ Name = 'diagsvc'; StartType = 'Disabled'; }
            @{ Name = 'DiagTrack'; StartType = 'Disabled'; }
            @{ Name = 'EFS'; StartType = 'Disabled'; }
            @{ Name = 'EntAppSvc'; StartType = 'Disabled'; }
            @{ Name = 'fhsvc'; StartType = 'Disabled'; }
            @{ Name = 'FrameServer'; StartType = 'Disabled'; }
            @{ Name = 'icssvc'; StartType = 'Disabled'; }
            @{ Name = 'lfsvc'; StartType = 'Disabled'; }
            @{ Name = 'LxpSvc'; StartType = 'Disabled'; }
            @{ Name = 'MSiSCSI'; StartType = 'Disabled'; }
            @{ Name = 'Netlogon'; StartType = 'Disabled'; }
            @{ Name = 'PeerDistSvc'; StartType = 'Disabled'; }
            @{ Name = 'PhoneSvc'; StartType = 'Disabled'; }
            @{ Name = 'PushToInstall'; StartType = 'Disabled'; }
            @{ Name = 'RemoteAccess'; StartType = 'Disabled'; }
            @{ Name = 'RetailDemo'; StartType = 'Disabled'; }
            @{ Name = 'SEMgrSvc'; StartType = 'Disabled'; }
            @{ Name = 'SensorDataService'; StartType = 'Disabled'; }
            @{ Name = 'SensorService'; StartType = 'Disabled'; }
            @{ Name = 'SensrSvc'; StartType = 'Disabled'; }
            @{ Name = 'shpamsvc'; StartType = 'Disabled'; }
            @{ Name = 'swprv'; StartType = 'Disabled'; }
            @{ Name = 'TapiSrv'; StartType = 'Disabled'; }
            @{ Name = 'VSS'; StartType = 'Disabled'; }
            @{ Name = 'WalletService'; StartType = 'Disabled'; }
            @{ Name = 'WdiServiceHost'; StartType = 'Disabled'; }
            @{ Name = 'WdiSystemHost'; StartType = 'Disabled'; }
            @{ Name = 'Wecsvc'; StartType = 'Disabled'; }
            @{ Name = 'WerSvc'; StartType = 'Disabled'; }
            @{ Name = 'wisvc'; StartType = 'Disabled'; }
            @{ Name = 'wlidsvc'; StartType = 'Disabled'; }
            @{ Name = 'WMPNetworkSvc'; StartType = 'Disabled'; }
            @{ Name = 'WpcMonSvc'; StartType = 'Disabled'; }
#>
        )

        foreach ($Service in @())
        {
            $SrvObj = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue

            if ($SrvObj -and $SrvObj.StartType -ne $Service.StartType -and
               (ShouldProcess @WhatIfSplat -Message "Setting [Status=$($Service.StartType)] -> `"$($SrvObj.DisplayName)`" ($($SrvObj.Name))" @VerboseSplat))
            {
                $SrvObj | Set-Service -StartupType $Service.StartType
            }
        }

        # ███╗   ███╗██╗███████╗ ██████╗
        # ████╗ ████║██║██╔════╝██╔════╝
        # ██╔████╔██║██║███████╗██║
        # ██║╚██╔╝██║██║╚════██║██║
        # ██║ ╚═╝ ██║██║███████║╚██████╗
        # ╚═╝     ╚═╝╚═╝╚══════╝ ╚═════╝

        if ($Admin)
        {
            # Install Hyper-V
            if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State -ne 'Enabled' -and
                (ShouldProcess @WhatIfSplat -Message "Adding Hyper-V." @VerboseSplat))
            {
                Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart > $null
            }
        }

        <#
        # Clear recent
        if ((Get-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*") -and
            (ShouldProcess @WhatIfSplat -Message "Clearing recent." @VerboseSplat))
        {
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse
        }
        #>
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
# MIIesgYJKoZIhvcNAQcCoIIeozCCHp8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCLno+H0jvGQAqs
# nJlXkRnujZ5DPN7jtV5XW0JhM48sKaCCGA4wggUHMIIC76ADAgECAhB0XMs0val9
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
# BgkqhkiG9w0BCQQxIgQgqyrK35Uo3NqnxzsHI3MLL37guPq0o+VAvs8+f1LzO6Ew
# DQYJKoZIhvcNAQEBBQAEggIAv0qKQ+/Dre3F2DCWhW6sJqJDDTQ/oPTyRFtQDzlO
# Kb47NhHWqYq6kPL+ENyy+rFkMhuNcGbfJ6xo2RjSUtG4NBWUIDBKWqer4HrV0NCI
# HlZaSc8Wd/nAvSrHYtxAnNdg8afpbzJ/b4PP8HSWuZmLmZbHUXpYIiqNKL0ZHTjQ
# FJEyU0pLNs8Aif8zqdx5v4W9kC74i4bHW8OHXIZu+khvSr9FJMPgyNkNI7Ybw+Yi
# lnkGUQkf5qmo6UFKpeZwMDq5sF91nQfV+eOKQ9h4230tattlfsyLOprC8ZSoqjkw
# vOvXszFl+szqIZYkp+WQT00TaI7asZp+1TqlMVAgqGheEt2iCLX/EwVg+45rhpIe
# bHlWXzFTjekaIUzh8+ISoFz7zeRUi7MbIwmw2R2/KG+C0YtSQa2e7oxKh3PyA+08
# T4B/R78gu4EUMEXDQWqRIhbgZ+whcJu6I5B/hqofplkMG/xVFxV2WSqG9O7A92l0
# KU0voPs36GUrE2WeiI8eAqVr+5gs+sTxNIojCPWzsfL1WESoI4hMC0CKPz4XHEA5
# 1qwG2rRa/ijxNU6HgSLgsjAkSrRL4Aam+/1eva2BgsrO4GYElPVp1+a8a1kLdwgU
# YYPflmx1PoVpQzsPe7wBPQZVjaGFgfMSCvYoCcPN9cTy6f+KfZJ/5f63DvvgO0F2
# ZuahggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhALrma8Wrp/
# lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwNjI1MDAxNjE4WjAvBgkqhkiG9w0BCQQx
# IgQgbQ5AQRhIn40U4FlY2qewEX81jWOXOqfb+KY1Ycje5YgwDQYJKoZIhvcNAQEB
# BQAEggIAieFMOLJiH6lZSJV1Ryv7IjV/GF6NgvDFZRopRdBVmGqL3ZhU7c/R+VrB
# kVxtLb080RvNmJpgC7Fv/5zQpmvcCEkCxevBSVyBdzTpxegMvrT+A8wwUCjX5nbS
# 79USUw47mdtRM/MKQX+l4NpcuS62hY+hirjX2a0A8F+aNHum26CpMsV8DH24TfJh
# nNNkG+6k3VZaVdLLvRzKDGc5CpY9Pd+R5TiYWRD8eRg1s3z0+cEdN1xMGXfPvSHo
# cav7rV3jfnkHfWAP1UGAmHVWEEYfxL3CRtRglf2g+OOihhxVpSzdjFRQDbjePFQX
# L6P/EC05zBeKaWIDcw1zzT1FlQKLcRZ51hV0WQAJ+fPsaEiIlqY5dJJcq8NehIm+
# nQYCIm8GvV0qxE2O59n9QBBkQZjl1NFnk4J9Y8S4onN/9kikhAbOAWiancflTn6t
# ZYh68+ACgFzDCB09WefBVjioMj8WJouz9cAsW9ug4r6pdvVAIm+0MFFYkZ3w6BQv
# 49lkQ78UMNViM/QJOsrNmf+bSk1lHPEb1R7iVHi9obZsQBkMGT3li87sBJSuC0ix
# CU/zWDV7LHPSA7Hzj15UFA62ULW8eV9BD0ZsUsImDfyMK23VruGjBjwDKT2pBi7U
# 6FswyxRXNVH6WbFblog57hEs3YXyQYFp0Nm5uyhcW5aEOPePJGI=
# SIG # End signature block
