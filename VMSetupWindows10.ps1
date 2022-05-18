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

    $EnvDataDrive = 'E:'
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

        # FIX
        # add array
        # add signing cert

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
    if ($Session)
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

            $EnvDataDrive = $Using:EnvDataDrive
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
# MIIZBgYJKoZIhvcNAQcCoIIY9zCCGPMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHHSJb4m9saFbu3w1LLZVU8rx
# tLOgghKHMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# 8jCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh
# 1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+Feo
# An39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1
# decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxnd
# X7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6
# Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPj
# Q2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlREr
# WHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JM
# q++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh
# 3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8j
# u2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnS
# DmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# dwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAG
# A1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOC
# AgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp
# /GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40B
# IiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2d
# fNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibB
# t94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7
# T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZA
# myEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdB
# eHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnK
# cPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/
# pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yY
# lvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbGMIIErqADAgEC
# AhAKekqInsmZQpAGYzhNhpedMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwMzI5
# MDAwMDAwWhcNMzMwMzE0MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xJDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIy
# IC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALkqliOmXLxf1knw
# FYIY9DPuzFxs4+AlLtIx5DxArvurxON4XX5cNur1JY1Do4HrOGP5PIhp3jzSMFEN
# MQe6Rm7po0tI6IlBfw2y1vmE8Zg+C78KhBJxbKFiJgHTzsNs/aw7ftwqHKm9MMYW
# 2Nq867Lxg9GfzQnFuUFqRUIjQVr4YNNlLD5+Xr2Wp/D8sfT0KM9CeR87x5MHaGjl
# RDRSXw9Q3tRZLER0wDJHGVvimC6P0Mo//8ZnzzyTlU6E6XYYmJkRFMUrDKAz200k
# heiClOEvA+5/hQLJhuHVGBS3BEXz4Di9or16cZjsFef9LuzSmwCKrB2NO4Bo/tBZ
# mCbO4O2ufyguwp7gC0vICNEyu4P6IzzZ/9KMu/dDI9/nw1oFYn5wLOUrsj1j6siu
# gSBrQ4nIfl+wGt0ZvZ90QQqvuY4J03ShL7BUdsGQT5TshmH/2xEvkgMwzjC3iw9d
# RLNDHSNQzZHXL537/M2xwafEDsTvQD4ZOgLUMalpoEn5deGb6GjkagyP6+SxIXuG
# Z1h+fx/oK+QUshbWgaHK2jCQa+5vdcCwNiayCDv/vb5/bBMY38ZtpHlJrYt/YYcF
# aPfUcONCleieu5tLsuK2QT3nr6caKMmtYbCgQRgZTu1Hm2GV7T4LYVrqPnqYklHN
# P8lE54CLKUJy93my3YTqJ+7+fXprAgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMC
# B4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3Mp
# dpovdYxqII+eyG8wHQYDVR0OBBYEFI1kt4kh/lZYRIRhp+pvHDaP3a8NMFoGA1Ud
# HwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUF
# BwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# WAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAA0tI3Sm0fX46kuZPwHk9gzkrxad2bOMl4IpnENvAS2rOLVw
# Eb+EGYs/XeWGT76TOt4qOVo5TtiEWaW8G5iq6Gzv0UhpGThbz4k5HXBw2U7fIyJs
# 1d/2WcuhwupMdsqh3KErlribVakaa33R9QIJT4LWpXOIxJiA3+5JlbezzMWn7g7h
# 7x44ip/vEckxSli23zh8y/pc9+RTv24KfH7X3pjVKWWJD6KcwGX0ASJlx+pedKZb
# NZJQfPQXpodkTz5GiRZjIGvL8nvQNeNKcEiptucdYL0EIhUlcAZyqUQ7aUcR0+7p
# x6A+TxC5MDbk86ppCaiLfmSiZZQR+24y8fW7OK3NwJMR1TJ4Sks3KkzzXNy2hcC7
# cDBVeNaY/lRtf3GpSBp43UZ3Lht6wDOK+EoojBKoc88t+dMj8p4Z4A2UKKDr2xpR
# oJWCjihrpM6ddt6pc6pIallDrl/q+A8GQp3fBmiW/iqgdFtjZt5rLLh4qk1wbfAs
# 8QcVfjW05rUMopml1xVrNQ6F1uAszOAMJLh8UgsemXzvyMjFjFhpr6s94c/MfRWu
# FL+Kcd/Kl7HYR+ocheBFThIcFClYzG/Tf8u+wQ5KbyCcrtlzMlkI5y2SoRoR/jKY
# pl0rl+CL05zMbbUNrkdjOEcXW28T2moQbh9Jt0RbtAgKh1pZBHYRoad3AhMcMYIF
# 6TCCBeUCAQEwJDAQMQ4wDAYDVQQDDAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJ
# BgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAj
# BgkqhkiG9w0BCQQxFgQUO0jknrL//Eb+X0GDzqiPI6ilDW4wDQYJKoZIhvcNAQEB
# BQAEggIAhoTUoBJRaByUo6yu/q/YgxE6HuvQppFl3hFDJQi4gM/YXJ9jRa5jgwu7
# n+WyVNjbYNcp7A4keO8P+kUMKbdzJVbD9jrXjtOQPzckYgEaJipcrssak2pWuZa0
# 1YIU+tW8Uw4CeXTcXGCSxqJgW6tSYim5wg5h6U5N6ToFerlUj8+sR7TDXaZYx3di
# o8GYUVKX34gCR0+LCPaN4hJT/MyXLajFzOda4RrmJAf+YW7Na1JwfhI+KH9zniQg
# QmEGIGQETW5fAut/L2XA+iLXPYrWSuWd3jl9w39FqGFgwNqf8HzmdZ1Cz8KIIkKe
# a8yXDhrxPz+StDkS30SvU9h3uTyF7eWTc8pC7Lihv4daMg+CzvDg8mpNlg3fdZpZ
# yL90hwN14mSmxrmemJ250CiJ0bLhVW62eH1Q99VKItL85XsAstFQemCMtZZ3JlgW
# rFHOyXyzehEZY90afAh1kmUrHj23VSww6XgCqvxCZnKKx7vYGeJKkWB5myJE8O8M
# U/JUIUqkx1u8oKsjjw2oPBAc+Cd149j9EtysVVKIef2w1NZppQhmekPQs7JtMXB7
# OFF3b7IwNvd/nCSR6ctwzkg98Av2do8PR6kBtBUXPZyT8TtPB6GJYtqMcZMwAyWH
# HqlS0CL+F7KyCbG2NY5inVNaKNmSkf2ZIvnvA8duYt7r6/k2hpihggMgMIIDHAYJ
# KoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNB
# NDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0G
# CWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMjIwNTE4MTU0NTM2WjAvBgkqhkiG9w0BCQQxIgQg2w/ai40VdN7Z
# M+FN5/xrK6mE4oTovTM+uXmmcN2LLNswDQYJKoZIhvcNAQEBBQAEggIAWZiClEAb
# ymkA9m+UmYgnYJXm33ICv5fc0545p6r/EHsE/2PnRCN7lDZsbfn7o7W41/XDsTCl
# yiSq1bFmx11dg6nllGOFhAx4Qnhv6YLo8FFhpAK6qR/sXDfH1yMZqcde6c2roWZZ
# p4Zow4FfxrO8YaDAv1fqeJdnaNSPgwLGn7WQDhRbax/A/seLT6rLepqPx14ZqU0I
# d30kxJdDVowvwJoqbjO111HN/Li5ijbuj0tQLkmyyukBjG8grwbjYg0jFQveQIqm
# pQ3Y2e1N/KQ4gHFId/idt8VyWMaYLHPchf5gO1LKiQxqCM9GvpFQtmbDsRs5/+KR
# J3YUMgeHJTMPFY1z6CrAD958mA+16+W1RiHri+ziXBVHckERs9QdH1A/hzeVbBFu
# kBSXNhzNN42fe7j7rO5NZi7d84zqV+4sGKZF93x6i3gS3mPwR6+AuNIDObWkVFjS
# q486Yap2JIO0dYrmmXUlSmTKeGxN2mzPnvmLVyMCRN5v75zq2ARp7RJyh/Sno0Y7
# omog2WqOUbLhA2EkVSvtCDBV0KPlFDzZXOjy9PiG4WqouJka1rfUF6ebNUHw2JYK
# mBKg7wzAgccpde+2ENk8CU4lD+2RGuKbJAvCauZ7PFE+ACp0Acnxi+1phI4Szuqb
# TssiCV2aD3eFlwcl01WuTKTv/Kp6N/MobNM=
# SIG # End signature block
