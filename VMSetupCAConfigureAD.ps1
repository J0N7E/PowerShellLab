<#
 .DESCRIPTION
    Setup and configure Certificate Authority server AD objects
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

    [Parameter(Mandatory=$true)]
    [ValidateSet('StandaloneRootCA', 'EnterpriseRootCA', 'EnterpriseSubordinateCA')]
    [String]$CAType,

    # Certificate Authority common name
    [Parameter(Mandatory=$true)]
    [String]$CACommonName,

    [Parameter(Mandatory=$true)]
    [String]$CAServerName,

    [Switch]$AddCrl,
    [Switch]$RemoveOld
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

    ############
    # Get files
    ############

    # Initialize
    $CAFiles = @{}

    # Itterate all ca files
    foreach($file in (Get-Item -Path "$PSScriptRoot\$CACommonName*"))
    {
        if ($file.Name -notmatch 'Response' -and
            $file.Name -notmatch '.req')
        {
            # Get file content
            $CAFiles.Add($file, (Get-Content -Path $file.FullName -Raw))
        }
    }

    # Check crt
    if (-not $CAFiles.GetEnumerator().Where({$_.Key -match '.crt'}))
    {
        throw "Can't find `"$CACommonName`" crt, aborting..."
    }

    # Check crl
    if ($AddCrl.IsPresent -and -not $CAFiles.GetEnumerator().Where({$_.Key -match '.crl'}))
    {
        throw "Can't find `"$CACommonName`" crl, aborting..."
    }

    # ███╗   ███╗ █████╗ ██╗███╗   ██╗
    # ████╗ ████║██╔══██╗██║████╗  ██║
    # ██╔████╔██║███████║██║██╔██╗ ██║
    # ██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    # ██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    # ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

    $MainScriptBlock =
    {
        ##################
        # Get domain info
        ##################

        $BaseDN = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
        $DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain
        $DomainNetbiosName = Get-CimInstance -ClassName Win32_NTDomain | Select-Object -ExpandProperty DomainName

        $AccessRight = @{}
        Get-ADObject -SearchBase "CN=Configuration,$BaseDN" -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName, rightsGuid | ForEach-Object { $AccessRight.Add($_.displayName, [System.GUID] $_.rightsGuid) }

        $SchemaID = @{}
        Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$BaseDN" -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName, schemaIDGUID | ForEach-Object { $SchemaID.Add($_.lDAPDisplayName, [System.GUID] $_.schemaIDGUID) }

        #######
        # Save
        #######

        # Create temp Directory
        New-Item -ItemType Directory -Path "$env:TEMP" -Name $CACommonName -Force > $null

        # Itterate all file
        foreach($file in $CAFiles.GetEnumerator())
        {
            # Save file to temp
            Set-Content -Path "$env:TEMP\$CACommonName\$($file.Key.Name)" -Value $file.Value -Force
        }

        # ██████╗ ██╗   ██╗██████╗ ██╗     ██╗███████╗██╗  ██╗
        # ██╔══██╗██║   ██║██╔══██╗██║     ██║██╔════╝██║  ██║
        # ██████╔╝██║   ██║██████╔╝██║     ██║███████╗███████║
        # ██╔═══╝ ██║   ██║██╔══██╗██║     ██║╚════██║██╔══██║
        # ██║     ╚██████╔╝██████╔╝███████╗██║███████║██║  ██║
        # ╚═╝      ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝

        #############
        # Get hashes
        #############

        # Get hashes from AIA container
        $DSAIAHashArray = TryCatch {

            certutil -store "ldap:///CN=$CACommonName,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?cACertificate?base?objectClass=certificationAuthority" "`"$CACommonName`""

        } -ErrorAction SilentlyContinue | Where-Object {
            $_ -match "Cert Hash\(sha1\): (.*)$"
        } | ForEach-Object { "$($Matches[1])" }

        $DSCrossHashArray = TryCatch {

            certutil -store "ldap:///CN=$CACommonName,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?crossCertificatePair?base?objectClass=certificationAuthority" "`"$CACommonName`""

        } -ErrorAction SilentlyContinue | Where-Object {
            $_ -match "Cert Hash\(sha1\): (.*)$"
        } | ForEach-Object { "$($Matches[1])" }

        # Get hashes from CDP container
        $DSCDPHashArray = TryCatch {

            certutil -store "ldap:///CN=$CAServerName,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?*?sub?objectClass=cRLDistributionPoint" "`"$CACommonName`""

        } -ErrorAction SilentlyContinue | Where-Object {
            $_ -match "CRL Hash\(sha1\): (.*)$"
        } | ForEach-Object { "$($Matches[1])" }

        if ($CAType -match 'Root')
        {
            # Get hashes from CA container
            $DSCAHashArray = TryCatch {

                certutil -store "ldap:///CN=$CACommonName,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?cACertificate?base?objectClass=certificationAuthority" "`"$CACommonName`""

            } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "Cert Hash\(sha1\): (.*)$"
            } | ForEach-Object { "$($Matches[1])" }
        }

        if ($CAType -match 'Enterprise')
        {
            # Get hashes from NTAuth container
            $DSNTAuthHashArray = TryCatch {

                certutil -store "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?cACertificate?base?objectClass=certificationAuthority" "`"$CACommonName`""

            } -ErrorAction SilentlyContinue | Where-Object {
                $_ -match "Cert Hash\(sha1\): (.*)$"
            } | ForEach-Object { "$($Matches[1])" }
        }

        ######
        # Add
        ######

        # Initialize arrays
        $CAFileCertificateHashArray = @()
        $CAFileCrlHashArray = @()

        # Itterate all files under certenroll
        foreach($file in (Get-Item -Path "$env:TEMP\$CACommonName\*"))
        {
            switch($file.Extension)
            {
                '.crt'
                {
                    # Get CA certificate hash
                    $CACertificateHash = TryCatch { certutil -dump "`"$($file.FullName)`"" } -ErrorAction SilentlyContinue | Where-Object {
                        $_ -match "Cert Hash\(sha1\): (.*)"
                    } | ForEach-Object { "$($Matches[1])" }

                    # Add cert hash to array
                    $CAFileCertificateHashArray += $CACertificateHash

                    # Check if cross ca certificate
                    if ($file.Name -match "\(\d-\d\)")
                    {
                        ########
                        # Cross
                        ########

                        # Check if certificate hash is in cross hashes
                        if ($CACertificateHash -notin $DSCrossHashArray -and
                            (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Name)`" ($CACertificateHash) to CrossCA container." @VerboseSplat))
                        {
                            TryCatch { certutil -f -dspublish "`"$($file.FullName)`"" CrossCA } > $null
                        }
                    }
                    else
                    {
                        ######
                        # AIA
                        ######

                        # Check if certificate hash is in AIA hashes
                        if ($CACertificateHash -notin $DSAIAHashArray -and
                            (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Name)`" ($CACertificateHash) to AIA container." @VerboseSplat))
                        {
                            # Check CA type
                            switch -regex ($CAType)
                            {
                                'Root'
                                {
                                    TryCatch { certutil -f -dspublish "`"$($file.FullName)`"" RootCA } > $null
                                }
                                'Subordinate'
                                {
                                    TryCatch { certutil -f -dspublish "`"$($file.FullName)`"" SubCA } > $null
                                }
                            }
                        }

                        ############################
                        # Certification Authorities
                        ############################

                        if ($CAType -match 'Root')
                        {
                            # Check if certificate hash in CA
                            if ($CACertificateHash -notin $DSCAHashArray -and
                                (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Name)`" ($CACertificateHash) to Certification Authorities container." @VerboseSplat))
                            {
                                TryCatch { certutil -f -dspublish "`"$($file.FullName)`"" RootCA } > $null
                            }
                        }

                        #####################
                        # NTAuthCertificates
                        #####################

                        if ($CAType -match 'Enterprise')
                        {
                            # Check if certificate hash in CA
                            if ($CACertificateHash -notin $DSNTAuthHashArray -and
                                (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Name)`" ($CACertificateHash) to NTAuthCertificates container." @VerboseSplat))
                            {
                                TryCatch { certutil -f -dspublish "`"$($file.FullName)`"" NTAuthCA } > $null
                            }
                        }
                    }
                }

                '.crl'
                {
                    # Get crl hash from file
                    $CAFileCrlHash = TryCatch { certutil -dump  "`"$($file.FullName)`"" } -ErrorAction SilentlyContinue | Where-Object {
                        $_ -match "CRL Hash\(sha1\): (.*)"
                    } | ForEach-Object { "$($Matches[1])" }

                    # Add crl hash to array
                    $CAFileCrlHashArray += $CAFileCrlHash

                    ######
                    # CDP
                    ######

                    # Check if crl hash in CDP
                    if ($AddCrl.IsPresent -and
                        ($CAFileCrlHash -notin $DSCDPHashArray) -and
                        (ShouldProcess @WhatIfSplat -Message "Adding `"$($file.Name)`" ($CAFileCrlHash) to CDP container." @VerboseSplat))
                    {
                        TryCatch { certutil -f -dspublish "`"$($file.FullName)`"" $CAServerName } > $null
                    }
                }
            }
        }

        #########
        # Remove
        #########

        if ($RemoveOld.IsPresent)
        {
            # AIA
            foreach($AIAHash in $DSAIAHashArray)
            {
                if ($AIAHash -notin $CAFileCertificateHashArray -and
                    (ShouldProcess @WhatIfSplat -Message "Remove `"$AIAHash`" from AIA container." @VerboseSplat))
                {
                    TryCatch { certutil -f -delstore "ldap:///CN=$CACommonName,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?cACertificate?base?objectClass=certificationAuthority" "`"$AIAHash`"" ` } > $null
                }
            }

            # CDP
            foreach($CDPHash in $DSCDPHashArray)
            {
                if ($CDPHash -notin $CAFileCrlHashArray -and
                    (ShouldProcess @WhatIfSplat -Message "Remove `"$CDPHash`" (CRL) from CDP container." @VerboseSplat))
                {
                    TryCatch { certutil -f -delstore "ldap:///CN=$CAServerName,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?*?sub?objectClass=cRLDistributionPoint" "`"$CDPHash`"" } > $null
                }
            }

            if ($CAType -match 'Root')
            {
                # CA
                foreach($CAHash in $DSCAHashArray)
                {
                    if ($CAHash -notin $CAFileCertificateHashArray -and
                        (ShouldProcess @WhatIfSplat -Message "Remove `"$CAHash`" from Certification Authorities container." @VerboseSplat))
                    {
                        TryCatch { certutil -f -delstore "ldap:///CN=$CACommonName,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?cACertificate?base?objectClass=certificationAuthority" "`"$CAHash`"" } > $null
                    }
                }
            }

            if ($CAType -match 'Enterprise')
            {
                # NTAuth
                foreach($NTAuthHash in $DSNTAuthHashArray)
                {
                    if ($NTAuthHash -notin $CAFileCertificateHashArray -and
                        (ShouldProcess @WhatIfSplat -Message "Remove `"$NTAuthHash`" from NTAuthCertificates container." @VerboseSplat))
                    {
                        TryCatch { certutil -f -delstore "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?cACertificate?base?objectClass=certificationAuthority" "`"$NTAuthHash`"" } > $null
                    }
                }
            }
        }

        #  █████╗  ██████╗██╗
        # ██╔══██╗██╔════╝██║
        # ███████║██║     ██║
        # ██╔══██║██║     ██║
        # ██║  ██║╚██████╗███████╗
        # ╚═╝  ╚═╝ ╚═════╝╚══════╝

        if ($CAType -match 'EnterpriseRoot')
        {
            ############################
            # Certification Authorities
            ############################

            Set-Ace -DistinguishedName "CN=$CACommonName,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -AceList $AceList
        }

        if ($CAType -match 'Enterprise')
        {
            ############
            # AIA & CDP
            ############

            $AceList =
            @(
                @{
                   IdentityReference        = "$DomainNetbiosName\$CAServerName$";
                   ActiveDirectoryRights    = 'GenericAll';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                }
            )

            # AIA
            Set-Ace -DistinguishedName "CN=$CACommonName,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -AceList $AceList

            # CDP
            Set-Ace -DistinguishedName "CN=$CACommonName,CN=$CAServerName,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -AceList $AceList

            ######################
            # Enrollment Services
            ######################

            # Get
            $ES = Get-ADObject -LDAPFilter "(cn=$CACommonName)" -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN"

            # Exist?
            if (-not $ES -and
                (ShouldProcess @WhatIfSplat -Message "Create `"$CACommonName`" Enrollment Services container." @VerboseSplat))
            {
                # Add
                $ES = New-ADObject -Name $CACommonName -DisplayName $CACommonName -Type 'pKIEnrollmentService' -Path "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -PassThru

                # Empty acl
                Set-Acl -AclObject (New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity) -Path "AD:$($ES.DistinguishedName)"
            }

            ##############
            # Certificate
            ##############

            # Get certificate from AD
            $cACertificate = Get-ADObject -Identity $ES.ObjectGUID -Properties cACertificate | Select-Object -ExpandProperty cACertificate

            # FIX
            # get current/latest of all CA crt files
            $TempCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2] "$env:TEMP\$CACommonName\$CACommonName.crt"

            if ((-not $cACertificate -or @(Compare-Object -ReferenceObject $cACertificate -DifferenceObject $TempCertificate.RawData -SyncWindow 0).Length -ne 0) -and
                (ShouldProcess @WhatIfSplat -Message "Adding `"$CACommonName`" Enrollment Services certificate to cACertificate attribute." @VerboseSplat))
            {
                Set-ADObject -Identity $ES.ObjectGUID -Replace @{ 'cACertificate' = $TempCertificate.RawData }
            }

            #############
            # Attributes
            #############

            $ESAttributes =
            @(
                @{ Name = 'cACertificateDN'; Value = "CN=$CACommonName, $($BaseDN.Replace(',', ', '))"; },  # set space after each ,
                @{ Name = 'dNSHostName'; Value = "$CAServerName.$DomainName"; },
                @{ Name = 'flags'; Value = 10; }
            )

            foreach($Attr in $ESAttributes)
            {
                if ((Get-ADObject -Identity $ES.ObjectGUID -Properties $Attr.Name).Item($Attr.Name).Value -ne $Attr.Value -and
                    (ShouldProcess @WhatIfSplat -Message "Setting `"$CACommonName`" Enrollment Services $($Attr.Name) = `"$($Attr.Value)`"." @VerboseSplat))
                {
                    Set-ADObject -Identity $ES.ObjectGUID -Replace @{ $Attr.Name = $Attr.Value }
                }
            }

            ###########
            # Security
            ###########

            $AceList =
            @(
                @{
                   IdentityReference        = 'NT AUTHORITY\Authenticated Users';
                   ActiveDirectoryRights    = 'GenericRead';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                },
                @{
                   IdentityReference        = 'NT AUTHORITY\Authenticated Users';
                   ActiveDirectoryRights    = 'ExtendedRight';
                   AccessControlType        = 'Allow';
                   ObjectType               = $AccessRight['Enroll'];
                   InheritanceType          = 'None';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                },
                @{
                   IdentityReference        = "$DomainNetbiosName\$CAServerName$";
                   ActiveDirectoryRights    = 'CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                },
                @{
                   IdentityReference        = "$DomainNetbiosName\Enterprise Admins";
                   ActiveDirectoryRights    = 'CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                }
            )

            Set-Ace -DistinguishedName $ES.DistinguishedName -AceList $AceList

            ######
            # KRA
            ######

            # Get
            $KRA = Get-ADObject -LDAPFilter "(cn=$CACommonName)" -SearchBase "CN=KRA,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN"

            # Exist?
            if (-not $KRA -and
                (ShouldProcess @WhatIfSplat -Message "Create `"$CACommonName`" KRA container." @VerboseSplat))
            {
                # Add
                $KRA = New-ADObject -Name $CACommonName -Type 'msPKI-PrivateKeyRecoveryAgent' -Path "CN=KRA,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDN" -OtherAttributes @{ userCertificate = ' ' } -PassThru

                # Empty acl
                Set-Acl -AclObject (New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity) -Path "AD:$($KRA.DistinguishedName)"
            }

            ###########
            # Security
            ###########

            $AceList =
            @(
                @{
                   IdentityReference        = 'Everyone';
                   ActiveDirectoryRights    = 'GenericRead';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                },
                @{
                   IdentityReference        = "$DomainNetbiosName\$CAServerName$";
                   ActiveDirectoryRights    = 'GenericAll';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                },
                @{
                   IdentityReference        = "$DomainNetbiosName\Domain Admins";
                   ActiveDirectoryRights    = 'GenericAll';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                },
                @{
                   IdentityReference        = "$DomainNetbiosName\Enterprise Admins";
                   ActiveDirectoryRights    = 'GenericAll';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                },
                @{
                   IdentityReference        = "BUILTIN\Administrators";
                   ActiveDirectoryRights    = 'GenericAll';
                   AccessControlType        = 'Allow';
                   ObjectType               = '00000000-0000-0000-0000-000000000000';
                   InheritanceType          = 'All';
                   InheritedObjectType      = '00000000-0000-0000-0000-000000000000';
                }
            )

            Set-Ace -DistinguishedName $KRA.DistinguishedName -AceList $AceList
        }

        # Remove temp directory
        Remove-Item -Path "$env:TEMP\$CACommonName" -Force -Recurse
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
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetAce.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Common
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $Force        = $Using:Force

            # Mandatory parameters
            $CAType = $Using:CAType
            $CACommonName = $Using:CACommonName
            $CAServerName = $Using:CAServerName
            $CAFiles = $Using:CAFiles

            $AddCrl = $Using:AddCrl
            $RemoveOld = $Using:RemoveOld
        }

        # Run main
        Invoke-Command -Session $Session -ScriptBlock $MainScriptBlock
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
                . $PSScriptRoot\f_SetAce.ps1
            }
            catch [Exception]
            {
                throw $_
            }

        } -NoNewScope

        # Run main
        Invoke-Command -ScriptBlock $MainScriptBlock -NoNewScope
    }
}

End
{
}

# SIG # Begin signature block
# MIIZBgYJKoZIhvcNAQcCoIIY9zCCGPMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpRrmFe7ZClG4kI/mcgTB5jOa
# yPagghKHMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# BgkqhkiG9w0BCQQxFgQUYfna8rJgDr8BU9YX2VkrL1U7G9EwDQYJKoZIhvcNAQEB
# BQAEggIAfKdJcX3Wo8pGvC0zjGy5SAu1JW+V4YWP7mI9ePC3031lZM3BFawF1MpQ
# xeiOzk5d+nNR/3Rh20H1prmJYUfu7pBa2AIKMaPXIUt4vevCkUFCfhzZnTy80z9r
# mq+Hp2vbo9epG/zwAZW6V8PnIA6VDbtpwsu/KcIhnC7vuJiJGzfsbsohCKkBBK5G
# /JE1Osts5+rl7FW3PLF/9zixDDn3aPM70PiUifiHzrNzQT/sHaDm4YoLrhJRyKFw
# 9+TFESM2d3LXL9MW3OLKkHZLXoPXp/IjFTrtEDDV3X1LkEwykR9vil2YrSMK4Jdv
# hX3dZFwqTGdk0XavaNGdx2eF+tlfusQ3kvHBL4lbR28BQo2F2jSkvz96JP/U9MSi
# NfOBR767eQEahCKX3XAIGiYNaMBC7xY+LUwKnfn2Yv5rejKPKnMQ826k7VDmuM95
# FqGBwQ1mzz4MCV54w3XAHrNBZsfovXfnmrvWsENzOpYgBTuc4Y+XTzqJ6l+yy6ug
# MOg8QEXbkFGB/YU5HFR9LWe3Qsg35EH2TARpBI8T6ZQ5vOotOwUa/0JxHw8XbQfX
# uK+0f6qj3Bf+AL9aPQ5g2nUuWIGsWQBrKwsU5igtGKgnzJNeWQqeNPWvnXGQ26M5
# mcany/VqonADRN2EGdM2VQMSzrgQnq1Gb7Fw/88qyv1gFpyrcguhggMgMIIDHAYJ
# KoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNB
# NDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0G
# CWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMjIwNTE4MTU0NTM0WjAvBgkqhkiG9w0BCQQxIgQgODvSGLljYKl6
# qv3ajQxmXDDSztFL3/Rcj6LyqgxDKKQwDQYJKoZIhvcNAQEBBQAEggIAca5qN+sw
# a/ro13x/MLT1Uw07Y0z0pVzMVHPKn88hdzFZhpwSlVmSCGjvuQApK1G/cUXH7n4/
# hUi1mOEGSpOU6egYhCZBMdTotMHhQF60BL/Fw2JoHRmogJHfNYULam/ovYKSsi+a
# xRMJKwIH/zrqswFhEAW997QFTb7olWnyBSZe+wuoiRFsPl0/HwEn+dnC/gw6i9kA
# xX1Vm8UIgnZrz5vhObm2zanezS1D3/+rM0b5AW/pchLvfV8uR/lCO/FyuJGAbomO
# EcghFBPQWCG/0btXdmWLWlO6WXXcuZHILlV8ZTm58d7DxC5Eq0sJFFmqtJ0w9C5U
# i1BdIxH9VACLcBSBzyck8ZC0QL4fcErZRsgrp816xZRVpmUeSjlFfL0N3s8Vx3a5
# cxWfOorhJQ3yns07IyQQh6VCNOhWTH8hdRT88xOQFVrDwa6h1YTsEsPswYStVb8H
# MDgGMry9nnjmsYKMObDc6+G6De+BG2XbvwqXE9l+8kO+P9W0DFvd3Oc2PTKdNJkd
# ZwEYtDFaFNm7/TrR7yIzy4alUfhTPqvKteeIJH4GOeDM8Ltfkhn76kWNnNgmrWGo
# ouwRjK1ROX29BZEKcX/FoRl5X+JHIst/M+LgMEze6925sRGEwf3gUrgVlC3672jr
# m9Aw2D1d+VYP7+9dqW/qYHgs3yDRxX+VbiE=
# SIG # End signature block
