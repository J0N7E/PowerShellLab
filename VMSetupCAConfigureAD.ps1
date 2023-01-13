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
            . $PSScriptRoot\f_CheckContinue.ps1
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
                @{ Name = 'cACertificateDN'; Value = "$($TempCertificate.Subject)"; },  # set space after each ,
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

    # Initialize
    $InvokeSplat = @{}

    # Setup remote
    if ($Session -and $Session.State -eq 'Opened')
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
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
                . $PSScriptRoot\f_TryCatch.ps1
                . $PSScriptRoot\f_SetAce.ps1
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
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU/C+etsifT6MxmLCMzdQptb0N
# aE2gghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUcTIdHUjt
# qTjhDAgcmuPIAt2eA+QwDQYJKoZIhvcNAQEBBQAEggIAt2UkImZ+otEigMLvrYid
# iX+7f0yX962F/fafC9uHR+kfBRNXUjkUw8OtzTlSqtwJaKbBVYaP3cFf50biiy9+
# XaOLAAwjWEkmxvTcv3sW7fFjrfCfPiKvzqGPME1HRjp6jJvDFXOk+lA5VATzduKk
# JO7jfZ/CKSrhl+jMACQNeC7AuqXaJiIHiLOjtNrl2rnZmgfrbNINmoawlUuqlDnv
# QT/syE1L9AYw5wRYvQbHpNvZMnKkPRSQ9dAK44U0A2KxicHtNR/3XHxDuUoAn33T
# 3NNLN2L1H0sx36TP3AS7LxuyGvf4TAlhduJORWV6RpeafV7cxNmSOrTmaFL2oKdw
# l98o/u/eJNFW8EmT9RSJA69KO8i8LFKy99oK1+1bhmKekdVLV7PlRQtQhxvssJwZ
# KaFVWOswYHhIzO0ru9uyEcYgSFOaTM7yzYvGpEB6NswYTYiTV6DkiOmVbxxYczAL
# Bz7ARWkrjNex22zWEdHoTT+cXehbgPzQ6ibMAjbbfcWMmoD3Blug7rOqcOYNFJ7l
# gQwvrhvN3XIwtQb1PuR9P9sl4K34rZEfkQ1kPYO69Mz6nXNQxRsuKWs/1wpYklEx
# qhWVsMIY2CRTsTVgICVuimg/C4EdfKnKxvbS7Zq+2atRiIfzn0ofTEgNUrHQ50d5
# hiPUZEWTapYjUt8RPGEXFQOhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwMTEzMjMwMDAx
# WjAvBgkqhkiG9w0BCQQxIgQg2RMHoXtTtknAc0X34LrK8YtptUw5i8NNN1KLu6c7
# l8MwDQYJKoZIhvcNAQEBBQAEggIAobjILVq1IldHilwyBPkTv5FpaQXT03tKbaKO
# WLtCyUdM2qNTmdIJhuRkC5HUYANIJG/dMH7HfQ/w5aS5hnjzb6CEKrkVBXscVorA
# zcuKaicW9s+cqc3gBfKpgbpGYdxJXX97SZdBgF7oX45N7Hbq+tqY7NGZL9OxOgMT
# CZAsNZuzjfiMrK9mEUluszvbS+yPKIjkdFPe0RVc6wZ3Yc1GF3dCCPAjB3nV5iYH
# oEm85gw7M0wWD4MAiaxzB7IZnNZdRvgBtdalMjbgUCKN3bCeNMofN3jDWmjDftYU
# Kw6XLV+ilCvaZO49fR8j7522JF3m6t/WoW95bKCLXvGzMQ9dxCarHEXfjUep5ZIZ
# q99cPA3EOfwauH1l3hNuQQDj3/gnSf9CMSZPRLKjZ82qtylh6ECP7gkZSJk5Rt2T
# Hk4MCrBQZIPg7G3r7rrx0ufaOX9BSMSeCu8Ik7mtT75QhrgPwCOtm/v4/IyVOdp8
# yNOHGLkRpWjtXDDhWsYC5SGW4GtQ7bV/aMgwTfX3xT8fxD3Xj9kb+8C6blBq8npT
# BJ0pisTzFVky/rEDrtB+rrkVajg145WUVj1B0PIdIGVgK2u6EOJ2rm+A0EUgukoA
# j+D2w1GpJZZH26QiI0F6E8HMyhp2eJC+jQJ/XOOpf2Z7mYEg3xZmSiPGL5ofwdBX
# Yttk2pk=
# SIG # End signature block
