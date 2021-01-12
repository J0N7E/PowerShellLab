<#
 .DESCRIPTION
    Setup and configure Certificate Authority server AD objects
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

    [Parameter(Mandatory=$true)]
    [ValidateSet('StandaloneRootCA', 'EnterpriseRootCA', 'EnterpriseSubordinateCA')]
    [String]$CAType,

    # Certificate Authority common name
    [Parameter(Mandatory=$true)]
    [String]$CACommonName,

    [Parameter(Mandatory=$true)]
    [String]$CAServerName
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
    if (-not $CAFiles.GetEnumerator().Where({$_.Key -match '.crl'}))
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

                    <#
                    # Add crl hash to array
                    $CAFileCrlHashArray += $CAFileCrlHash
                    #>

                    ######
                    # CDP
                    ######

                    # Check if crl hash in CDP
                    if (($CAFileCrlHash -notin $DSCDPHashArray) -and
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

        # AIA
        foreach($AIAHash in $DSAIAHashArray)
        {
            if ($AIAHash -notin $CAFileCertificateHashArray -and
                (ShouldProcess @WhatIfSplat -Message "Remove `"$AIAHash`" from AIA container." @VerboseSplat))
            {
                TryCatch { certutil -f -delstore "ldap:///CN=$CACommonName,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?cACertificate?base?objectClass=certificationAuthority" "`"$AIAHash`"" ` } > $null
            }
        }

        <#
        # CDP
        foreach($CDPHash in $DSCDPHashArray)
        {
            if ($CDPHash -notin $CAFileCrlHashArray -and
                (ShouldProcess @WhatIfSplat -Message "Remove `"$CDPHash`" (CRL) from CDP container." @VerboseSplat))
            {
                TryCatch { certutil -f -delstore "ldap:///CN=$CAServerName,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$($BaseDN)?*?sub?objectClass=cRLDistributionPoint" "`"$CDPHash`"" } > $null
            }
        }
        #>

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
# FIX
# reinstall and check default DN
#VERBOSE: Setting "Enterprise CA04" Enrollment Services cACertificateDN = "CN=Enterprise CA04,DC=bcl,DC=nu".

            $ESAttributes =
            @(
                @{ Name = 'cACertificateDN'; Value = "CN=$CACommonName,$BaseDN"; },
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

    # Remote
    if ($Session -and $Session.State -eq 'Opened')
    {
        # Load functions
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_TryCatch.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_ShouldProcess.ps1
        Invoke-Command -Session $Session -ErrorAction Stop -FilePath $PSScriptRoot\f_SetAce.ps1

        # Get parameters
        Invoke-Command -Session $Session -ScriptBlock `
        {
            # Splat
            $VerboseSplat = $Using:VerboseSplat
            $WhatIfSplat  = $Using:WhatIfSplat
            $ComputerName = $Using:ComputerName

            # Mandatory parameters
            $CAType = $Using:CAType
            $CACommonName = $Using:CACommonName
            $CAServerName = $Using:CAServerName
            $CAFiles = $Using:CAFiles
        }

        # Run main
        Invoke-Command -Session $Session -ScriptBlock $MainScriptBlock
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
# MIIXpgYJKoZIhvcNAQcCoIIXlzCCF5MCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUeLEtDCH3sqWYUZOUP/ZUsoFQ
# QwegghI6MIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRc4FDK6VDxq2Q8E1NKPfOz
# rFcHjzANBgkqhkiG9w0BAQEFAASCAgAdlw9ywh06Z4fzes5IhY3KQUsPTxfolR98
# w7S5uXxCky0Jeg6uRHTGN7TZREDyRiFG7/0AH/DXR1G2RovA0jSNOo1CYSxOTEIE
# wMVvFq6M8ZuGP0M6/YAJ8gbN6zxMZDCtMhyDyScqE6S7xd/3mWpIiilnWvnLpfq3
# +VetR5JR8PQkgQk7JuK2zWlokkDyZx02o1f9h9+jiJTlb5M/z4R9IeNi1mwcTuAM
# X/XMX39TmoJxhbi1gIjYCqz6l4zTQwqUR9+y+9Tchk71C9/lc+p9+h8RaDnjr+GR
# 7E25DB1Dh0gAdN7Ig4GEB+4PovjelAtjuhPT8WwZZKPCGoKFojY5SMi/ot98tQhH
# V0QEGYcDRTUHjtdeTHl79S+9mJmVhaC5AdaACZnid7J/2yUDdddWcjZXPCOPXjIH
# iL7zLmwKV1YfFClqVczh/qabMfdmPkKA6owHjxRXpGAuRfH9zK5P5ORpm6ETyXRQ
# sbDvQQfCRltG51V/GqCs1U9MLEcm2Mib9CA5KD0GXPCUvmQhe3910Z3PV3wJ8dFd
# HV5rXLy/+RDNIK/L9MTfmOrKFyJI4TBwo0gVL04DV9jtN4iiSNIFc68pLLT44lYc
# 1hlCRKR82d/v4tUxyHHVuDzx5RLAhOEhuijukrQo+FEHqdXL/QCt8MhzBbfmeuyo
# 66Frl+wPYqGCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAxMDEyMDAwMDA2WjAjBgkqhkiG9w0BCQQx
# FgQUOgqksZ9PWvxBtUKGbS8WBLGkMfMwDQYJKoZIhvcNAQEBBQAEggEAbaja2Oka
# Ml9xpUCRaetJPGXbYR4LPJOfroY/X8PEfYI8WbWUcCg3z8gXiAk1KHKECg5F3Yos
# DbOCnvp/tgANE7tKQEszih4E5fZ0LiF8i1vZMDssxLJE/kWhBxOiEjc4SqctbjuB
# tCwr6DZftnkYjv1sH7P+ADRkBHDkfcf1kVKFDpzr0o8oYemOEAeJN3bMxfkRK32y
# DJ7t/WE2C9ttjKHPpe2cG1Q4nA0YKa4lvhmPDFKQEOe8uafwDriU9RYf6JoOUmKy
# sBok4xNyUVAjRAVBT/zvLAiE4djmHuatPz5qr7a7GNfgwmdaxCOJvr8MUzrLje1C
# r0LqomuMA8yLBw==
# SIG # End signature block
