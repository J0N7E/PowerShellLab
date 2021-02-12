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
# MIIUrwYJKoZIhvcNAQcCoIIUoDCCFJwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwL3y0aupsNXqBX3tfdeL37px
# ZJOggg8yMIIE9zCCAt+gAwIBAgIQJoAlxDS3d7xJEXeERSQIkTANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUmJwfrSe2/IWRQepUlTddbuXR7qMwDQYJ
# KoZIhvcNAQEBBQAEggIAeiqj4Eaa4ObPwli6A9v0Rpwg8m2OK86tYk47FALP/Lwn
# x0G4GMMfL6wejry0r/nTZ4ZuUi/PVK77mrJpGb+AriUmyCMdCKqEaO7AtRuM/O7S
# uS91/vyRiR/roMYPUd7Fs4EnXbHDhobVfsgZ4fJEpxiGZY7QW3t87hiiioBQCDj4
# Wjv+j3SdZGqzcTfvbvAcw1Xr3s9UuGsSpUN63CwZwi39mmnLhnuCT0iKMwerQ8lU
# 96XHB+Ru/uE5NgZmobjc1FuMo3YenDpjSwmN9KHNZdW2CTbLLeA5QjGhgl7AJUUx
# yNl0E1I5iGwxd8Gl4KMa27/oqFt/7fmHOOWAJawmNHjqWWQujxEV7GpSMnWBysh/
# mKi+gacJ1kXsRaQ3fskjPtmdPssOobnB3MP0UBK81sRjwxYBcx3KQR4NSbvs5tCx
# LTZMH71Z0h8uW4r8Oq6R8p65SHHiMFbBWimhx3d86JoQ9DO+halBSJQpVu13pObL
# 0kvF3wjNgEAtQxYsYE5xsbhWuzsNg8plXOskccErj9c25ly6iomp0Y7u4AIBpX3J
# J0ojIY8MG1ox7YWb5RTSpUIlbVSwGYbQiSzwbLUUZslGhzpZO6gW17VO8gDlfZeV
# M0VPAC952rDxNFFqqga1bwb5UniNRZUGaoNwehK2aPrAbMfwRz39f31tbxhnIEWh
# ggIgMIICHAYJKoZIhvcNAQkGMYICDTCCAgkCAQEwgYYwcjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGlu
# ZyBDQQIQDUJK4L46iP9gQCHOFADw3TAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjEwMjEyMDEwMDA0WjAjBgkq
# hkiG9w0BCQQxFgQUsMuF92u5DT2CxJZXmoMYMn3d5BIwDQYJKoZIhvcNAQEBBQAE
# ggEAIRzQDoZKOdGie+ay7K9rmQKqnWIwR0OhpSxdIlLeMoEhULT/ft6eytZkQvj+
# TQFdXuVi/OgNJdJhzz/ZHvyl3G2dW+gZISxyTYvJQ8l4yS+teiPIpuzbCI9f8/9q
# D/IVthvfjE4zLqzwbVu0a0JZscbWzqfW1JZeaxLXriNdgf5efqNQXI/CcmjQE9WW
# kAMzLoT/ljQTM5mFM1uEO6beXodohXfoYhSFFO4kVuBDUEE+AcJnMixcELuh1bKc
# JBz6acyNAJNsB2AGbtiEk1d0gjNSJPQrbF/p7b9qNGd7fCB9i6kSJhQcP7CNYqar
# zmqe/HzU6V6XqzLEWWsuKEqAPw==
# SIG # End signature block
