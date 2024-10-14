<#
.SYNOPSIS
This PowerShell script provides functionality to audit the Access Control List (ACL) of a specified file or directory path. It resolves security identifiers (SIDs) and Active Directory (AD) objects, creating a structured representation of principals (users and groups) with their associated access rights.

.DESCRIPTION
The script defines several functions:
- `New-Principal`: Creates a custom object representing a principal (user or group) with properties such as Name, SamAccountName, Type, and access rights.
- `Resolve-ADObject`: Resolves an AD object based on a provided SID or SamAccountName, returning a principal object or creating an unknown principal if not found.
- `Resolve-Group`: Retrieves members of an AD group and creates principal objects for each member.
- `Audit-ACL`: Audits the ACL of a specified path, processing each access rule to identify and resolve principals, including handling built-in accounts and unresolved SIDs.

.PARAMETER Path
The path of the file or directory whose ACL will be audited. This parameter is mandatory and must point to a valid path.

.PARAMETER IgnoreInherited
A switch parameter that, when specified, causes the script to ignore inherited access rules during the audit.

.PARAMETER ExcludeGroups
A string parameter that allows specifying groups to exclude from the audit process.

.EXAMPLE
Audit-ACL -Path "C:\ExampleDirectory" -IgnoreInherited -ExcludeGroups "Domain Admins"
This command audits the ACL of the specified directory, ignoring inherited rules and excluding the "Domain Admins" group from the results.

#>

Function New-Principal {
    param(
        [string]$Name,
        [string]$SamAccountName,
        [string]$Type,
        [string]$FromGroup,
        [string]$AccessControlType,
        [string]$FileSystemRights,
        [string]$IsInherited
    )

    return [PSCustomObject]@{
        Name  = $Name
        SamAccountName   = $SamAccountName
        Type = $Type
        FromGroup = $FromGroup
        AccessControlType = $AccessControlType
        FileSystemRights = $FileSystemRights
        IsInherited = $IsInherited
        Path = $Path
    }
}

Function Resolve-ADObject {
    param(
        [string]$SID,
        [string]$SamAccountName,
        [object]$AccessRule

    )

    If($SID -ne '') {
        Write-Verbose "Try to find sid in AD: $($SID)"
        $ADObject = Get-AdObject -Filter { objectSid -eq $SID } -Properties ObjectClass, SamAccountName
    } Else {
        Write-Verbose "Try to find samaccountname in AD: $($SamAccountName)"
        $ADObject = Get-AdObject -Filter { SamAccountName -eq $SamAccountName } -Properties ObjectClass, SamAccountName
    }

    If(-not $ADObject) {
        Write-Verbose "Could not find AD object - SamAccountName: $SamAccountName - SID: $SID"
        New-Principal -Name $AccessRule.IdentityReference -Type 'Unknown' -AccessControlType $AccessRule.AccessControlType -FileSystemRights $AccessRule.FileSystemRights -IsInherited $AccessRule.IsInherited
    } Else {
        Switch($ADObject) {
            # ADGroup
            {$ADObject.ObjectClass -eq 'group'} {
                # Resolve the group but add it as principal either way

                # Check if we want to resolve that group
                If(-not ($ExcludeGroups -and $_.SamAccountName -match $ExcludeGroups)) {
                    Resolve-Group -SamAccountName $_.SamAccountName -AccessRule $AccessRule
                    New-Principal -Name $_.Name -Type 'ADGroup' -SamAccountName $_.SamAccountName -AccessControlType $AccessRule.AccessControlType -FileSystemRights $AccessRule.FileSystemRights -IsInherited $AccessRule.IsInherited
                }

            }
            # ADUser
            {$ADObject.ObjectClass -eq 'user'} {
                New-Principal -Name $_.Name -Type 'ADUser' -SamAccountName $_.SamAccountName -AccessControlType $AccessRule.AccessControlType -FileSystemRights $AccessRule.FileSystemRights -IsInherited $AccessRule.IsInherited
            }
            # Whatever that would be
            default {
                New-Principal -Name $AccessRule.IdentityReference -Type 'Unknown' -AccessControlType $AccessRule.AccessControlType -FileSystemRights $AccessRule.FileSystemRights -IsInherited $AccessRule.IsInherited
            }
        }
    }
}

Function Resolve-Group {
    param(
        [string]$SamAccountName,
        [object]$AccessRule
    )

    Get-AdGroupMember -Identity $SamAccountName -Recursive | Foreach-Object {
        $GroupMember = $_
        New-Principal -Name $GroupMember.Name -Type 'ADUser' -SamAccountName $GroupMember.SamAccountName -FromGroup $SamAccountName -AccessControlType $AccessRule.AccessControlType -FileSystemRights $AccessRule.FileSystemRights -IsInherited $AccessRule.IsInherited
    }
}

Function Resolve-ACL {
    [CMDLetBinding()]

Param(
    [Parameter(Mandatory,ValueFromPipeline)]
    [ValidateScript({ Test-Path -Path $_ })]
    [String]$Path,
    [switch]$IgnoreInherited,
    [string]$ExcludeGroups
)

Begin {}

Process {
    $Acl = Get-ACL $Path

    IF(-not $Acl) {
        Write-Error "Could not read access control list"
        Exit
    }

    Foreach ($AccessRule in $Acl.Access) {
        If($IgnoreInherited -and $AccessRule.IsInherited -eq $true) {
            Continue
        }

        # Check what kind of object we are dealing with
        Switch($AccessRule) {
            # Unresolved SID
            { $_.IdentityReference -match 'S-1-5-21' } {
                Write-Verbose "Identified SID in: $($_.IdentityReference)"
                Resolve-ADObject -SID $_.IdentityReference -AccessRule $AccessRule
            }

            # Builtin accounts
            { $_.IdentityReference -match '(^NT AUTHORITY\\|^BUILTIN\\|^Everyone$)' } {
                Write-Verbose "Identified builtin account in: $($_.IdentityReference)"
                New-Principal -Name $_.IdentityReference -Type 'BUILTIN' -AccessControlType $_.AccessControlType -FileSystemRights $_.FileSystemRights -IsInherited $_.IsInherited
            }

            # Try to find an AD object
            default {
                # Remove the downlevel domain name
                Write-Verbose "Could not identity $($_.IdentityReference)"
                $SamAccountName = $_.IdentityReference -replace '^.*?\\'

                Write-Verbose "Proceed to search AD for $SamAccountName"
                Resolve-ADObject -SamAccountName $SamAccountName -AccessRule $AccessRule
            }

        }
    }
}

End {}


}

Export-ModuleMember -Function Resolve-ACL
