# Run with appropriate AD privileges
# Place pcs.txt in the same directory (one PC name per line)

Import-Module ActiveDirectory

$pcListFile = "pcs.txt"
$pcNames = Get-Content $pcListFile | Where-Object { $_ -ne "" }

foreach ($pcName in $pcNames) {
    Write-Host "Processing: $pcName"
    
    try {
        # Get the computer object (same name as user)
        $computer = Get-ADComputer -Identity $pcName -ErrorAction Stop
        $user = Get-ADUser -Identity $pcName -ErrorAction Stop
        
        # Add "Reset Password" extended right
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $computer.SID,
            "ExtendedRight",
            "Allow",
            [Guid]"00299570-246d-11d0-a768-00aa006e0529",
            "None"
        )
        
        $acl = Get-Acl "AD:$($user.DistinguishedName)"
        $acl.AddAccessRule($ace)
        Set-Acl -AclObject $acl -Path "AD:$($user.DistinguishedName)"
        
        Write-Host "Added Reset Password right for $pcName" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed: $_" -ForegroundColor Red
    }
}

Write-Host "`nComplete." -ForegroundColor Cyan