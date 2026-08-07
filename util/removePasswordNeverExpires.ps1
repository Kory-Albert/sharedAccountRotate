Import-Module ActiveDirectory

$pcListFile = "pcs.txt"
$pcNames = Get-Content $pcListFile | Where-Object { $_ -ne "" }

foreach ($pcName in $pcNames) {
    Write-Host "Processing: $pcName"
    
    try {
        $user = Get-ADUser -Identity $pcName -ErrorAction Stop
        
        # Uncheck "Password never expires"
        Set-ADUser -Identity $user -PasswordNeverExpires $false
        
        Write-Host "Removed Password Never Expires for $pcName" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed: $_" -ForegroundColor Red
    }
}

Write-Host "`nComplete." -ForegroundColor Cyan