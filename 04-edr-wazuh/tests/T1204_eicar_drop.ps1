<#
  Lab-only malware-drop simulation for ATT&CK T1204.002.
  Writes the harmless EICAR antivirus test string into C:\LabDrop under a new name each run.
#>
Remove-Item C:\LabDrop\invoice_update*.exe -Force -ErrorAction SilentlyContinue
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$f = "C:\LabDrop\invoice_update_$(Get-Date -Format yyyyMMddHHmmss).exe"
Set-Content -Path $f -Value $eicar -NoNewline
Write-Host "Dropped $f"