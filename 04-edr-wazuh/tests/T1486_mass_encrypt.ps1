<#
  Lab-only ransomware simulation for ATT&CK T1486 (Data Encrypted for Impact).
  Touches only files under C:\FinanceShare. Use -Setup to create test files,
  -Run to "encrypt" them (random bytes + .locked rename), -Reset to start over.
#>
param([switch]$Setup, [switch]$Run, [switch]$Reset,
      [string]$Path = "C:\FinanceShare", [int]$Count = 200)

if ($Path -notlike "C:\FinanceShare*") { throw "Refusing to run outside C:\FinanceShare" }

if ($Setup -or $Reset) {
    if (Test-Path $Path) { Remove-Item "$Path\*" -Force }
    else { New-Item $Path -ItemType Directory | Out-Null }
    1..$Count | ForEach-Object { "Invoice $_ - lab data" | Set-Content "$Path\invoice_$_.txt" }
    Write-Host "Created $Count files in $Path"
}

if ($Run) {
    $rng = New-Object Random
    $start = Get-Date
    Get-ChildItem "$Path\*.txt" | ForEach-Object {
        $b = New-Object byte[] 256; $rng.NextBytes($b)
        [IO.File]::WriteAllBytes($_.FullName, $b)
        Rename-Item $_.FullName ($_.Name + ".locked")
    }
    "Encrypted {0} files in {1:N1}s" -f (Get-ChildItem "$Path\*.locked").Count, ((Get-Date) - $start).TotalSeconds
}