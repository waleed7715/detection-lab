# disable-account.ps1 - Wazuh stateful active response, account containment (ATT&CK T1078)
#   command "add"    : disable the AD account named in the triggering alert
#   command "delete" : re-enable it (Wazuh sends this when the AR timeout lapses)
#
# Safety: acts ONLY on accounts whose distinguished name is inside $AllowedOU.
# Machine accounts, admins, service accounts and anything else are refused and logged.
#
# Protocol (Wazuh docs, custom active response scripts):
#   - read ONE JSON line from stdin
#   - for "add": write a check_keys message to stdout (newline-terminated), read the
#     reply line, and act only on "continue"
#
# Build for the Windows agent (run on the agent host, elevated):
#   Invoke-PS2EXE -InputFile disable-account.ps1 -OutputFile disable-account.exe

$AllowedOU = "OU=TestUsers,OU=SOCLab,DC=soc,DC=lab"
$LogFile   = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-ARLog([string]$msg) {
    $line = "{0} disable-account: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $msg
    for ($i = 0; $i -lt 5; $i++) {
        try { [IO.File]::AppendAllText($LogFile, $line + "`r`n"); return }
        catch { Start-Sleep -Milliseconds 200 }
    }
}

# Raw stdin/stdout streams behave the same in powershell.exe and in a PS2EXE-built exe.
$stdin  = New-Object IO.StreamReader([Console]::OpenStandardInput())
$stdout = New-Object IO.StreamWriter([Console]::OpenStandardOutput())
$stdout.AutoFlush = $true

try {
    $line = $stdin.ReadLine()
    if (-not $line) { Write-ARLog "empty input; nothing to do"; exit 0 }

    $msg     = $line | ConvertFrom-Json
    $command = $msg.command
    $user    = $msg.parameters.alert.data.win.eventdata.targetUserName
    Write-ARLog "received command=$command user=$user rule=$($msg.parameters.alert.rule.id)"

    if (-not $user)         { Write-ARLog "no targetUserName in alert; nothing to do"; exit 0 }
    if ($user -match '\$$') { Write-ARLog "REFUSED: '$user' is a machine account"; exit 0 }

    Import-Module ActiveDirectory -ErrorAction Stop
    $safe = $user -replace "'", "''"
    $obj  = Get-ADUser -Filter "SamAccountName -eq '$safe'" -ErrorAction Stop
    if (-not $obj) { Write-ARLog "REFUSED: '$user' not found in AD"; exit 0 }

    if (-not $obj.DistinguishedName.EndsWith(",$AllowedOU", [StringComparison]::OrdinalIgnoreCase)) {
        Write-ARLog "REFUSED: '$user' is outside $AllowedOU ($($obj.DistinguishedName))"
        exit 0
    }

    switch ($command) {
        "add" {
            $check = @{
                version    = 1
                origin     = @{ name = "disable-account"; module = "active-response" }
                command    = "check_keys"
                parameters = @{ keys = @($user) }
            } | ConvertTo-Json -Compress -Depth 5
            $stdout.WriteLine($check)

            $reply    = $stdin.ReadLine()
            $decision = if ($reply) { ($reply | ConvertFrom-Json).command } else { "continue" }
            if ($decision -eq "abort") { Write-ARLog "ABORTED: '$user' is already contained"; exit 0 }

            Disable-ADAccount -Identity $obj
            Write-ARLog "DISABLED account '$user'"
        }
        "delete" {
            Enable-ADAccount -Identity $obj
            Write-ARLog "RE-ENABLED account '$user' (timeout lapsed)"
        }
        default { Write-ARLog "unknown command '$command'" }
    }
}
catch {
    Write-ARLog "ERROR: $($_.Exception.Message)"
    exit 1
}
