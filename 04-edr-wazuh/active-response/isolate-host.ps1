# isolate-host.ps1 - Wazuh stateful active response, strict host network isolation
#   add    : block ALL network traffic except to the Wazuh manager
#   delete : restore normal firewall policy (Wazuh sends this when the timeout lapses)
#
# The manager is allowed FIRST, before the block is applied, so the agent never
# loses its link and the timeout-revert can always arrive. Every rule we add is
# tagged in the WazuhIsolation group, so the revert removes exactly what we added.
#
# Build for the Windows agent (run on the agent host, elevated):
#   Add-Type -TypeDefinition (Get-Content ar-launcher.cs -Raw) `
#     -OutputAssembly isolate-host.exe -OutputType ConsoleApplication

$ManagerIP = "10.10.10.20"
$MgrPorts  = "1514","1515"
$Group     = "WazuhIsolation"
$LogFile   = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-ARLog([string]$msg) {
    $line = "{0} isolate-host: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $msg
    for ($i = 0; $i -lt 5; $i++) {
        try { [IO.File]::AppendAllText($LogFile, $line + "`r`n"); return }
        catch { Start-Sleep -Milliseconds 200 }
    }
}

$stdin  = New-Object IO.StreamReader([Console]::OpenStandardInput())
$stdout = New-Object IO.StreamWriter([Console]::OpenStandardOutput())
$stdout.AutoFlush = $true

try {
    $line = $stdin.ReadLine()
    if (-not $line) { Write-ARLog "empty input; nothing to do"; exit 0 }

    $msg     = $line | ConvertFrom-Json
    $command = $msg.command
    $host_   = $env:COMPUTERNAME
    Write-ARLog "received command=$command host=$host_ rule=$($msg.parameters.alert.rule.id)"

    Import-Module NetSecurity -ErrorAction Stop

    switch ($command) {
        "add" {
            $check = @{
                version    = 1
                origin     = @{ name = "isolate-host"; module = "active-response" }
                command    = "check_keys"
                parameters = @{ keys = @($host_) }
            } | ConvertTo-Json -Compress -Depth 5
            $stdout.WriteLine($check)

            $reply    = $stdin.ReadLine()
            $decision = if ($reply) { ($reply | ConvertFrom-Json).command } else { "continue" }
            if ($decision -eq "abort") { Write-ARLog "ABORTED: '$host_' already isolated"; exit 0 }

            # 1) allow the manager BEFORE blocking, so the agent link survives
            New-NetFirewallRule -DisplayName "WazuhIsolation-Mgr-Out" -Group $Group -Direction Outbound `
                -Action Allow -RemoteAddress $ManagerIP -Protocol TCP -RemotePort $MgrPorts -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName "WazuhIsolation-Mgr-In" -Group $Group -Direction Inbound `
                -Action Allow -RemoteAddress $ManagerIP -Profile Any | Out-Null

            # 2) now block everything else, all profiles
            Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block
            Write-ARLog "ISOLATED host '$host_' - all traffic blocked except $ManagerIP"
        }
        "delete" {
            Remove-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue
            # restore the normal Windows default: block inbound, allow outbound
            Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
            Write-ARLog "RESTORED host '$host_' network (timeout lapsed)"
        }
        default { Write-ARLog "unknown command '$command'" }
    }
}
catch {
    Write-ARLog "ERROR: $($_.Exception.Message)"
    exit 1
}