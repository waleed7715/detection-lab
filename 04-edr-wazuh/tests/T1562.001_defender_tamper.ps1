<#
  Lab-only Defender tampering simulation for ATT&CK T1562.001.
  -Run disables real-time protection and adds an exclusion; -Reset undoes both.
#>
param([switch]$Run, [switch]$Reset)
$stage = "C:\Windows\Temp\stage"
if ($Run) {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Add-MpPreference -ExclusionPath $stage
    Write-Host "RTP disabled: $((Get-MpPreference).DisableRealtimeMonitoring)"
}
if ($Reset) {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Remove-MpPreference -ExclusionPath $stage
    Write-Host "RTP disabled: $((Get-MpPreference).DisableRealtimeMonitoring)"
}