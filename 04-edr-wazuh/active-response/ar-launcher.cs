// ar-launcher.cs - minimal console launcher for a PowerShell-based Wazuh active response.
//
// Wazuh's Windows agent runs active responses as .exe files and talks to them over
// stdin/stdout (alert JSON in, check_keys out, continue/abort back in). PS2EXE-built
// executables consume stdin themselves, which breaks that exchange. This launcher just
// starts powershell.exe on the .ps1 of the same name and lets it inherit the agent's
// stdin/stdout unchanged, so all logic stays in the readable .ps1.
//
// Build on the agent host (elevated), from the active-response\bin folder:
//   Add-Type -TypeDefinition (Get-Content ar-launcher.cs -Raw) `
//     -OutputAssembly disable-account.exe -OutputType ConsoleApplication
// The exe runs <its own name>.ps1 from the same folder.

using System;
using System.Diagnostics;
using System.IO;

public static class ArLauncher
{
    public static int Main()
    {
        string exePath = Process.GetCurrentProcess().MainModule.FileName;
        string script  = Path.ChangeExtension(exePath, ".ps1");

        // The Wazuh agent is 32-bit; make sure we start 64-bit PowerShell,
        // which is where the ActiveDirectory module lives.
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string sysDir = Environment.Is64BitProcess ? "System32" : "Sysnative";
        string ps     = Path.Combine(winDir, sysDir, @"WindowsPowerShell\v1.0\powershell.exe");

        var psi = new ProcessStartInfo(ps,
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script + "\"");
        psi.UseShellExecute = false;   // child inherits stdin/stdout from the agent

        using (Process p = Process.Start(psi))
        {
            p.WaitForExit();
            return p.ExitCode;
        }
    }
}