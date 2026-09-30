rule XWorm_RAT
{
    meta:
        description = "XWorm RAT (AsyncRAT-lineage, Stub namespace). Keys on the command-dispatch handler and WMI recon strings, which survive symbol obfuscation."
        author      = "Waleed"
        date        = "2026-09-27"
        family      = "XWorm"
        reference   = "Project 4 — samples ac7e7f56, eb8b9a20 (obfuscated)"
        note        = "Does NOT match packed samples (e.g. eaad67ae native loader) until unpacked."

    strings:
        // Command-dispatch strings from Messages.Read() — functional, hard to obfuscate away
        $c1 = "StartDDos"  ascii wide
        $c2 = "savePlugin" ascii wide
        $c3 = "sendPlugin" ascii wide
        $c4 = "Shosts"     ascii wide
        $c5 = "PCShutdown" ascii wide
        $c6 = "Xchat"      ascii wide

        // Host recon from ClientSocket.Info()
        $w1 = "SELECT * FROM AntivirusProduct" ascii wide
        $w2 = "SecurityCenter2"                ascii wide
        $w3 = "Win32_VideoController"          ascii wide

    condition:
        uint16(0) == 0x5A4D and          // PE (MZ)
        4 of ($c*) and                   // at least 4 of the command handlers
        2 of ($w*)                       // at least 2 of the WMI recon queries
}
