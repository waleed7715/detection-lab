rule Remcos_RAT
{
    meta:
        description = "Remcos RAT (Breaking-Security). Keys on the encrypted SETTINGS resource marker plus Remcos/vendor strings and the watchdog registry artifact."
        author      = "Waleed"
        date        = "2026-09-29"
        family      = "Remcos"
        reference   = "Project 4 — native C++, RC4-encrypted SETTINGS resource"

    strings:
        // Resource name holding the RC4-encrypted config (RCDATA "SETTINGS")
        $res = "SETTINGS" ascii wide

        // Vendor / family markers seen in Remcos builds
        $v1 = "Remcos" ascii wide
        $v2 = "Breaking-Security" ascii wide nocase
        $v3 = "BreakingSecurity" ascii wide nocase

        // Behavioral / capability strings common to Remcos
        $b1 = "Watchdog" ascii wide nocase
        $b2 = "Keylogger" ascii wide nocase
        $b3 = "MicRecords" ascii wide
        $b4 = "Screenshots" ascii wide

    condition:
        uint16(0) == 0x5A4D and                 // PE (MZ)
        $res and                                // must carry the SETTINGS resource
        (
            any of ($v*) or                     // a vendor/family string, OR
            2 of ($b*)                          // two capability strings
        )
}
