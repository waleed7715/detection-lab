rule AsyncRAT
{
    meta:
        description = "AsyncRAT (Client namespace, AES-CBC+HMAC config). Primary anchor is the hardcoded PBKDF2 salt in the Aes256 class; string cluster is a fallback."
        author      = "Waleed"
        date        = "2026-09-27"
        family      = "AsyncRAT"
        reference   = "Project 4 — sample 2b76adf1 (v0.5.8), cert CN=AsyncRAT Server"

    strings:
        // PBKDF2 salt from Aes256 — stable across AsyncRAT builds
        $salt = { BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43
                  00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41 }

        // .NET metadata / config markers (raw in the assembly)
        $s1 = "Serversignature"    ascii wide
        $s2 = "Aes256"             ascii wide
        $s3 = "Rfc2898DeriveBytes" ascii wide
        $s4 = "AsyncRAT Server"    ascii wide

    condition:
        uint16(0) == 0x5A4D and          // PE (MZ)
        ($salt or 3 of ($s*))            // salt alone is high-confidence; else 3 string markers
}
