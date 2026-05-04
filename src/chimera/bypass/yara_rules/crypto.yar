/*
 * Embedded crypto-constant rules for chimera.
 *
 * Sized to be quick to scan: a small set covering the constants an
 * analyst sees most often in real Android/iOS native libs. For a deeper
 * sweep, drop additional .yar files into the same directory — chimera
 * loads every *.yar it finds at startup.
 */

rule AES_TE_TABLE
{
    meta:
        algorithm = "AES"
        kind = "crypto_constant"
        description = "AES T-table (Te0 forward) — first four entries of the standard 256-entry table"
    strings:
        // Te0[0..3] big-endian (Rijndael forward T-table)
        $te0_be = { c6 63 63 a5 f8 7c 7c 84 ee 77 77 99 f6 7b 7b 8d }
        // Same as bytes laid out little-endian in many compilers
        $te0_le = { a5 63 63 c6 84 7c 7c f8 99 77 77 ee 8d 7b 7b f6 }
    condition:
        any of them
}

rule AES_SBOX
{
    meta:
        algorithm = "AES"
        kind = "crypto_constant"
        description = "AES forward S-box first 16 bytes"
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        $sbox
}

rule AES_RCON
{
    meta:
        algorithm = "AES"
        kind = "crypto_constant"
        description = "AES round constants (Rcon)"
    strings:
        $rcon = { 01 02 04 08 10 20 40 80 1b 36 }
    condition:
        $rcon
}

rule DES_SBOX_S1
{
    meta:
        algorithm = "DES"
        kind = "crypto_constant"
        description = "DES S-box S1 first row"
    strings:
        $s1 = { 0e 04 0d 01 02 0f 0b 08 03 0a 06 0c 05 09 00 07 }
    condition:
        $s1
}

rule MD5_INIT_CONSTANTS
{
    meta:
        algorithm = "MD5"
        kind = "crypto_constant"
        description = "MD5 IV (a, b, c, d) little-endian"
    strings:
        $iv = { 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 }
    condition:
        $iv
}

rule SHA1_INIT_CONSTANTS
{
    meta:
        algorithm = "SHA1"
        kind = "crypto_constant"
        description = "SHA-1 IV"
    strings:
        $h0 = { 67 45 23 01 ef cd ab 89 98 ba dc fe 10 32 54 76 c3 d2 e1 f0 }
    condition:
        $h0
}

rule SHA256_INIT_CONSTANTS
{
    meta:
        algorithm = "SHA256"
        kind = "crypto_constant"
        description = "SHA-256 H0..H7 IV"
    strings:
        $h = { 67 e6 09 6a 85 ae 67 bb 72 f3 6e 3c 3a f5 4f a5 7f 52 0e 51 8c 68 05 9b ab d9 83 1f 19 cb e1 5b }
    condition:
        $h
}

rule BLOWFISH_PI_INITIAL
{
    meta:
        algorithm = "Blowfish"
        kind = "crypto_constant"
        description = "Blowfish P-array initial constants from pi"
    strings:
        $pi = { 24 3f 6a 88 85 a3 08 d3 13 19 8a 2e 03 70 73 44 }
    condition:
        $pi
}

rule CHACHA20_CONSTANT
{
    meta:
        algorithm = "ChaCha20"
        kind = "crypto_constant"
        description = "ChaCha20 sigma constant 'expand 32-byte k'"
    strings:
        $sigma = "expand 32-byte k"
    condition:
        $sigma
}

rule CURVE25519_PRIME
{
    meta:
        algorithm = "Curve25519"
        kind = "crypto_constant"
        description = "Curve25519 prime 2^255-19 marker"
    strings:
        // Last 8 bytes of the 2^255 - 19 prime, common in implementations
        $p = { ed ff ff ff ff ff ff 7f }
    condition:
        $p
}
