#!/usr/bin/env python3
"""Generate FLIRT-equivalent signature packs from real ELF / PE libraries.

Usage::

    # ELF (glibc, openssl, zlib, curl, etc.)
    scripts/build_libfn_sigs.py \\
        --library /usr/lib/x86_64-linux-gnu/libc.so.6 \\
        --library /usr/lib/x86_64-linux-gnu/libssl.so.3 \\
        --library /usr/lib/x86_64-linux-gnu/libz.so.1 \\
        --out src/chimera/data/sigs/libc-x86_64.json \\
        --pack-name libc-musl-openssl-zlib

    # PE (a Windows SDK static-link build of msvcrt, if you have one staged)
    scripts/build_libfn_sigs.py --format pe --library msvcrt.dll --out msvcrt-x86_64.json

The script walks each library's symbol table, reads the first N bytes at
each named function's entry address, and writes them as Signature entries
under a mask that nulls out call-target operands so the signature
survives PIE / ASLR relocations. We do not currently scan dynamic
relocations — symbol entries point at PLT stubs on most distros, which
match each other across builds without any further normalisation.

The output is committed alongside the source so docker images carry the
matcher's input out of the box.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Add the repo to sys.path so we can import chimera modules without an
# editable install. The script lives in `scripts/` so the repo root is
# one level up.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from chimera.parsers.function_signatures import (  # noqa: E402
    SIG_BYTES,
    Signature,
    dump_signature_pack,
)

logger = logging.getLogger("build_sigs")

# Bytes that are likely to vary across builds (relocated immediates).
# We mask them aggressively so a signature trained on Debian glibc still
# matches the same function on a musl build.
#
# x86_64 instruction-bytes that often hold relocatable operands:
#   E8 <rel32>    call
#   E9 <rel32>    jmp
#   0F 8X <rel32> conditional jumps
#   48 8B 0D <rel32>  mov rcx, [rip+disp]
#   48 8D 0D <rel32>  lea rcx, [rip+disp]
# We don't try to parse the instruction stream; instead we apply a
# best-effort heuristic: any byte that decodes as a likely-rip-relative
# operand gets masked. This is implemented in `mask_relocatable_x86_64`.

# Functions whose names we want to lift. Trimmed deliberately —
# matching too many tiny helpers produces noise (their prefixes collide).
# 200 high-signal names from libc + libssl + zlib + curl are enough to
# rename the bulk of static-link calls in real binaries.
_WANTED_NAMES = {
    # libc — strings / mem
    "memcpy", "memmove", "memset", "memcmp", "memchr",
    "strlen", "strnlen", "strcpy", "strncpy", "strdup", "strndup",
    "strcat", "strncat", "strcmp", "strncmp", "strcasecmp", "strncasecmp",
    "strchr", "strrchr", "strstr", "strtok", "strtok_r", "strspn", "strcspn",
    "strpbrk", "strerror", "snprintf", "sprintf", "vsnprintf", "vsprintf",
    "printf", "fprintf", "vprintf", "vfprintf",
    # libc — io
    "open", "openat", "close", "read", "write", "lseek", "pread", "pwrite",
    "fopen", "fopen64", "fread", "fwrite", "fclose", "fseek", "ftell",
    "fputs", "fputc", "fgets", "fgetc", "fflush", "feof", "ferror",
    # libc — alloc
    "malloc", "free", "calloc", "realloc", "aligned_alloc", "posix_memalign",
    # libc — exit / env
    "exit", "_exit", "abort", "atexit", "getenv", "setenv", "unsetenv",
    "system", "execve", "execvp", "execv", "fork", "wait", "waitpid",
    # libc — conversions
    "atoi", "atol", "atoll", "atof", "strtol", "strtoll", "strtoul",
    "strtoull", "strtod", "strtof",
    # libc — sort / search
    "qsort", "qsort_r", "bsearch",
    # libc — sockets
    "socket", "bind", "listen", "accept", "accept4", "connect",
    "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg",
    "getaddrinfo", "freeaddrinfo", "getnameinfo", "gethostbyname",
    "setsockopt", "getsockopt", "shutdown", "select", "poll", "epoll_wait",
    # libc — pthreads
    "pthread_create", "pthread_join", "pthread_detach",
    "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_init",
    "pthread_cond_wait", "pthread_cond_signal", "pthread_cond_broadcast",
    "pthread_self", "pthread_exit",
    # libc — signals / time
    "signal", "sigaction", "raise", "kill",
    "gettimeofday", "clock_gettime", "nanosleep", "usleep", "sleep",
    "time", "localtime", "gmtime", "mktime", "strftime", "strptime",
    # libssl / libcrypto (OpenSSL)
    "SSL_new", "SSL_free", "SSL_connect", "SSL_accept", "SSL_read", "SSL_write",
    "SSL_CTX_new", "SSL_CTX_free", "SSL_load_error_strings", "SSL_library_init",
    "TLS_method", "TLS_client_method", "TLS_server_method",
    "EVP_MD_CTX_new", "EVP_MD_CTX_free", "EVP_DigestInit_ex", "EVP_DigestUpdate",
    "EVP_DigestFinal_ex", "EVP_sha256", "EVP_sha1", "EVP_md5",
    "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex",
    "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex",
    "AES_set_encrypt_key", "AES_set_decrypt_key", "AES_encrypt", "AES_decrypt",
    "RSA_new", "RSA_free", "RSA_public_encrypt", "RSA_private_decrypt",
    "X509_new", "X509_free", "X509_NAME_oneline", "X509_verify_cert",
    "BIO_new", "BIO_free", "BIO_read", "BIO_write",
    # zlib
    "deflate", "deflateInit_", "deflateInit2_", "deflateEnd",
    "inflate", "inflateInit_", "inflateInit2_", "inflateEnd",
    "compress", "compress2", "uncompress", "crc32", "adler32",
    "gzopen", "gzread", "gzwrite", "gzclose",
    # curl
    "curl_easy_init", "curl_easy_setopt", "curl_easy_perform",
    "curl_easy_cleanup", "curl_easy_strerror", "curl_global_init",
    "curl_global_cleanup", "curl_slist_append", "curl_slist_free_all",
    # mobile-relevant
    "JNI_OnLoad", "JNI_OnUnload",
    "objc_msgSend", "objc_retain", "objc_release", "objc_autorelease",
    "_objc_msgSend",
}


def mask_relocatable_x86_64(prefix: bytes, n: int = SIG_BYTES) -> bytes:
    """Return a mask covering `n` bytes. Best-effort: null the operand of
    obvious rip-relative or call/jmp instructions so cross-distro variants
    of the same function still match.

    This is intentionally simple — a full instruction decoder would close
    a few more false negatives but adds capstone as a runtime dep. The
    current rules cover the bulk of glibc/musl variation we see in
    practice.
    """
    mask = bytearray(b"\xff" * min(n, len(prefix)))
    i = 0
    while i < len(mask):
        b = prefix[i] if i < len(prefix) else 0
        # E8/E9 + 4-byte relative immediate.
        if b in (0xE8, 0xE9):
            for k in range(1, 5):
                if i + k < len(mask):
                    mask[i + k] = 0
            i += 5
            continue
        # 0F 8X conditional jumps + 4-byte relative.
        if b == 0x0F and i + 1 < len(prefix) and 0x80 <= prefix[i + 1] <= 0x8F:
            for k in range(2, 6):
                if i + k < len(mask):
                    mask[i + k] = 0
            i += 6
            continue
        # REX.W + 8B/8D /[mod 0b00 r/m 0b101]   (rip+disp32 mem op)
        if b in (0x48, 0x4C) and i + 2 < len(prefix):
            op = prefix[i + 1]
            modrm = prefix[i + 2]
            if op in (0x8B, 0x8D) and (modrm & 0xC7) == 0x05:
                for k in range(3, 7):
                    if i + k < len(mask):
                        mask[i + k] = 0
                i += 7
                continue
        i += 1
    return bytes(mask)


def _arch_for_elf(elf) -> str:
    machine = elf.header["e_machine"]
    return {
        "EM_X86_64": "x86_64",
        "EM_386": "x86",
        "EM_AARCH64": "aarch64",
        "EM_ARM": "arm",
    }.get(machine, machine.lower())


def collect_elf_signatures(library: Path, lib_name: str) -> list[Signature]:
    """Read every wanted function symbol from `library` and emit signatures."""
    from elftools.elf.elffile import ELFFile

    sigs: list[Signature] = []
    with open(library, "rb") as fh:
        elf = ELFFile(fh)
        arch = _arch_for_elf(elf)
        symtab = elf.get_section_by_name(".dynsym") or elf.get_section_by_name(".symtab")
        if symtab is None:
            logger.warning("%s has no symbol table; skipping", library)
            return sigs

        for sym in symtab.iter_symbols():
            name = sym.name
            if not name or name not in _WANTED_NAMES:
                continue
            if sym["st_info"]["type"] != "STT_FUNC":
                continue
            addr = sym["st_value"]
            size = sym["st_size"]
            if addr == 0 or size < 8:
                # Imported PLT stubs sit at addr=0; tiny shims would
                # produce noisy false-positive matches.
                continue

            data = _read_bytes_at_vaddr(elf, fh, addr, SIG_BYTES)
            if not data or len(data) < 4:
                continue
            mask = mask_relocatable_x86_64(data, SIG_BYTES) if arch == "x86_64" else b"\xff" * len(data)
            sigs.append(Signature(
                name=name, lib=lib_name, size=size,
                bytes_=data, mask=mask, arch=arch, format="elf",
            ))
    return sigs


def _read_bytes_at_vaddr(elf, fh, vaddr: int, length: int) -> bytes | None:
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        vstart = seg["p_vaddr"]
        vsize = seg["p_filesz"]
        if vstart <= vaddr < vstart + vsize:
            file_offset = seg["p_offset"] + (vaddr - vstart)
            fh.seek(file_offset)
            return fh.read(length)
    return None


def collect_pe_signatures(library: Path, lib_name: str) -> list[Signature]:
    """Walk a PE's export directory; emit signatures for wanted names."""
    import pefile
    sigs: list[Signature] = []
    pe = pefile.PE(str(library), fast_load=False)
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return sigs
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name is None:
                continue
            name = exp.name.decode(errors="replace")
            if name not in _WANTED_NAMES:
                continue
            try:
                data = pe.get_data(exp.address, SIG_BYTES)
            except Exception:
                continue
            if len(data) < 4:
                continue
            mask = mask_relocatable_x86_64(data, SIG_BYTES)
            sigs.append(Signature(
                name=name, lib=lib_name, size=0,
                bytes_=data, mask=mask, arch="x86_64", format="pe",
            ))
    finally:
        pe.close()
    return sigs


def main() -> int:
    ap = argparse.ArgumentParser(description="Build Chimera function signature packs.")
    ap.add_argument("--library", action="append", required=True,
                    help="Path to a shared library or static archive (repeatable).")
    ap.add_argument("--out", type=Path, required=True, help="Output JSON path.")
    ap.add_argument("--pack-name", default="library-pack",
                    help="Logical name recorded in the pack metadata.")
    ap.add_argument("--format", choices=("elf", "pe"), default="elf",
                    help="Binary format for the input libraries.")
    ap.add_argument("--lib-name", default=None,
                    help="Override the lib= field on emitted signatures.")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    all_sigs: list[Signature] = []
    for lib_path_str in args.library:
        lib_path = Path(lib_path_str)
        if not lib_path.exists():
            logger.warning("missing library: %s", lib_path)
            continue
        lib_name = args.lib_name or lib_path.stem
        if args.format == "elf":
            sigs = collect_elf_signatures(lib_path, lib_name)
        else:
            sigs = collect_pe_signatures(lib_path, lib_name)
        logger.info("  %s -> %d signatures", lib_path.name, len(sigs))
        all_sigs.extend(sigs)

    written = dump_signature_pack(all_sigs, args.out, args.pack_name)
    logger.info("wrote %d signatures to %s", written, args.out)
    return 0 if written else 1


if __name__ == "__main__":
    sys.exit(main())
