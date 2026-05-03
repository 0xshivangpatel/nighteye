"""PE/Windows executable digital signature check.

Checks whether a Windows PE file (.exe, .dll, .sys, .scr, .msi)
has a digital signature. Unsigned executables are far more likely
to be malware — legitimate software is almost always signed.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("nighteye.ingest.pe_signer")

# Market cap / trust anchors: well-known signing authorities whose
# signatures indicate a legitimate binary.
_KNOWN_SIGNER_SUBSTRINGS: frozenset[str] = frozenset({
    "microsoft corporation", "microsoft windows",
    "google inc", "google llc",
    "intel corporation",
    "amd",
    "nvidia corporation",
    "adobe systems", "adobe inc",
    "oracle", "java",
    "vmware", "vmware inc",
    "citrix",
    "dropbox",
    "mozilla corporation",
    "apple inc",
    "hewlett-packard", "hp inc",
    "dell inc", "dell technologies",
    "lenovo",
    "samsung",
    "realtek semiconductor",
    "broadcom",
    "qualcomm",
    "western digital", "seagate",
    "symantec", "mcafee", "trend micro", "crowdstrike", "sentinelone",
    "cisco", "juniper", "fortinet",
    "logitech",
    "autodesk",
    "salesforce",
    "slack technologies",
    "zoom video",
    "teamviewer",
    "anydesk",
    "tableau",
    "atlassian",
    "github",
    "git",
    "python software foundation",
    "apache",
    "canonical",  # Ubuntu
    "red hat",
    "suse",
])

# PE file extensions eligible for signature check
_PE_EXTENSIONS: frozenset[str] = frozenset({".exe", ".dll", ".sys", ".scr", ".msi"})


def _find_security_directory(pe) -> tuple[int, int] | None:
    """Locate IMAGE_DIRECTORY_ENTRY_SECURITY (virtual address, size)."""
    try:
        if not hasattr(pe, "OPTIONAL_HEADER") or pe.OPTIONAL_HEADER is None:
            return None
    except Exception:
        return None
    oh = pe.OPTIONAL_HEADER
    for attr in (
        "DATA_DIRECTORY",
        "IMAGE_DATA_DIRECTORY",               # pefile 2023.x
        "IMAGE_OPTIONAL_HEADER64",             # PE32+ fallback
    ):
        dd = getattr(oh, attr, None)
        if dd is None:
            continue
        if isinstance(dd, list):
            for entry in dd:
                if hasattr(entry, "name") and "security" in str(entry.name).lower():
                    return (entry.VirtualAddress, entry.Size)
        elif hasattr(dd, "IMAGE_DIRECTORY_ENTRY_SECURITY"):
            sec = dd.IMAGE_DIRECTORY_ENTRY_SECURITY
            return (sec.VirtualAddress, sec.Size)
    return None


def has_known_signer(path: Path) -> bool | None:
    """Check whether a PE file is signed by a known vendor.

    Returns:
        True  — signed by a known-good vendor (Microsoft, Google, etc.)
        False — file has no signature or is signed by an unknown entity
        None  — could not determine (pefile not installed, not a PE file)
    """
    ext = path.suffix.lower()
    if ext not in _PE_EXTENSIONS:
        return None  # Not a PE — signature check not applicable

    try:
        import pefile
    except ImportError:
        logger.debug("pefile not installed; skipping signature check")
        return None

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError:
        return None
    except Exception:
        logger.debug("Failed to parse PE: %s", path.name)
        return None

    # Parse security directory for Authenticode info
    sec_dir = _find_security_directory(pe)
    if sec_dir is None:
        # No digital signature at all
        pe.close()
        return False

    # Try to extract signer from certificate table
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])
    except Exception:
        pe.close()
        return None  # Couldn't parse certs, can't determine

    try:
        signer = extract_signer_from_pe(pe)
    except Exception:
        signer = None

    pe.close()

    if not signer:
        return False  # No signer extracted — unsigned or unparseable

    signer_lower = signer.lower()
    for known in _KNOWN_SIGNER_SUBSTRINGS:
        if known in signer_lower:
            return True

    return False  # Signed, but by unknown entity


def extract_signer_from_pe(pe) -> str | None:
    """Try to extract the certificate signer name."""
    try:
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
    except (AttributeError, IndexError, KeyError):
        return None

    if security is None or security.VirtualAddress == 0:
        return None

    try:
        offset = pe.get_offset_from_rva(security.VirtualAddress)
    except Exception:
        return None

    if offset is None:
        return None

    try:
        sig_data = pe.__data__[offset: offset + security.Size]
    except Exception:
        return None

    # Extract DER-encoded certificates embedded in WIN_CERTIFICATE structure
    # Format: dwLength (4) + wRevision (2) + wCertificateType (2) + cert[]
    import struct

    pos = 0
    while pos + 8 <= len(sig_data):
        length, revision, cert_type = struct.unpack_from("<IHH", sig_data, pos)
        if length < 8 or pos + length > len(sig_data):
            break
        if revision == 0x0200 and cert_type == 0x0002:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
            cert_der = sig_data[pos + 8: pos + length]
            # Parse X.509 subject field from certificate
            signer = _parse_x509_subject(cert_der)
            if signer:
                return signer
        pos += 8 + (length - 8)
    return None


def _parse_x509_subject(cert_der: bytes, max_depth: int = 4) -> str | None:
    """Extract CN (Common Name) from DER-encoded X.509 certificate.

    Uses a minimal ASN.1 parser so we don't require cryptography/pyasn1.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        for attr in cert.subject:
            if attr.oid._name == "commonName":
                return attr.value
        return str(cert.subject)
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: crude DER parser for commonName
    return _crude_parse_cn(cert_der, max_depth)


def _crude_parse_cn(data: bytes, depth: int) -> str | None:
    """Crude DER X.509 CN extractor."""
    import struct

    cn_bytes = b"commonName"
    pos = 0
    while pos < len(data):
        try:
            # Find SET/SEQUENCE with commonName OID
            if data[pos:pos + 2] == b"\x31\x0b":  # SET of length 11
                seq = data[pos + 2:pos + 2 + 11]
                if cn_bytes in seq:
                    # Find the string value that follows
                    for i in range(len(seq)):
                        if seq[i:i + len(cn_bytes)] == cn_bytes:
                            # Look for printable string or UTF8 string after OID
                            after = seq[i + len(cn_bytes):]
                            for tag in (0x0C, 0x13, 0x16, 0x1E):  # UTF8, Printable, IA5, BMP
                                if after and after[0] == tag:
                                    strlen = after[1]
                                    if strlen <= len(after) - 2:
                                        return after[2:2 + strlen].decode("utf-8", errors="ignore")
        except Exception:
            pass
        pos += 1
    return None


def is_unsigned_pe(path: Path) -> bool:
    """Quick check: return True if this is an unsigned PE executable.

    Returns True when we're confident the file is unsigned (keep it).
    Returns False when the file is signed by a known vendor (skip it)
    or when we can't determine (keep it — false negatives are worse).
    """
    result = has_known_signer(path)
    if result is True:
        return False  # Signed by known vendor → skip
    return True  # Unsigned or unknown → keep
