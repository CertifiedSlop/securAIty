"""
Security Utilities

Common security utility functions for input validation, output encoding,
injection prevention, and secure data handling following OWASP guidelines.
"""

import html
import os
import re
import secrets
import string
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Set

from .exceptions import SecurityValidationError


SECURE_TOKEN_CHARS = string.ascii_letters + string.digits + "-_"
EMAIL_PATTERN: Pattern = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)
USERNAME_PATTERN: Pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{2,31}$")
DANGEROUS_CHARS_PATTERN: Pattern = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]"
)
SQL_KEYWORDS_PATTERN: Pattern = re.compile(
    r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|TRUNCATE|GRANT|REVOKE)\b",
    re.IGNORECASE,
)
SQL_COMMENT_PATTERN: Pattern = re.compile(r"(--|#|/\*)")
OPEN_REDIRECT_PATTERNS: List[Pattern] = [
    re.compile(r"^//", re.IGNORECASE),
    re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", re.IGNORECASE),
    re.compile(r"^\\", re.IGNORECASE),
]


def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure URL-safe random token.

    Uses Python's secrets module for secure random number generation.
    Suitable for CSRF tokens, session identifiers, and password reset tokens.

    Args:
        length: Token length in bytes (default: 32)

    Returns:
        URL-safe random token string

    Raises:
        SecurityValidationError: If length is invalid
    """
    if length < 16 or length > 256:
        raise SecurityValidationError("Token length must be between 16 and 256 bytes")

    token_bytes = secrets.token_urlsafe(length)
    return token_bytes


def sanitize_input(text: str) -> str:
    """
    Remove dangerous control characters from input.

    Strips null bytes, control characters, and other non-printable
    characters that could be used for injection or bypass attacks.

    Args:
        text: Input text to sanitize

    Returns:
        Sanitized text with dangerous characters removed

    Raises:
        SecurityValidationError: If input is None or empty
    """
    if text is None:
        raise SecurityValidationError("Input cannot be None")

    if not isinstance(text, str):
        text = str(text)

    if not text.strip():
        raise SecurityValidationError("Input cannot be empty")

    sanitized = DANGEROUS_CHARS_PATTERN.sub("", text)
    sanitized = " ".join(sanitized.split())

    return sanitized


def prevent_xss(text: str) -> str:
    """
    HTML escape text to prevent Cross-Site Scripting (XSS) attacks.

    Converts dangerous HTML characters to their entity equivalents:
    - & becomes &amp;
    - < becomes &lt;
    - > becomes &gt;
    - " becomes &quot;
    - ' becomes &#x27;

    Suitable for HTML body context output encoding per OWASP guidelines.

    Args:
        text: Untrusted text to escape

    Returns:
        HTML-escaped text safe for rendering

    Raises:
        SecurityValidationError: If input is None
    """
    if text is None:
        raise SecurityValidationError("Input cannot be None")

    if not isinstance(text, str):
        text = str(text)

    return html.escape(text, quote=True)


def prevent_xss_attribute(text: str) -> str:
    """
    Encode text for safe use in HTML attributes.

    Uses hexadecimal entity encoding for all non-alphanumeric characters
    as recommended by OWASP for attribute context encoding.

    Args:
        text: Untrusted text to encode

    Returns:
        Attribute-encoded text

    Raises:
        SecurityValidationError: If input is None
    """
    if text is None:
        raise SecurityValidationError("Input cannot be None")

    if not isinstance(text, str):
        text = str(text)

    result = []
    for char in text:
        if char.isalnum():
            result.append(char)
        else:
            result.append(f"&#x{ord(char):02X};")

    return "".join(result)


def prevent_sql_injection(text: str) -> str:
    """
    Validate and escape text for SQL context.

    Note: This is a secondary defense. Primary defense should be
    parameterized queries/prepared statements. This function provides
    additional validation by detecting SQL injection patterns.

    Args:
        text: Input text to validate/escape

    Returns:
        Escaped text with SQL keywords neutralized

    Raises:
        SecurityValidationError: If dangerous SQL patterns detected
    """
    if text is None:
        raise SecurityValidationError("Input cannot be None")

    if not isinstance(text, str):
        text = str(text)

    sanitized = sanitize_input(text)

    if SQL_COMMENT_PATTERN.search(sanitized):
        raise SecurityValidationError("SQL comments are not allowed")

    if SQL_KEYWORDS_PATTERN.search(sanitized):
        raise SecurityValidationError("SQL keywords are not allowed in input")

    escaped = sanitized.replace("'", "''")
    escaped = escaped.replace("\\", "\\\\")

    return escaped


def validate_email(email: str) -> bool:
    """
    Validate email format according to RFC 5322 simplified pattern.

    Checks for:
    - Valid local part (before @)
    - Valid domain part (after @)
    - Proper TLD (at least 2 characters)
    - No consecutive dots
    - No leading/trailing dots in local or domain parts

    Args:
        email: Email address to validate

    Returns:
        True if email format is valid, False otherwise
    """
    if email is None or not isinstance(email, str):
        return False

    if len(email) > 254:
        return False

    if not EMAIL_PATTERN.match(email):
        return False

    local_part, domain_part = email.rsplit("@", 1)

    if local_part.startswith(".") or local_part.endswith("."):
        return False
    if ".." in local_part:
        return False

    if domain_part.startswith(".") or domain_part.endswith("."):
        return False
    if ".." in domain_part:
        return False

    labels = domain_part.split(".")
    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            return False
        if not label:
            return False

    return True


def validate_username(username: str) -> bool:
    """
    Validate username according to security rules.

    Rules:
    - Must start with a letter (a-z, A-Z)
    - Length: 3-32 characters
    - Allowed characters: letters, numbers, underscore, hyphen
    - No consecutive underscores or hyphens
    - Cannot end with underscore or hyphen

    Args:
        username: Username to validate

    Returns:
        True if username is valid, False otherwise
    """
    if username is None or not isinstance(username, str):
        return False

    if len(username) < 3 or len(username) > 32:
        return False

    if not USERNAME_PATTERN.match(username):
        return False

    if username.endswith("_") or username.endswith("-"):
        return False

    if "__" in username or "--" in username:
        return False

    return True


def rate_limit_key(identifier: str, prefix: str = "rate_limit") -> str:
    """
    Generate cache key for rate limiting.

    Creates a consistent, safe cache key suitable for Redis or
    other caching systems. Sanitizes input to prevent null byte
    injection and normalizes identifiers.

    Args:
        identifier: Unique identifier (user_id, IP, API key)
        prefix: Key prefix for namespacing (default: "rate_limit")

    Returns:
        Formatted cache key string

    Raises:
        SecurityValidationError: If identifier is empty
    """
    if not identifier:
        raise SecurityValidationError("Identifier cannot be empty")

    safe_identifier = identifier.replace("\x00", "").strip()

    if len(safe_identifier) > 256:
        safe_identifier = sha256_hex(safe_identifier.encode())
    else:
        safe_identifier = re.sub(r"[^a-z0-9._-]", "_", safe_identifier.lower())

    return f"{prefix}:{safe_identifier}"


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.

    Uses secrets.compare_digest which is designed to prevent
    timing analysis attacks by ensuring comparison takes the same
    amount of time regardless of where the difference occurs.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    return secrets.compare_digest(a, b)


def constant_time_compare_str(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Args:
        a: First string
        b: Second string

    Returns:
        True if equal, False otherwise
    """
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def mask_sensitive_data(
    data: str,
    mask_char: str = "*",
    visible_start: int = 2,
    visible_end: int = 4,
) -> str:
    """
    Mask sensitive data for safe logging and display.

    Shows only the first and last few characters with masked
    characters in between. Suitable for passwords, tokens,
    API keys, and credit card numbers.

    Args:
        data: Sensitive data to mask
        mask_char: Character to use for masking (default: *)
        visible_start: Number of characters to show at start
        visible_end: Number of characters to show at end

    Returns:
        Masked string

    Raises:
        SecurityValidationError: If data is None or empty
    """
    if data is None:
        raise SecurityValidationError("Data cannot be None")

    if not isinstance(data, str):
        data = str(data)

    if not data:
        raise SecurityValidationError("Data cannot be empty")

    data_length = len(data)

    if data_length <= visible_start + visible_end:
        return mask_char * data_length

    masked_length = data_length - visible_start - visible_end
    return f"{data[:visible_start]}{mask_char * masked_length}{data[-visible_end:]}"


def mask_email(email: str) -> str:
    """
    Mask email address for privacy.

    Shows first character of local part and domain, masks the rest.
    Example: john.doe@example.com becomes j******@e******.com

    Args:
        email: Email address to mask

    Returns:
        Masked email string

    Raises:
        SecurityValidationError: If email is invalid
    """
    if not validate_email(email):
        raise SecurityValidationError("Invalid email format")

    local_part, domain_part = email.rsplit("@", 1)
    domain_name, tld = domain_part.rsplit(".", 1)

    masked_local = f"{local_part[0]}{'*' * (len(local_part) - 1)}" if local_part else ""
    masked_domain = f"{domain_name[0]}{'*' * (len(domain_name) - 1)}" if domain_name else ""

    return f"{masked_local}@{masked_domain}.{tld}"


def is_safe_redirect_url(url: str, allowed_hosts: Optional[List[str]] = None) -> bool:
    """
    Validate redirect URL to prevent open redirect vulnerabilities.

    Checks for:
    - Protocol-relative URLs (//example.com)
    - Absolute URLs with different host
    - Backslash-based bypasses
    - JavaScript/data URLs
    - Host not in allowed list

    Args:
        url: URL to validate for redirect
        allowed_hosts: List of allowed hostnames (default: empty)

    Returns:
        True if URL is safe for redirect, False otherwise
    """
    if url is None or not isinstance(url, str):
        return False

    url = url.strip()

    if not url:
        return False

    url_lower = url.lower()
    if url_lower.startswith(("javascript:", "data:", "vbscript:")):
        return False

    for pattern in OPEN_REDIRECT_PATTERNS:
        if pattern.match(url):
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname:
                if allowed_hosts:
                    return parsed.hostname.lower() in [h.lower() for h in allowed_hosts]
                return False

    if url.startswith("/"):
        if url.startswith("//"):
            return False
        if not url.startswith("/\\"):
            return True

    if allowed_hosts:
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname:
                return parsed.hostname.lower() in [h.lower() for h in allowed_hosts]
        except Exception:
            return False

    return True


def validate_url(url: str, allowed_schemes: Optional[List[str]] = None) -> bool:
    """
    Validate URL format and scheme.

    Args:
        url: URL to validate
        allowed_schemes: List of allowed URL schemes (default: http, https)

    Returns:
        True if URL is valid, False otherwise
    """
    if url is None or not isinstance(url, str):
        return False

    url = url.strip()

    if not url:
        return False

    if len(url) > 2048:
        return False

    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False

    if not parsed.scheme:
        return False

    if parsed.scheme.lower() not in [s.lower() for s in allowed_schemes]:
        return False

    if not parsed.netloc:
        return False

    return True


def normalize_path(path: str) -> str:
    """
    Normalize file path to prevent directory traversal.

    Resolves .., removes duplicate slashes, and ensures
    path doesn't escape intended directory.

    Args:
        path: File path to normalize

    Returns:
        Normalized path

    Raises:
        SecurityValidationError: If path is invalid or dangerous
    """
    if path is None:
        raise SecurityValidationError("Path cannot be None")

    if not isinstance(path, str):
        path = str(path)

    path = path.strip()

    if not path:
        raise SecurityValidationError("Path cannot be empty")

    normalized = os.path.normpath(path)

    if normalized.startswith("..") or "/../" in path or "\\..\\" in path:
        raise SecurityValidationError("Path traversal detected")

    return normalized


def is_safe_path(base_path: str, user_path: str) -> bool:
    """
    Check if user_path is within base_path to prevent path traversal.

    Resolves both paths to absolute paths and verifies that the
    user-provided path is contained within the allowed base path.
    This prevents directory traversal attacks where users attempt
    to access files outside the intended directory.

    Args:
        base_path: Base directory path that should contain all access
        user_path: User-provided path to validate

    Returns:
        True if user_path is safely within base_path, False otherwise
    """
    try:
        base = Path(base_path).resolve()
        user = Path(user_path).resolve()
        user.relative_to(base)
        return True
    except (ValueError, RuntimeError):
        return False


def validate_content_type(content_type: str, allowed_types: Optional[List[str]] = None) -> bool:
    """
    Validate Content-Type header to prevent injection attacks.

    Args:
        content_type: Content-Type header value
        allowed_types: List of allowed MIME types

    Returns:
        True if content type is valid, False otherwise
    """
    if content_type is None or not isinstance(content_type, str):
        return False

    content_type = content_type.strip().lower()

    if not content_type:
        return False

    if ";" in content_type:
        content_type = content_type.split(";")[0].strip()

    if allowed_types is None:
        allowed_types = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
        ]

    return content_type in allowed_types


def generate_csrf_token() -> str:
    """
    Generate cryptographically secure CSRF token.

    Returns:
        32-byte URL-safe CSRF token
    """
    return generate_secure_token(32)


def validate_csrf_token(token: str, expected_token: str) -> bool:
    """
    Validate CSRF token using constant-time comparison.

    Args:
        token: Token to validate
        expected_token: Expected token value

    Returns:
        True if tokens match, False otherwise
    """
    if not token or not expected_token:
        return False

    return constant_time_compare_str(token, expected_token)


def strip_null_bytes(data: bytes) -> bytes:
    """
    Remove null bytes from binary data.

    Useful for preventing null byte injection attacks.

    Args:
        data: Binary data to strip

    Returns:
        Data with null bytes removed
    """
    return data.replace(b"\x00", b"")


def strip_null_bytes_str(data: str) -> str:
    """
    Remove null bytes from string.

    Args:
        data: String to strip

    Returns:
        String with null bytes removed
    """
    return data.replace("\x00", "")


def is_ipv4_address(ip: str) -> bool:
    """
    Validate IPv4 address format.

    Args:
        ip: IP address to validate

    Returns:
        True if valid IPv4 address, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False

    parts = ip.split(".")

    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False

        num = int(part)

        if num < 0 or num > 255:
            return False

        if len(part) > 1 and part.startswith("0"):
            return False

    return True


def is_ipv6_address(ip: str) -> bool:
    """
    Validate IPv6 address format.

    Args:
        ip: IP address to validate

    Returns:
        True if valid IPv6 address, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False

    try:
        import ipaddress
        ipaddress.IPv6Address(ip)
        return True
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe filesystem operations.

    Removes or replaces dangerous characters that could be
    used for path traversal or command injection.

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename

    Raises:
        SecurityValidationError: If filename is invalid
    """
    if not filename or not isinstance(filename, str):
        raise SecurityValidationError("Filename cannot be empty")

    filename = filename.strip()

    if not filename:
        raise SecurityValidationError("Filename cannot be empty")

    reserved_names = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
                      "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
                      "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}

    name_without_ext = filename.rsplit(".", 1)[0].upper()
    if name_without_ext in reserved_names:
        raise SecurityValidationError("Reserved filename not allowed")

    dangerous_chars = ["<", ">", ":", '"', "|", "?", "*", "\x00"]
    for char in dangerous_chars:
        filename = filename.replace(char, "_")

    filename = re.sub(r"[/\\]+", "_", filename)

    filename = filename.strip(". ")

    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = f"{name[:255-len(ext)]}{ext}"

    return filename

