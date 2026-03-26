"""
Unit tests for security utilities in securAIty security module.

Tests cover input sanitization, XSS prevention, SQL injection detection,
email/username validation, data masking, and redirect URL validation.
"""

import pytest

from securAIty.security.exceptions import SecurityValidationError
from securAIty.security.utils import (
    constant_time_compare,
    constant_time_compare_str,
    generate_csrf_token,
    generate_secure_token,
    is_ipv4_address,
    is_ipv6_address,
    is_safe_redirect_url,
    mask_email,
    mask_sensitive_data,
    normalize_path,
    prevent_sql_injection,
    prevent_xss,
    prevent_xss_attribute,
    rate_limit_key,
    sanitize_filename,
    sanitize_input,
    strip_null_bytes,
    strip_null_bytes_str,
    validate_content_type,
    validate_csrf_token,
    validate_email,
    validate_url,
    validate_username,
)


class TestGenerateSecureToken:
    """Tests for generate_secure_token function."""

    def test_generate_secure_token_returns_url_safe_string(self) -> None:
        """Returns URL-safe random string."""
        token = generate_secure_token(32)

        assert isinstance(token, str)
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in token)

    def test_generate_secure_token_default_length(self) -> None:
        """Uses default length of 32 bytes."""
        token = generate_secure_token()
        assert len(token) >= 32

    def test_generate_secure_token_custom_length(self) -> None:
        """Respects custom length parameter."""
        token = generate_secure_token(64)
        assert len(token) >= 64

    def test_generate_secure_token_different_each_call(self) -> None:
        """Returns different tokens on each call."""
        tokens = [generate_secure_token(32) for _ in range(50)]
        unique_tokens = set(tokens)
        assert len(unique_tokens) == 50

    def test_generate_secure_token_length_too_low_raises_error(self) -> None:
        """Length below 16 raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="must be between"):
            generate_secure_token(8)

    def test_generate_secure_token_length_too_high_raises_error(self) -> None:
        """Length above 256 raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="must be between"):
            generate_secure_token(300)


class TestSanitizeInput:
    """Tests for sanitize_input function."""

    def test_sanitize_input_removes_control_characters(self) -> None:
        """Removes dangerous control characters."""
        input_text = "Hello\x00World\x01Test"
        result = sanitize_input(input_text)
        assert "\x00" not in result
        assert "\x01" not in result
        assert "HelloWorldTest" in result

    def test_sanitize_input_removes_null_bytes(self) -> None:
        """Removes null bytes from input."""
        input_text = "test\x00data"
        result = sanitize_input(input_text)
        assert "\x00" not in result
        assert "testdata" in result

    def test_sanitize_input_normalizes_whitespace(self) -> None:
        """Normalizes multiple whitespace to single space."""
        input_text = "Hello    World\n\nTest"
        result = sanitize_input(input_text)
        assert "Hello World Test" == result

    def test_sanitize_input_none_raises_error(self) -> None:
        """None input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be None"):
            sanitize_input(None)

    def test_sanitize_input_empty_string_raises_error(self) -> None:
        """Empty string raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be empty"):
            sanitize_input("")

    def test_sanitize_input_whitespace_only_raises_error(self) -> None:
        """Whitespace-only string raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be empty"):
            sanitize_input("   ")

    def test_sanitize_input_non_string_converts(self) -> None:
        """Converts non-string input to string."""
        result = sanitize_input(12345)
        assert result == "12345"


class TestPreventXss:
    """Tests for prevent_xss function."""

    def test_prevent_xss_escapes_script_tags(self) -> None:
        """Escapes HTML special characters."""
        input_text = "<script>alert('XSS')</script>"
        result = prevent_xss(input_text)
        assert "<" not in result
        assert ">" not in result
        assert "&lt;script&gt;" in result

    def test_prevent_xss_escapes_quotes(self) -> None:
        """Escapes quote characters."""
        input_text = '"onclick"=\'test\''
        result = prevent_xss(input_text)
        assert "&quot;" in result
        assert "&#x27;" in result

    def test_prevent_xss_escapes_ampersand(self) -> None:
        """Escapes ampersand characters."""
        input_text = "Tom & Jerry"
        result = prevent_xss(input_text)
        assert "&amp;" in result

    def test_prevent_xss_none_raises_error(self) -> None:
        """None input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be None"):
            prevent_xss(None)

    def test_prevent_xss_non_string_converts(self) -> None:
        """Converts non-string input to string."""
        result = prevent_xss(123)
        assert "123" in result

    def test_prevent_xss_safe_input_unchanged_except_entities(self) -> None:
        """Safe input preserved with proper escaping."""
        input_text = "Hello World"
        result = prevent_xss(input_text)
        assert result == "Hello World"


class TestPreventXssAttribute:
    """Tests for prevent_xss_attribute function."""

    def test_prevent_xss_attribute_encodes_special_chars(self) -> None:
        """Encodes special characters with hex entities."""
        input_text = '<>"&'
        result = prevent_xss_attribute(input_text)
        assert "&#x" in result

    def test_prevent_xss_attribute_preserves_alphanumeric(self) -> None:
        """Preserves alphanumeric characters."""
        input_text = "abc123XYZ"
        result = prevent_xss_attribute(input_text)
        assert result == "abc123XYZ"

    def test_prevent_xss_attribute_none_raises_error(self) -> None:
        """None input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be None"):
            prevent_xss_attribute(None)


class TestPreventSqlInjection:
    """Tests for prevent_sql_injection function."""

    def test_prevent_sql_injection_detects_union_select(self) -> None:
        """Detects UNION SELECT pattern."""
        input_text = "1 UNION SELECT * FROM users"
        with pytest.raises(SecurityValidationError, match="SQL keywords"):
            prevent_sql_injection(input_text)

    def test_prevent_sql_injection_detects_drop_table(self) -> None:
        """Detects DROP TABLE pattern."""
        input_text = "'; DROP TABLE users; --"
        with pytest.raises(SecurityValidationError, match="SQL keywords"):
            prevent_sql_injection(input_text)

    def test_prevent_sql_injection_detects_sql_comments(self) -> None:
        """Detects SQL comment patterns."""
        input_text = "admin'--"
        with pytest.raises(SecurityValidationError, match="SQL comments"):
            prevent_sql_injection(input_text)

    def test_prevent_sql_injection_escapes_single_quotes(self) -> None:
        """Escapes single quotes."""
        input_text = "O'Brien"
        result = prevent_sql_injection(input_text)
        assert "O''Brien" == result

    def test_prevent_sql_injection_escapes_backslashes(self) -> None:
        """Escapes backslashes."""
        input_text = "path\\to\\file"
        result = prevent_sql_injection(input_text)
        assert "path\\\\to\\\\file" == result

    def test_prevent_sql_injection_none_raises_error(self) -> None:
        """None input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be None"):
            prevent_sql_injection(None)

    def test_prevent_sql_injection_safe_input_returns_escaped(self) -> None:
        """Safe input is returned escaped."""
        input_text = "normal text input"
        result = prevent_sql_injection(input_text)
        assert result == "normal text input"


class TestValidateEmail:
    """Tests for validate_email function."""

    def test_validate_email_valid_emails(self) -> None:
        """Validates valid email addresses."""
        valid_emails = [
            "test@example.com",
            "user.name@domain.org",
            "user+tag@example.co.uk",
            "test123@test-domain.com",
        ]
        for email in valid_emails:
            assert validate_email(email) is True

    def test_validate_email_invalid_emails(self) -> None:
        """Rejects invalid email addresses."""
        invalid_emails = [
            "invalid",
            "@example.com",
            "test@",
            "test..test@example.com",
            ".test@example.com",
            "test@example.",
            "test @example.com",
        ]
        for email in invalid_emails:
            assert validate_email(email) is False

    def test_validate_email_none_returns_false(self) -> None:
        """None input returns False."""
        assert validate_email(None) is False

    def test_validate_email_non_string_returns_false(self) -> None:
        """Non-string input returns False."""
        assert validate_email(12345) is False

    def test_validate_email_too_long_returns_false(self) -> None:
        """Emails over 254 characters return False."""
        long_email = "a" * 250 + "@example.com"
        assert validate_email(long_email) is False

    def test_validate_email_consecutive_dots_returns_false(self) -> None:
        """Consecutive dots in local part return False."""
        assert validate_email("test..user@example.com") is False


class TestValidateUsername:
    """Tests for validate_username function."""

    def test_validate_username_valid_usernames(self) -> None:
        """Validates valid usernames."""
        valid_usernames = [
            "testuser",
            "test_user",
            "test-user",
            "TestUser123",
            "user123",
        ]
        for username in valid_usernames:
            assert validate_username(username) is True

    def test_validate_username_invalid_usernames(self) -> None:
        """Rejects invalid usernames."""
        invalid_usernames = [
            "ab",
            "123user",
            "user_name_",
            "user-name-",
            "user__name",
            "user--name",
            "user name",
            "user@name",
        ]
        for username in invalid_usernames:
            assert validate_username(username) is False

    def test_validate_username_too_short_returns_false(self) -> None:
        """Usernames under 3 characters return False."""
        assert validate_username("ab") is False

    def test_validate_username_too_long_returns_false(self) -> None:
        """Usernames over 32 characters return False."""
        assert validate_username("a" * 33) is False

    def test_validate_username_none_returns_false(self) -> None:
        """None input returns False."""
        assert validate_username(None) is False

    def test_validate_username_non_string_returns_false(self) -> None:
        """Non-string input returns False."""
        assert validate_username(12345) is False


class TestRateLimitKey:
    """Tests for rate_limit_key function."""

    def test_rate_limit_key_generates_correct_format(self) -> None:
        """Generates correctly formatted cache key."""
        result = rate_limit_key("user-123")
        assert result == "rate_limit:user-123"

    def test_rate_limit_key_custom_prefix(self) -> None:
        """Uses custom prefix."""
        result = rate_limit_key("user-123", prefix="api_limit")
        assert result == "api_limit:user-123"

    def test_rate_limit_key_normalizes_identifier(self) -> None:
        """Normalizes identifier to lowercase."""
        result = rate_limit_key("USER-123")
        assert result == "rate_limit:user-123"

    def test_rate_limit_key_sanitizes_special_chars(self) -> None:
        """Sanitizes special characters in identifier."""
        result = rate_limit_key("user @123!")
        assert "rate_limit:user__123_" == result

    def test_rate_limit_key_empty_identifier_raises_error(self) -> None:
        """Empty identifier raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be empty"):
            rate_limit_key("")


class TestConstantTimeCompare:
    """Tests for constant-time comparison functions."""

    def test_constant_time_compare_equal_bytes(self) -> None:
        """Returns True for equal byte strings."""
        data = b"test data"
        assert constant_time_compare(data, data) is True

    def test_constant_time_compare_unequal_bytes(self) -> None:
        """Returns False for unequal byte strings."""
        assert constant_time_compare(b"data1", b"data2") is False

    def test_constant_time_compare_different_length_bytes(self) -> None:
        """Returns False for different length byte strings."""
        assert constant_time_compare(b"short", b"much longer data") is False

    def test_constant_time_compare_empty_bytes(self) -> None:
        """Handles empty byte strings correctly."""
        assert constant_time_compare(b"", b"") is True
        assert constant_time_compare(b"", b"data") is False

    def test_constant_time_compare_str_equal_strings(self) -> None:
        """Returns True for equal strings."""
        data = "test string"
        assert constant_time_compare_str(data, data) is True

    def test_constant_time_compare_str_unequal_strings(self) -> None:
        """Returns False for unequal strings."""
        assert constant_time_compare_str("string1", "string2") is False

    def test_constant_time_compare_str_unicode_strings(self) -> None:
        """Handles unicode strings correctly."""
        str1 = "Pässwörd"
        str2 = "Pässwörd"
        assert constant_time_compare_str(str1, str2) is True


class TestMaskSensitiveData:
    """Tests for mask_sensitive_data function."""

    def test_mask_sensitive_data_default_masking(self) -> None:
        """Masks with default visible characters."""
        result = mask_sensitive_data("password123")
        assert result.startswith("pa")
        assert result.endswith("rd123")
        assert "*" in result

    def test_mask_sensitive_data_custom_mask_char(self) -> None:
        """Uses custom mask character."""
        result = mask_sensitive_data("secret", mask_char="#")
        assert "#" in result

    def test_mask_sensitive_data_custom_visible_chars(self) -> None:
        """Uses custom visible character counts."""
        result = mask_sensitive_data("verylongpassword", visible_start=3, visible_end=5)
        assert len(result) == 16
        assert result.startswith("ver")
        assert result.endswith("ssword")

    def test_mask_sensitive_data_short_data(self) -> None:
        """Handles data shorter than visible chars."""
        result = mask_sensitive_data("ab")
        assert result == "**"

    def test_mask_sensitive_data_none_raises_error(self) -> None:
        """None input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be None"):
            mask_sensitive_data(None)

    def test_mask_sensitive_data_empty_raises_error(self) -> None:
        """Empty input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be empty"):
            mask_sensitive_data("")


class TestMaskEmail:
    """Tests for mask_email function."""

    def test_mask_email_masks_local_part(self) -> None:
        """Masks local part of email."""
        result = mask_email("john.doe@example.com")
        assert result.startswith("j")
        assert "@" in result

    def test_mask_email_masks_domain(self) -> None:
        """Masks domain part of email."""
        result = mask_email("user@gmail.com")
        assert "g" in result.split("@")[1]

    def test_mask_email_invalid_email_raises_error(self) -> None:
        """Invalid email raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="Invalid email"):
            mask_email("invalid-email")

    def test_mask_email_none_raises_error(self) -> None:
        """None input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError):
            mask_email(None)


class TestIsSafeRedirectUrl:
    """Tests for is_safe_redirect_url function."""

    def test_is_safe_redirect_url_relative_path_safe(self) -> None:
        """Relative paths are safe."""
        assert is_safe_redirect_url("/dashboard") is True
        assert is_safe_redirect_url("/users/profile") is True

    def test_is_safe_redirect_url_protocol_relative_blocks(self) -> None:
        """Protocol-relative URLs are blocked."""
        assert is_safe_redirect_url("//evil.com") is False

    def test_is_safe_redirect_url_absolute_url_blocks(self) -> None:
        """Absolute URLs to other hosts are blocked."""
        assert is_safe_redirect_url("http://evil.com") is False
        assert is_safe_redirect_url("https://evil.com/path") is False

    def test_is_safe_redirect_url_javascript_blocks(self) -> None:
        """JavaScript URLs are blocked."""
        assert is_safe_redirect_url("javascript:alert(1)") is False
        assert is_safe_redirect_url("JAVASCRIPT:alert(1)") is False

    def test_is_safe_redirect_url_data_url_blocks(self) -> None:
        """Data URLs are blocked."""
        assert is_safe_redirect_url("data:text/html,<script>alert(1)</script>") is False

    def test_is_safe_redirect_url_backslash_bypass_blocks(self) -> None:
        """Backslash bypasses are blocked."""
        assert is_safe_redirect_url("\\evil.com") is False
        assert is_safe_redirect_url("/\\evil.com") is False

    def test_is_safe_redirect_url_allowed_hosts(self) -> None:
        """Allows URLs in allowed hosts list."""
        allowed = ["example.com", "trusted.org"]
        assert is_safe_redirect_url("https://example.com/path", allowed_hosts=allowed) is True
        assert is_safe_redirect_url("https://evil.com/path", allowed_hosts=allowed) is False

    def test_is_safe_redirect_url_none_returns_false(self) -> None:
        """None input returns False."""
        assert is_safe_redirect_url(None) is False

    def test_is_safe_redirect_url_empty_returns_false(self) -> None:
        """Empty string returns False."""
        assert is_safe_redirect_url("") is False


class TestValidateUrl:
    """Tests for validate_url function."""

    def test_validate_url_valid_http_url(self) -> None:
        """Validates valid HTTP URL."""
        assert validate_url("http://example.com") is True
        assert validate_url("http://example.com/path?query=value") is True

    def test_validate_url_valid_https_url(self) -> None:
        """Validates valid HTTPS URL."""
        assert validate_url("https://example.com") is True

    def test_validate_url_invalid_url(self) -> None:
        """Rejects invalid URLs."""
        assert validate_url("not-a-url") is False
        assert validate_url("") is False

    def test_validate_url_disallowed_scheme(self) -> None:
        """Rejects disallowed schemes."""
        assert validate_url("ftp://example.com") is False
        assert validate_url("javascript:alert(1)") is False

    def test_validate_url_custom_allowed_schemes(self) -> None:
        """Accepts custom allowed schemes."""
        assert validate_url("ftp://example.com", allowed_schemes=["ftp"]) is True

    def test_validate_url_too_long(self) -> None:
        """Rejects URLs over 2048 characters."""
        long_url = "http://example.com/" + "a" * 2050
        assert validate_url(long_url) is False

    def test_validate_url_none_returns_false(self) -> None:
        """None input returns False."""
        assert validate_url(None) is False


class TestNormalizePath:
    """Tests for normalize_path function."""

    def test_normalize_path_removes_duplicate_slashes(self) -> None:
        """Removes duplicate slashes."""
        result = normalize_path("/path//to///file")
        assert result == "/path/to/file"

    def test_normalize_path_resolves_dots(self) -> None:
        """Resolves . and .. safely."""
        result = normalize_path("/path/./to/file")
        assert result == "/path/to/file"

    def test_normalize_path_directory_traversal_raises_error(self) -> None:
        """Directory traversal raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="Path traversal"):
            normalize_path("/path/../../../etc/passwd")

        with pytest.raises(SecurityValidationError, match="Path traversal"):
            normalize_path("../etc/passwd")

    def test_normalize_path_none_raises_error(self) -> None:
        """None input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be None"):
            normalize_path(None)

    def test_normalize_path_empty_raises_error(self) -> None:
        """Empty path raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be empty"):
            normalize_path("")


class TestValidateContentType:
    """Tests for validate_content_type function."""

    def test_validate_content_type_allowed_types(self) -> None:
        """Validates allowed content types."""
        assert validate_content_type("application/json") is True
        assert validate_content_type("text/plain") is True
        assert validate_content_type("multipart/form-data") is True

    def test_validate_content_type_disallowed_type(self) -> None:
        """Rejects disallowed content types."""
        assert validate_content_type("application/x-php") is False

    def test_validate_content_type_with_charset(self) -> None:
        """Handles content type with charset."""
        assert validate_content_type("application/json; charset=utf-8") is True

    def test_validate_content_type_none_returns_false(self) -> None:
        """None input returns False."""
        assert validate_content_type(None) is False

    def test_validate_content_type_empty_returns_false(self) -> None:
        """Empty string returns False."""
        assert validate_content_type("") is False


class TestGenerateCsrfToken:
    """Tests for generate_csrf_token function."""

    def test_generate_csrf_token_returns_string(self) -> None:
        """Returns a string token."""
        token = generate_csrf_token()
        assert isinstance(token, str)

    def test_generate_csrf_token_url_safe(self) -> None:
        """Returns URL-safe token."""
        token = generate_csrf_token()
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in token)

    def test_generate_csrf_token_different_each_call(self) -> None:
        """Returns different tokens on each call."""
        tokens = [generate_csrf_token() for _ in range(50)]
        unique_tokens = set(tokens)
        assert len(unique_tokens) == 50


class TestValidateCsrfToken:
    """Tests for validate_csrf_token function."""

    def test_validate_csrf_token_matching_tokens(self) -> None:
        """Matching tokens return True."""
        token = generate_csrf_token()
        assert validate_csrf_token(token, token) is True

    def test_validate_csrf_token_mismatched_tokens(self) -> None:
        """Mismatched tokens return False."""
        token1 = generate_csrf_token()
        token2 = generate_csrf_token()
        assert validate_csrf_token(token1, token2) is False

    def test_validate_csrf_token_empty_tokens(self) -> None:
        """Empty tokens return False."""
        assert validate_csrf_token("", "") is False

    def test_validate_csrf_token_none_tokens(self) -> None:
        """None tokens return False."""
        assert validate_csrf_token(None, None) is False


class TestStripNullBytes:
    """Tests for strip_null_bytes and strip_null_bytes_str functions."""

    def test_strip_null_bytes_removes_nulls(self) -> None:
        """Removes null bytes from binary data."""
        data = b"test\x00data\x00here"
        result = strip_null_bytes(data)
        assert b"\x00" not in result
        assert result == b"testdatahere"

    def test_strip_null_bytes_no_nulls(self) -> None:
        """Returns data unchanged if no nulls."""
        data = b"testdata"
        result = strip_null_bytes(data)
        assert result == data

    def test_strip_null_bytes_str_removes_nulls(self) -> None:
        """Removes null bytes from string."""
        data = "test\x00data\x00here"
        result = strip_null_bytes_str(data)
        assert "\x00" not in result
        assert result == "testdatahere"


class TestIsIpv4Address:
    """Tests for is_ipv4_address function."""

    def test_is_ipv4_address_valid_addresses(self) -> None:
        """Validates valid IPv4 addresses."""
        assert is_ipv4_address("192.168.1.1") is True
        assert is_ipv4_address("0.0.0.0") is True
        assert is_ipv4_address("255.255.255.255") is True
        assert is_ipv4_address("10.0.0.1") is True

    def test_is_ipv4_address_invalid_addresses(self) -> None:
        """Rejects invalid IPv4 addresses."""
        assert is_ipv4_address("256.1.1.1") is False
        assert is_ipv4_address("1.2.3") is False
        assert is_ipv4_address("1.2.3.4.5") is False
        assert is_ipv4_address("1.2.3.4.5") is False
        assert is_ipv4_address("abc.def.ghi.jkl") is False
        assert is_ipv4_address("01.02.03.04") is False

    def test_is_ipv4_address_none_returns_false(self) -> None:
        """None input returns False."""
        assert is_ipv4_address(None) is False


class TestIsIpv6Address:
    """Tests for is_ipv6_address function."""

    def test_is_ipv6_address_valid_addresses(self) -> None:
        """Validates valid IPv6 addresses."""
        assert is_ipv6_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
        assert is_ipv6_address("::1") is True
        assert is_ipv6_address("fe80::1") is True
        assert is_ipv6_address("2001:db8::1") is True

    def test_is_ipv6_address_invalid_addresses(self) -> None:
        """Rejects invalid IPv6 addresses."""
        assert is_ipv6_address("not-an-ipv6") is False
        assert is_ipv6_address("192.168.1.1") is False
        assert is_ipv6_address("gggg::1") is False

    def test_is_ipv6_address_none_returns_false(self) -> None:
        """None input returns False."""
        assert is_ipv6_address(None) is False


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""

    def test_sanitize_filename_removes_dangerous_chars(self) -> None:
        """Removes dangerous characters from filename."""
        result = sanitize_filename("file<name>.txt")
        assert "<" not in result
        assert ">" not in result
        assert "file_name_.txt" == result

    def test_sanitize_filename_normalizes_path_separators(self) -> None:
        """Normalizes path separators."""
        result = sanitize_filename("path/to/file.txt")
        assert "/" not in result
        assert "\\" not in result

    def test_sanitize_filename_trims_long_filename(self) -> None:
        """Trims filenames over 255 characters."""
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255

    def test_sanitize_filename_reserved_names_raises_error(self) -> None:
        """Reserved names raise SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="Reserved filename"):
            sanitize_filename("CON")
        with pytest.raises(SecurityValidationError, match="Reserved filename"):
            sanitize_filename("NUL.txt")
        with pytest.raises(SecurityValidationError, match="Reserved filename"):
            sanitize_filename("COM1")

    def test_sanitize_filename_none_raises_error(self) -> None:
        """None input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be empty"):
            sanitize_filename(None)

    def test_sanitize_filename_empty_raises_error(self) -> None:
        """Empty input raises SecurityValidationError."""
        with pytest.raises(SecurityValidationError, match="cannot be empty"):
            sanitize_filename("")
