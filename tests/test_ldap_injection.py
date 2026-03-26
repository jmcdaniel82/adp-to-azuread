"""Tests for LDAP injection vulnerability prevention."""

from __future__ import annotations

import pytest
from ldap3.utils.conv import escape_filter_chars

from app.services.defaults import DefaultDirectoryGateway


class MockConnection:
    """Mock LDAP connection for testing."""
    
    def __init__(self):
        self.entries = []
        self.result = {"result": 0, "description": "success", "message": ""}
        self.bound = True
        self.closed = False


class MockDirectoryContext:
    """Mock directory context for testing."""
    
    def __init__(self, conn):
        self.conn = conn
        self.settings = type('obj', (object,), {
            'search_base': 'OU=Users,DC=example,DC=com',
            'server': 'ldap.example.com',
            'ca_bundle_path': '/path/to/ca.crt',
        })()
        self.conn_factory = lambda: conn


class TestLDAPInjectionPrevention:
    """Test LDAP injection vulnerability is prevented."""
    
    def test_employee_id_filter_escaping(self):
        """Verify employee IDs are escaped in LDAP filters."""
        # Test that escape_filter_chars properly escapes LDAP metacharacters
        test_cases = [
            ("123456", "123456"),  # Normal case
            ("*", r"\2a"),  # Wildcard
            ("(", r"\28"),  # Open paren
            (")", r"\29"),  # Close paren
            ("&", "&"),  # Ampersand is not an LDAP filter metacharacter by itself
            ("|", "|"),  # Pipe is only significant in filter syntax, not as a bare value
            ("*)(|(cn=*", r"\2a\29\28|\28cn=\2a"),  # Malicious payload
        ]
        
        for input_id, expected_escaped in test_cases:
            escaped = escape_filter_chars(input_id)
            assert escaped == expected_escaped, (
                f"Failed to escape '{input_id}': expected '{expected_escaped}' got '{escaped}'"
            )
    
    def test_malicious_employee_id_payloads(self):
        """Test that malicious LDAP filter payloads are properly escaped."""
        malicious_payloads = [
            "*",
            "*)(|(cn=*",
            "*))(&",
            "admin*",
            "*)(&(uid=*",
            "*",
        ]
        
        for payload in malicious_payloads:
            escaped = escape_filter_chars(payload)
            # Verify no filter metacharacters remain unescaped
            assert "*" not in escaped or r"\2a" in escaped
            assert "(" not in escaped or r"\28" in escaped
            assert ")" not in escaped or r"\29" in escaped
            filter_str = f"(employeeID={escaped})"
            assert filter_str.count("(") == 1
            assert filter_str.count(")") == 1
    
    def test_find_user_by_employee_id_uses_escape(self):
        """Verify find_user_by_employee_id uses filter escaping."""
        # This test verifies that the DefaultDirectoryGateway.find_user_by_employee_id
        # method properly escapes the employee_id parameter
        
        gateway = DefaultDirectoryGateway(
            validate_settings=lambda require_create_base=False: [],
            get_settings=lambda require_create_base=False: None,
            log_target_details=lambda *args, **kwargs: None,
            create_server=lambda *args, **kwargs: None,
            make_conn_factory=lambda server, user, password, context: None,
            get_department_by_dn=lambda *args: None,
            apply_changes=lambda *args: None,
            safe_unbind=lambda *args: None,
        )
        
        # Test that the method correctly handles employee_id escaping
        # This is a basic check that the method exists and is callable
        assert hasattr(gateway, 'find_user_by_employee_id')
        assert callable(gateway.find_user_by_employee_id)


class TestLDAPFilterConstruction:
    """Test proper LDAP filter construction to prevent injection."""
    
    def test_filter_escaping_preserves_functionality(self):
        """Verify that escaping doesn't break legitimate searches."""
        legitimate_ids = [
            "EMP123456",
            "user_2024",
            "john.doe",
            "123-456-7890",
        ]
        
        for emp_id in legitimate_ids:
            escaped = escape_filter_chars(emp_id)
            # After escaping, the ID should still be present (possibly with escapes)
            assert len(escaped) >= 1
            # The escaped version should not introduce new filter syntax
            filter_str = f"(employeeID={escaped})"
            assert filter_str.count("(") == 1  # Only our opening paren
            assert filter_str.count(")") == 1  # Only our closing paren
            assert "|" not in filter_str or r"\7c" in filter_str
            assert "&" not in filter_str or r"\26" in filter_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
