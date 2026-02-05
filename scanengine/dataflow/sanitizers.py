"""
Sanitizer Registry - Configuration and detection of sanitization functions

Provides a configurable registry of functions that sanitize tainted data
for specific sink types (e.g., ESAPI.encodeForSQL sanitizes for SQL injection).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from collections import defaultdict
import re
import logging

# Import SinkType from parent package
import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])
from ..dataflow_analyzer import SinkType

logger = logging.getLogger(__name__)


@dataclass
class Sanitizer:
    """
    Definition of a sanitizer function.

    A sanitizer is a function/method that neutralizes tainted data
    for specific vulnerability types.
    """
    method_name: str
    class_name: Optional[str] = None  # None means any class
    package_pattern: Optional[str] = None  # Regex for package matching
    sanitizes_for: Set[SinkType] = field(default_factory=set)  # Which sinks this sanitizes
    argument_index: int = 0  # Which argument gets sanitized (0 = first, -1 = receiver)
    returns_sanitized: bool = True  # Whether return value is sanitized
    description: str = ""

    def matches(self, method_name: str, class_name: Optional[str] = None,
               package: Optional[str] = None) -> bool:
        """Check if this sanitizer matches the given method call"""
        if self.method_name != method_name:
            return False

        if self.class_name:
            if not class_name:
                return False
            # Allow partial match (e.g., "ESAPI" matches "org.owasp.esapi.ESAPI")
            if self.class_name not in class_name:
                return False

        if self.package_pattern and package:
            if not re.match(self.package_pattern, package):
                return False

        return True


class SanitizerRegistry:
    """
    Registry of known sanitizer functions.

    Provides lookup for sanitizers by method name and context,
    with built-in definitions for common security libraries.
    """

    # ============================================================
    # JAVA SANITIZERS
    # ============================================================

    JAVA_SANITIZERS = [
        # ----- OWASP ESAPI -----
        Sanitizer(
            method_name='encodeForSQL',
            class_name='ESAPI',
            package_pattern=r'org\.owasp\.esapi',
            sanitizes_for={SinkType.SQL_QUERY},
            description="ESAPI SQL encoder"
        ),
        Sanitizer(
            method_name='encodeForHTML',
            class_name='ESAPI',
            package_pattern=r'org\.owasp\.esapi',
            sanitizes_for={SinkType.XSS},
            description="ESAPI HTML encoder"
        ),
        Sanitizer(
            method_name='encodeForHTMLAttribute',
            class_name='ESAPI',
            package_pattern=r'org\.owasp\.esapi',
            sanitizes_for={SinkType.XSS},
            description="ESAPI HTML attribute encoder"
        ),
        Sanitizer(
            method_name='encodeForJavaScript',
            class_name='ESAPI',
            package_pattern=r'org\.owasp\.esapi',
            sanitizes_for={SinkType.XSS},
            description="ESAPI JavaScript encoder"
        ),
        Sanitizer(
            method_name='encodeForLDAP',
            class_name='ESAPI',
            package_pattern=r'org\.owasp\.esapi',
            sanitizes_for={SinkType.LDAP_QUERY},
            description="ESAPI LDAP encoder"
        ),
        Sanitizer(
            method_name='encodeForXPath',
            class_name='ESAPI',
            package_pattern=r'org\.owasp\.esapi',
            sanitizes_for={SinkType.XPATH_QUERY},
            description="ESAPI XPath encoder"
        ),
        Sanitizer(
            method_name='encodeForOS',
            class_name='ESAPI',
            package_pattern=r'org\.owasp\.esapi',
            sanitizes_for={SinkType.COMMAND_EXEC},
            description="ESAPI OS command encoder"
        ),
        Sanitizer(
            method_name='encodeForURL',
            class_name='ESAPI',
            package_pattern=r'org\.owasp\.esapi',
            sanitizes_for={SinkType.SSRF},
            description="ESAPI URL encoder"
        ),

        # ----- OWASP Java Encoder -----
        Sanitizer(
            method_name='forHtml',
            class_name='Encode',
            package_pattern=r'org\.owasp\.encoder',
            sanitizes_for={SinkType.XSS},
            description="OWASP Java Encoder for HTML"
        ),
        Sanitizer(
            method_name='forHtmlContent',
            class_name='Encode',
            package_pattern=r'org\.owasp\.encoder',
            sanitizes_for={SinkType.XSS},
            description="OWASP Java Encoder for HTML content"
        ),
        Sanitizer(
            method_name='forHtmlAttribute',
            class_name='Encode',
            package_pattern=r'org\.owasp\.encoder',
            sanitizes_for={SinkType.XSS},
            description="OWASP Java Encoder for HTML attributes"
        ),
        Sanitizer(
            method_name='forJavaScript',
            class_name='Encode',
            package_pattern=r'org\.owasp\.encoder',
            sanitizes_for={SinkType.XSS},
            description="OWASP Java Encoder for JavaScript"
        ),
        Sanitizer(
            method_name='forJavaScriptSource',
            class_name='Encode',
            package_pattern=r'org\.owasp\.encoder',
            sanitizes_for={SinkType.XSS},
            description="OWASP Java Encoder for JavaScript source"
        ),
        Sanitizer(
            method_name='forUri',
            class_name='Encode',
            package_pattern=r'org\.owasp\.encoder',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="OWASP Java Encoder for URI"
        ),
        Sanitizer(
            method_name='forUriComponent',
            class_name='Encode',
            package_pattern=r'org\.owasp\.encoder',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="OWASP Java Encoder for URI components"
        ),

        # ----- Spring Framework -----
        Sanitizer(
            method_name='htmlEscape',
            class_name='HtmlUtils',
            package_pattern=r'org\.springframework\.web\.util',
            sanitizes_for={SinkType.XSS},
            description="Spring HtmlUtils HTML escaper"
        ),
        Sanitizer(
            method_name='javaScriptEscape',
            class_name='JavaScriptUtils',
            package_pattern=r'org\.springframework\.web\.util',
            sanitizes_for={SinkType.XSS},
            description="Spring JavaScriptUtils escaper"
        ),

        # ----- Apache Commons Text -----
        Sanitizer(
            method_name='escapeHtml4',
            class_name='StringEscapeUtils',
            package_pattern=r'org\.apache\.commons\.text',
            sanitizes_for={SinkType.XSS},
            description="Apache Commons HTML4 escaper"
        ),
        Sanitizer(
            method_name='escapeHtml3',
            class_name='StringEscapeUtils',
            package_pattern=r'org\.apache\.commons\.text',
            sanitizes_for={SinkType.XSS},
            description="Apache Commons HTML3 escaper"
        ),
        Sanitizer(
            method_name='escapeXml10',
            class_name='StringEscapeUtils',
            package_pattern=r'org\.apache\.commons\.text',
            sanitizes_for={SinkType.XSS, SinkType.XPATH_QUERY},
            description="Apache Commons XML escaper"
        ),
        Sanitizer(
            method_name='escapeEcmaScript',
            class_name='StringEscapeUtils',
            package_pattern=r'org\.apache\.commons\.text',
            sanitizes_for={SinkType.XSS},
            description="Apache Commons ECMAScript escaper"
        ),

        # ----- Apache Commons Lang (legacy) -----
        Sanitizer(
            method_name='escapeHtml',
            class_name='StringEscapeUtils',
            package_pattern=r'org\.apache\.commons\.lang',
            sanitizes_for={SinkType.XSS},
            description="Apache Commons Lang HTML escaper (legacy)"
        ),
        Sanitizer(
            method_name='escapeSql',
            class_name='StringEscapeUtils',
            package_pattern=r'org\.apache\.commons\.lang',
            sanitizes_for={SinkType.SQL_QUERY},
            description="Apache Commons Lang SQL escaper (legacy)"
        ),

        # ----- PreparedStatement (parameterized queries) -----
        Sanitizer(
            method_name='setString',
            class_name='PreparedStatement',
            package_pattern=r'java\.sql',
            sanitizes_for={SinkType.SQL_QUERY},
            argument_index=1,  # Second argument is the value
            description="PreparedStatement parameterized value"
        ),
        Sanitizer(
            method_name='setInt',
            class_name='PreparedStatement',
            package_pattern=r'java\.sql',
            sanitizes_for={SinkType.SQL_QUERY},
            argument_index=1,
            description="PreparedStatement parameterized int"
        ),
        Sanitizer(
            method_name='setLong',
            class_name='PreparedStatement',
            package_pattern=r'java\.sql',
            sanitizes_for={SinkType.SQL_QUERY},
            argument_index=1,
            description="PreparedStatement parameterized long"
        ),
        Sanitizer(
            method_name='setObject',
            class_name='PreparedStatement',
            package_pattern=r'java\.sql',
            sanitizes_for={SinkType.SQL_QUERY},
            argument_index=1,
            description="PreparedStatement parameterized object"
        ),
        Sanitizer(
            method_name='setBoolean',
            class_name='PreparedStatement',
            package_pattern=r'java\.sql',
            sanitizes_for={SinkType.SQL_QUERY},
            argument_index=1,
            description="PreparedStatement parameterized boolean"
        ),

        # ----- Integer/numeric parsing (type coercion sanitizes) -----
        Sanitizer(
            method_name='parseInt',
            class_name='Integer',
            package_pattern=r'java\.lang',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC, SinkType.FILE_ACCESS},
            description="Integer parsing coerces to safe numeric"
        ),
        Sanitizer(
            method_name='parseLong',
            class_name='Long',
            package_pattern=r'java\.lang',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC, SinkType.FILE_ACCESS},
            description="Long parsing coerces to safe numeric"
        ),
        Sanitizer(
            method_name='parseDouble',
            class_name='Double',
            package_pattern=r'java\.lang',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
            description="Double parsing coerces to safe numeric"
        ),
        Sanitizer(
            method_name='valueOf',
            class_name='Integer',
            package_pattern=r'java\.lang',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC, SinkType.FILE_ACCESS},
            description="Integer valueOf coerces to safe numeric"
        ),
        Sanitizer(
            method_name='valueOf',
            class_name='Long',
            package_pattern=r'java\.lang',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC, SinkType.FILE_ACCESS},
            description="Long valueOf coerces to safe numeric"
        ),

        # ----- Java URLEncoder -----
        Sanitizer(
            method_name='encode',
            class_name='URLEncoder',
            package_pattern=r'java\.net',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="Java URL encoder"
        ),

        # ----- Google Guava -----
        Sanitizer(
            method_name='htmlEscaper',
            class_name='HtmlEscapers',
            package_pattern=r'com\.google\.common\.html',
            sanitizes_for={SinkType.XSS},
            returns_sanitized=False,  # Returns an escaper, not escaped string
            description="Guava HTML escaper factory"
        ),
        Sanitizer(
            method_name='escape',
            class_name='CharEscaper',
            package_pattern=r'com\.google\.common\.escape',
            sanitizes_for={SinkType.XSS},
            description="Guava escaper"
        ),

        # ----- JSoup (for HTML sanitization) -----
        Sanitizer(
            method_name='clean',
            class_name='Jsoup',
            package_pattern=r'org\.jsoup',
            sanitizes_for={SinkType.XSS},
            description="JSoup HTML cleaner"
        ),

        # ----- Path canonicalization (partial protection) -----
        Sanitizer(
            method_name='getCanonicalPath',
            class_name='File',
            package_pattern=r'java\.io',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="File path canonicalization"
        ),
        Sanitizer(
            method_name='normalize',
            class_name='Path',
            package_pattern=r'java\.nio\.file',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Path normalization"
        ),
        Sanitizer(
            method_name='toRealPath',
            class_name='Path',
            package_pattern=r'java\.nio\.file',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Path resolution to real path"
        ),
    ]

    # ============================================================
    # PYTHON SANITIZERS
    # ============================================================

    PYTHON_SANITIZERS = [
        # ----- html module -----
        Sanitizer(
            method_name='escape',
            class_name='html',
            sanitizes_for={SinkType.XSS},
            description="Python html.escape"
        ),

        # ----- shlex module (command sanitization) -----
        Sanitizer(
            method_name='quote',
            class_name='shlex',
            sanitizes_for={SinkType.COMMAND_EXEC},
            description="Python shlex.quote for shell escaping"
        ),

        # ----- urllib -----
        Sanitizer(
            method_name='quote',
            class_name='urllib.parse',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="Python URL quoting"
        ),
        Sanitizer(
            method_name='quote_plus',
            class_name='urllib.parse',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="Python URL quoting (plus)"
        ),

        # ----- Django -----
        Sanitizer(
            method_name='escape',
            class_name='django.utils.html',
            sanitizes_for={SinkType.XSS},
            description="Django HTML escape"
        ),
        Sanitizer(
            method_name='mark_safe',
            class_name='django.utils.safestring',
            sanitizes_for=set(),  # This REMOVES safety, so no sanitization
            description="Django mark_safe (DANGER - removes protection)"
        ),
        Sanitizer(
            method_name='format_html',
            class_name='django.utils.html',
            sanitizes_for={SinkType.XSS},
            description="Django format_html (safe formatting)"
        ),

        # ----- Bleach (HTML sanitizer) -----
        Sanitizer(
            method_name='clean',
            class_name='bleach',
            sanitizes_for={SinkType.XSS},
            description="Bleach HTML cleaner"
        ),
        Sanitizer(
            method_name='linkify',
            class_name='bleach',
            sanitizes_for={SinkType.XSS},
            description="Bleach linkifier (with escaping)"
        ),

        # ----- Markupsafe -----
        Sanitizer(
            method_name='escape',
            class_name='markupsafe',
            sanitizes_for={SinkType.XSS},
            description="MarkupSafe escape"
        ),
    ]

    # ============================================================
    # JAVASCRIPT/NODE SANITIZERS
    # ============================================================

    JAVASCRIPT_SANITIZERS = [
        # ----- validator.js -----
        Sanitizer(
            method_name='escape',
            class_name='validator',
            sanitizes_for={SinkType.XSS},
            description="validator.js escape"
        ),

        # ----- DOMPurify -----
        Sanitizer(
            method_name='sanitize',
            class_name='DOMPurify',
            sanitizes_for={SinkType.XSS},
            description="DOMPurify HTML sanitizer"
        ),

        # ----- xss-filters -----
        Sanitizer(
            method_name='inHTMLData',
            class_name='xssFilters',
            sanitizes_for={SinkType.XSS},
            description="xss-filters HTML data"
        ),
        Sanitizer(
            method_name='inHTMLComment',
            class_name='xssFilters',
            sanitizes_for={SinkType.XSS},
            description="xss-filters HTML comment"
        ),

        # ----- he (HTML entities) -----
        Sanitizer(
            method_name='encode',
            class_name='he',
            sanitizes_for={SinkType.XSS},
            description="he HTML entity encoder"
        ),

        # ----- Node.js path -----
        Sanitizer(
            method_name='normalize',
            class_name='path',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Node.js path.normalize"
        ),
        Sanitizer(
            method_name='resolve',
            class_name='path',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Node.js path.resolve"
        ),
    ]

    def __init__(self, custom_sanitizers: Optional[List[Sanitizer]] = None):
        """
        Initialize the sanitizer registry.

        Args:
            custom_sanitizers: Additional custom sanitizers to add
        """
        # Index sanitizers by method name for fast lookup
        self._by_method: Dict[str, List[Sanitizer]] = defaultdict(list)

        # Load built-in sanitizers
        self._load_sanitizers(self.JAVA_SANITIZERS)
        self._load_sanitizers(self.PYTHON_SANITIZERS)
        self._load_sanitizers(self.JAVASCRIPT_SANITIZERS)

        # Load custom sanitizers
        if custom_sanitizers:
            self._load_sanitizers(custom_sanitizers)

        logger.debug(f"SanitizerRegistry initialized with {len(self._by_method)} methods")

    def _load_sanitizers(self, sanitizers: List[Sanitizer]):
        """Load sanitizers into the index"""
        for san in sanitizers:
            self._by_method[san.method_name].append(san)

    def get_sanitization(self, method_name: str,
                        class_name: Optional[str] = None,
                        package: Optional[str] = None) -> Optional[Sanitizer]:
        """
        Check if a method call is a sanitizer.

        Args:
            method_name: Name of the method being called
            class_name: Class/object type if known
            package: Package/module if known

        Returns:
            Sanitizer if found, None otherwise
        """
        candidates = self._by_method.get(method_name, [])

        for sanitizer in candidates:
            if sanitizer.matches(method_name, class_name, package):
                return sanitizer

        return None

    def get_sanitization_for_call(self, method_name: str,
                                  receiver_type: Optional[str] = None) -> Optional[Sanitizer]:
        """
        Convenience method for checking a method call.

        Args:
            method_name: Method name
            receiver_type: Type of the receiver object (e.g., "HtmlUtils")

        Returns:
            Sanitizer if found
        """
        return self.get_sanitization(method_name, receiver_type)

    def is_sanitizer(self, method_name: str) -> bool:
        """Quick check if a method name is a known sanitizer"""
        return method_name in self._by_method

    def get_sanitizers_for_sink(self, sink_type: SinkType) -> List[Sanitizer]:
        """Get all sanitizers that protect against a specific sink type"""
        result = []
        for sanitizers in self._by_method.values():
            for san in sanitizers:
                if sink_type in san.sanitizes_for:
                    result.append(san)
        return result

    def add_sanitizer(self, sanitizer: Sanitizer):
        """Add a custom sanitizer"""
        self._by_method[sanitizer.method_name].append(sanitizer)

    def remove_sanitizer(self, method_name: str, class_name: Optional[str] = None):
        """Remove a sanitizer from the registry"""
        if method_name in self._by_method:
            if class_name:
                self._by_method[method_name] = [
                    s for s in self._by_method[method_name]
                    if s.class_name != class_name
                ]
            else:
                del self._by_method[method_name]


# Methods that preserve taint (transform but don't sanitize)
TAINT_PRESERVING_METHODS = {
    # String transformations
    'trim', 'strip', 'stripLeading', 'stripTrailing',
    'toLowerCase', 'toUpperCase',
    'substring', 'subSequence',
    'replace', 'replaceAll', 'replaceFirst',
    'split', 'join',
    'concat', 'append', 'prepend',
    'toString', 'valueOf',
    'format',
    'chars', 'bytes', 'toCharArray',
    'getBytes',

    # Collection transformations
    'map', 'filter', 'flatMap', 'reduce',
    'sorted', 'distinct', 'limit', 'skip',
    'collect', 'toList', 'toArray',

    # Builder patterns
    'builder', 'build', 'add', 'set',

    # Optional unwrapping
    'get', 'orElse', 'orElseGet',
}


def is_taint_preserving(method_name: str) -> bool:
    """Check if a method preserves taint (transforms but doesn't sanitize)"""
    return method_name in TAINT_PRESERVING_METHODS
