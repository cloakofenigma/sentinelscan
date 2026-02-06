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

        # ----- sanitize-html -----
        Sanitizer(
            method_name='sanitizeHtml',
            class_name=None,
            sanitizes_for={SinkType.XSS},
            description="sanitize-html library"
        ),

        # ----- escape-html -----
        Sanitizer(
            method_name='escapeHtml',
            class_name=None,
            sanitizes_for={SinkType.XSS},
            description="escape-html library"
        ),

        # ----- lodash/underscore -----
        Sanitizer(
            method_name='escape',
            class_name='_',
            sanitizes_for={SinkType.XSS},
            description="lodash/underscore escape"
        ),

        # ----- encodeURIComponent -----
        Sanitizer(
            method_name='encodeURIComponent',
            class_name=None,
            sanitizes_for={SinkType.XSS, SinkType.SSRF},
            description="JavaScript URL encoding"
        ),
        Sanitizer(
            method_name='encodeURI',
            class_name=None,
            sanitizes_for={SinkType.SSRF},
            description="JavaScript URI encoding"
        ),
    ]

    # ============================================================
    # GO SANITIZERS
    # ============================================================

    GO_SANITIZERS = [
        # ----- html/template (auto-escaping) -----
        Sanitizer(
            method_name='HTMLEscapeString',
            class_name='html',
            sanitizes_for={SinkType.XSS},
            description="Go html.HTMLEscapeString"
        ),
        Sanitizer(
            method_name='HTMLEscaper',
            class_name='html',
            sanitizes_for={SinkType.XSS},
            description="Go html.HTMLEscaper"
        ),
        Sanitizer(
            method_name='EscapeString',
            class_name='html',
            sanitizes_for={SinkType.XSS},
            description="Go html.EscapeString"
        ),

        # ----- url package -----
        Sanitizer(
            method_name='QueryEscape',
            class_name='url',
            sanitizes_for={SinkType.XSS, SinkType.SSRF},
            description="Go url.QueryEscape"
        ),
        Sanitizer(
            method_name='PathEscape',
            class_name='url',
            sanitizes_for={SinkType.FILE_ACCESS, SinkType.SSRF},
            description="Go url.PathEscape"
        ),

        # ----- filepath package -----
        Sanitizer(
            method_name='Clean',
            class_name='filepath',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Go filepath.Clean"
        ),
        Sanitizer(
            method_name='Abs',
            class_name='filepath',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Go filepath.Abs"
        ),

        # ----- database/sql parameterized -----
        Sanitizer(
            method_name='Prepare',
            class_name='DB',
            sanitizes_for={SinkType.SQL_QUERY},
            description="Go sql.Prepare (parameterized)"
        ),
        Sanitizer(
            method_name='QueryRow',
            class_name='DB',
            sanitizes_for={SinkType.SQL_QUERY},
            argument_index=1,  # Args after query are params
            description="Go sql.QueryRow with params"
        ),

        # ----- strconv (type conversion) -----
        Sanitizer(
            method_name='Atoi',
            class_name='strconv',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
            description="Go strconv.Atoi (int conversion)"
        ),
        Sanitizer(
            method_name='ParseInt',
            class_name='strconv',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
            description="Go strconv.ParseInt"
        ),

        # ----- bluemonday (HTML sanitizer) -----
        Sanitizer(
            method_name='Sanitize',
            class_name='Policy',
            sanitizes_for={SinkType.XSS},
            description="bluemonday HTML sanitizer"
        ),
        Sanitizer(
            method_name='SanitizeBytes',
            class_name='Policy',
            sanitizes_for={SinkType.XSS},
            description="bluemonday bytes sanitizer"
        ),
    ]

    # ============================================================
    # C# / .NET SANITIZERS
    # ============================================================

    CSHARP_SANITIZERS = [
        # ----- System.Web.HttpUtility -----
        Sanitizer(
            method_name='HtmlEncode',
            class_name='HttpUtility',
            sanitizes_for={SinkType.XSS},
            description=".NET HttpUtility.HtmlEncode"
        ),
        Sanitizer(
            method_name='HtmlAttributeEncode',
            class_name='HttpUtility',
            sanitizes_for={SinkType.XSS},
            description=".NET HttpUtility.HtmlAttributeEncode"
        ),
        Sanitizer(
            method_name='UrlEncode',
            class_name='HttpUtility',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description=".NET HttpUtility.UrlEncode"
        ),
        Sanitizer(
            method_name='JavaScriptStringEncode',
            class_name='HttpUtility',
            sanitizes_for={SinkType.XSS},
            description=".NET HttpUtility.JavaScriptStringEncode"
        ),

        # ----- System.Net.WebUtility -----
        Sanitizer(
            method_name='HtmlEncode',
            class_name='WebUtility',
            sanitizes_for={SinkType.XSS},
            description=".NET WebUtility.HtmlEncode"
        ),
        Sanitizer(
            method_name='UrlEncode',
            class_name='WebUtility',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description=".NET WebUtility.UrlEncode"
        ),

        # ----- System.Security.SecurityElement -----
        Sanitizer(
            method_name='Escape',
            class_name='SecurityElement',
            sanitizes_for={SinkType.XSS},
            description=".NET SecurityElement.Escape"
        ),

        # ----- AntiXSS Library -----
        Sanitizer(
            method_name='HtmlEncode',
            class_name='Encoder',
            package_pattern=r'Microsoft\.Security\.Application',
            sanitizes_for={SinkType.XSS},
            description="AntiXSS HtmlEncode"
        ),
        Sanitizer(
            method_name='JavaScriptEncode',
            class_name='Encoder',
            package_pattern=r'Microsoft\.Security\.Application',
            sanitizes_for={SinkType.XSS},
            description="AntiXSS JavaScriptEncode"
        ),
        Sanitizer(
            method_name='UrlEncode',
            class_name='Encoder',
            package_pattern=r'Microsoft\.Security\.Application',
            sanitizes_for={SinkType.SSRF},
            description="AntiXSS UrlEncode"
        ),
        Sanitizer(
            method_name='LdapEncode',
            class_name='Encoder',
            package_pattern=r'Microsoft\.Security\.Application',
            sanitizes_for={SinkType.LDAP_QUERY},
            description="AntiXSS LdapEncode"
        ),

        # ----- SqlParameter (parameterized) -----
        Sanitizer(
            method_name='AddWithValue',
            class_name='SqlParameterCollection',
            sanitizes_for={SinkType.SQL_QUERY},
            description=".NET SqlParameter (parameterized)"
        ),
        Sanitizer(
            method_name='Add',
            class_name='SqlParameterCollection',
            sanitizes_for={SinkType.SQL_QUERY},
            description=".NET SqlParameter.Add"
        ),

        # ----- Path class -----
        Sanitizer(
            method_name='GetFullPath',
            class_name='Path',
            sanitizes_for={SinkType.FILE_ACCESS},
            description=".NET Path.GetFullPath"
        ),

        # ----- Type conversion -----
        Sanitizer(
            method_name='Parse',
            class_name='Int32',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
            description=".NET Int32.Parse"
        ),
        Sanitizer(
            method_name='TryParse',
            class_name='Int32',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
            description=".NET Int32.TryParse"
        ),
    ]

    # ============================================================
    # RUBY SANITIZERS
    # ============================================================

    RUBY_SANITIZERS = [
        # ----- ERB::Util -----
        Sanitizer(
            method_name='html_escape',
            class_name='ERB::Util',
            sanitizes_for={SinkType.XSS},
            description="Ruby ERB html_escape"
        ),
        Sanitizer(
            method_name='h',
            class_name=None,  # Rails helper
            sanitizes_for={SinkType.XSS},
            description="Rails h() helper"
        ),

        # ----- CGI -----
        Sanitizer(
            method_name='escapeHTML',
            class_name='CGI',
            sanitizes_for={SinkType.XSS},
            description="Ruby CGI.escapeHTML"
        ),
        Sanitizer(
            method_name='escape',
            class_name='CGI',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="Ruby CGI.escape"
        ),

        # ----- Rack::Utils -----
        Sanitizer(
            method_name='escape_html',
            class_name='Rack::Utils',
            sanitizes_for={SinkType.XSS},
            description="Rack escape_html"
        ),

        # ----- Rails sanitize helpers -----
        Sanitizer(
            method_name='sanitize',
            class_name='ActionView',
            sanitizes_for={SinkType.XSS},
            description="Rails sanitize helper"
        ),
        Sanitizer(
            method_name='strip_tags',
            class_name='ActionView',
            sanitizes_for={SinkType.XSS},
            description="Rails strip_tags"
        ),

        # ----- Shellwords -----
        Sanitizer(
            method_name='escape',
            class_name='Shellwords',
            sanitizes_for={SinkType.COMMAND_EXEC},
            description="Ruby Shellwords.escape"
        ),
        Sanitizer(
            method_name='shellescape',
            class_name='String',
            sanitizes_for={SinkType.COMMAND_EXEC},
            description="Ruby String#shellescape"
        ),

        # ----- ActiveRecord (parameterized) -----
        Sanitizer(
            method_name='sanitize_sql',
            class_name='ActiveRecord',
            sanitizes_for={SinkType.SQL_QUERY},
            description="ActiveRecord sanitize_sql"
        ),
        Sanitizer(
            method_name='sanitize_sql_array',
            class_name='ActiveRecord',
            sanitizes_for={SinkType.SQL_QUERY},
            description="ActiveRecord sanitize_sql_array"
        ),

        # ----- File path -----
        Sanitizer(
            method_name='realpath',
            class_name='File',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Ruby File.realpath"
        ),
        Sanitizer(
            method_name='expand_path',
            class_name='File',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Ruby File.expand_path"
        ),

        # ----- Type conversion -----
        Sanitizer(
            method_name='to_i',
            class_name='String',
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
            description="Ruby String#to_i"
        ),
    ]

    # ============================================================
    # RUST SANITIZERS
    # ============================================================

    RUST_SANITIZERS = [
        # ----- html_escape crate -----
        Sanitizer(
            method_name='encode_text',
            class_name='html_escape',
            sanitizes_for={SinkType.XSS},
            description="Rust html_escape::encode_text"
        ),
        Sanitizer(
            method_name='encode_safe',
            class_name='html_escape',
            sanitizes_for={SinkType.XSS},
            description="Rust html_escape::encode_safe"
        ),

        # ----- askama (auto-escaping templates) -----
        Sanitizer(
            method_name='escape',
            class_name='askama',
            sanitizes_for={SinkType.XSS},
            description="Askama template escaping"
        ),

        # ----- ammonia (HTML sanitizer) -----
        Sanitizer(
            method_name='clean',
            class_name='ammonia',
            sanitizes_for={SinkType.XSS},
            description="Ammonia HTML sanitizer"
        ),

        # ----- urlencoding -----
        Sanitizer(
            method_name='encode',
            class_name='urlencoding',
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="Rust urlencoding::encode"
        ),

        # ----- std::path -----
        Sanitizer(
            method_name='canonicalize',
            class_name='Path',
            sanitizes_for={SinkType.FILE_ACCESS},
            description="Rust Path::canonicalize"
        ),

        # ----- sqlx (parameterized) -----
        Sanitizer(
            method_name='bind',
            class_name='Query',
            sanitizes_for={SinkType.SQL_QUERY},
            description="sqlx query binding"
        ),

        # ----- shell-escape -----
        Sanitizer(
            method_name='escape',
            class_name='shell_escape',
            sanitizes_for={SinkType.COMMAND_EXEC},
            description="Rust shell-escape"
        ),
    ]

    # ============================================================
    # PHP SANITIZERS
    # ============================================================

    PHP_SANITIZERS = [
        # ----- Built-in functions -----
        Sanitizer(
            method_name='htmlspecialchars',
            class_name=None,
            sanitizes_for={SinkType.XSS},
            description="PHP htmlspecialchars"
        ),
        Sanitizer(
            method_name='htmlentities',
            class_name=None,
            sanitizes_for={SinkType.XSS},
            description="PHP htmlentities"
        ),
        Sanitizer(
            method_name='strip_tags',
            class_name=None,
            sanitizes_for={SinkType.XSS},
            description="PHP strip_tags"
        ),
        Sanitizer(
            method_name='escapeshellarg',
            class_name=None,
            sanitizes_for={SinkType.COMMAND_EXEC},
            description="PHP escapeshellarg"
        ),
        Sanitizer(
            method_name='escapeshellcmd',
            class_name=None,
            sanitizes_for={SinkType.COMMAND_EXEC},
            description="PHP escapeshellcmd"
        ),
        Sanitizer(
            method_name='addslashes',
            class_name=None,
            sanitizes_for={SinkType.SQL_QUERY},
            description="PHP addslashes"
        ),

        # ----- mysqli -----
        Sanitizer(
            method_name='real_escape_string',
            class_name='mysqli',
            sanitizes_for={SinkType.SQL_QUERY},
            description="mysqli real_escape_string"
        ),
        Sanitizer(
            method_name='mysqli_real_escape_string',
            class_name=None,
            sanitizes_for={SinkType.SQL_QUERY},
            description="mysqli_real_escape_string"
        ),

        # ----- PDO (parameterized) -----
        Sanitizer(
            method_name='prepare',
            class_name='PDO',
            sanitizes_for={SinkType.SQL_QUERY},
            description="PDO prepare (parameterized)"
        ),
        Sanitizer(
            method_name='bindParam',
            class_name='PDOStatement',
            sanitizes_for={SinkType.SQL_QUERY},
            description="PDO bindParam"
        ),
        Sanitizer(
            method_name='bindValue',
            class_name='PDOStatement',
            sanitizes_for={SinkType.SQL_QUERY},
            description="PDO bindValue"
        ),

        # ----- URL encoding -----
        Sanitizer(
            method_name='urlencode',
            class_name=None,
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="PHP urlencode"
        ),
        Sanitizer(
            method_name='rawurlencode',
            class_name=None,
            sanitizes_for={SinkType.SSRF, SinkType.XSS},
            description="PHP rawurlencode"
        ),

        # ----- Path functions -----
        Sanitizer(
            method_name='realpath',
            class_name=None,
            sanitizes_for={SinkType.FILE_ACCESS},
            description="PHP realpath"
        ),
        Sanitizer(
            method_name='basename',
            class_name=None,
            sanitizes_for={SinkType.FILE_ACCESS},
            description="PHP basename"
        ),

        # ----- Filter functions -----
        Sanitizer(
            method_name='filter_var',
            class_name=None,
            sanitizes_for={SinkType.XSS, SinkType.SQL_QUERY},
            description="PHP filter_var"
        ),
        Sanitizer(
            method_name='filter_input',
            class_name=None,
            sanitizes_for={SinkType.XSS, SinkType.SQL_QUERY},
            description="PHP filter_input"
        ),

        # ----- Intval (type coercion) -----
        Sanitizer(
            method_name='intval',
            class_name=None,
            sanitizes_for={SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
            description="PHP intval"
        ),
        Sanitizer(
            method_name='floatval',
            class_name=None,
            sanitizes_for={SinkType.SQL_QUERY},
            description="PHP floatval"
        ),

        # ----- HTMLPurifier -----
        Sanitizer(
            method_name='purify',
            class_name='HTMLPurifier',
            sanitizes_for={SinkType.XSS},
            description="HTMLPurifier"
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

        # Load built-in sanitizers for all supported languages
        self._load_sanitizers(self.JAVA_SANITIZERS)
        self._load_sanitizers(self.PYTHON_SANITIZERS)
        self._load_sanitizers(self.JAVASCRIPT_SANITIZERS)
        self._load_sanitizers(self.GO_SANITIZERS)
        self._load_sanitizers(self.CSHARP_SANITIZERS)
        self._load_sanitizers(self.RUBY_SANITIZERS)
        self._load_sanitizers(self.RUST_SANITIZERS)
        self._load_sanitizers(self.PHP_SANITIZERS)

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
    # String transformations (Java/JS/Python/etc.)
    'trim', 'strip', 'stripLeading', 'stripTrailing', 'lstrip', 'rstrip',
    'toLowerCase', 'toUpperCase', 'lower', 'upper', 'capitalize', 'title',
    'substring', 'subSequence', 'slice', 'substr',
    'replace', 'replaceAll', 'replaceFirst', 'gsub', 'sub',
    'split', 'join', 'rsplit',
    'concat', 'append', 'prepend', 'push', 'unshift',
    'toString', 'valueOf', 'str', '__str__',
    'format', 'sprintf', 'printf',
    'chars', 'bytes', 'toCharArray', 'encode', 'decode',
    'getBytes',

    # Collection transformations
    'map', 'filter', 'flatMap', 'reduce', 'fold',
    'sorted', 'sort', 'distinct', 'uniq', 'limit', 'skip', 'take', 'drop',
    'collect', 'toList', 'toArray', 'list', 'tuple',
    'each', 'forEach', 'for_each',
    'first', 'last', 'reverse', 'reversed',
    'zip', 'enumerate', 'iter',

    # Builder patterns
    'builder', 'build', 'add', 'set', 'with', 'and',

    # Optional unwrapping
    'get', 'orElse', 'orElseGet', 'unwrap', 'unwrap_or', 'expect',
    'getOrDefault', 'getOrElse',

    # Ruby-specific
    'chomp', 'chop', 'squeeze', 'swapcase', 'reverse',
    'chars', 'lines', 'each_char', 'each_line',

    # Go-specific
    'String', 'Bytes', 'Runes',

    # Rust-specific
    'as_str', 'as_bytes', 'into_string', 'to_string', 'to_owned',
    'chars', 'lines', 'split_whitespace',

    # PHP-specific
    'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper',
    'substr', 'str_replace', 'preg_replace', 'explode', 'implode',
}


def is_taint_preserving(method_name: str) -> bool:
    """Check if a method preserves taint (transforms but doesn't sanitize)"""
    return method_name in TAINT_PRESERVING_METHODS
