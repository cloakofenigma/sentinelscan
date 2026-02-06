"""
Multi-Language Dataflow Support

Provides taint sources, sinks, and sanitizers for:
- Go
- C#
- Kotlin
- PHP
- Ruby
- Rust
- Swift

Each language has its own set of:
1. Taint sources (user input entry points)
2. Sinks (dangerous operations)
3. Sanitizers (functions that clean tainted data)
4. Annotations/attributes (markers for parameters)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from enum import Enum
import re

# Import base types from existing dataflow module
import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])
from ..dataflow_analyzer import TaintSource, SinkType


# ============================================================================
# LANGUAGE CONFIGURATION
# ============================================================================

@dataclass
class LanguageDataflowConfig:
    """Configuration for language-specific dataflow analysis."""
    language: str
    taint_sources: Dict[str, TaintSource]
    sink_methods: Dict[str, SinkType]
    sanitizers: Dict[str, Set[SinkType]]
    source_annotations: Dict[str, TaintSource] = field(default_factory=dict)
    # Patterns for matching (regex)
    source_patterns: List[tuple] = field(default_factory=list)
    sink_patterns: List[tuple] = field(default_factory=list)


# ============================================================================
# GO LANGUAGE SUPPORT
# ============================================================================

GO_TAINT_SOURCES = {
    # net/http package
    'FormValue': TaintSource.HTTP_PARAMETER,
    'PostFormValue': TaintSource.HTTP_PARAMETER,
    'Form.Get': TaintSource.HTTP_PARAMETER,
    'URL.Query': TaintSource.HTTP_PARAMETER,
    'Header.Get': TaintSource.HTTP_HEADER,
    'Cookie': TaintSource.COOKIE,
    'Body': TaintSource.HTTP_BODY,
    'URL.Path': TaintSource.PATH_VARIABLE,
    'URL.RawPath': TaintSource.PATH_VARIABLE,
    'RequestURI': TaintSource.PATH_VARIABLE,

    # os package
    'Getenv': TaintSource.ENVIRONMENT,
    'LookupEnv': TaintSource.ENVIRONMENT,
    'Environ': TaintSource.ENVIRONMENT,

    # io/ioutil / os package
    'ReadFile': TaintSource.FILE_INPUT,
    'ReadAll': TaintSource.FILE_INPUT,
    'Read': TaintSource.FILE_INPUT,

    # bufio
    'ReadString': TaintSource.FILE_INPUT,
    'ReadLine': TaintSource.FILE_INPUT,
    'ReadBytes': TaintSource.FILE_INPUT,

    # database/sql
    'Scan': TaintSource.DATABASE,
    'QueryRow': TaintSource.DATABASE,

    # Gin framework
    'Query': TaintSource.HTTP_PARAMETER,
    'PostForm': TaintSource.HTTP_PARAMETER,
    'Param': TaintSource.PATH_VARIABLE,
    'GetHeader': TaintSource.HTTP_HEADER,
    'ShouldBind': TaintSource.HTTP_BODY,
    'ShouldBindJSON': TaintSource.HTTP_BODY,

    # Echo framework
    'QueryParam': TaintSource.HTTP_PARAMETER,
    'FormValue': TaintSource.HTTP_PARAMETER,
    'Bind': TaintSource.HTTP_BODY,

    # Fiber framework
    'Query': TaintSource.HTTP_PARAMETER,
    'Params': TaintSource.PATH_VARIABLE,
    'BodyParser': TaintSource.HTTP_BODY,
}

GO_SINK_METHODS = {
    # database/sql - SQL Injection
    'Query': SinkType.SQL_QUERY,
    'QueryRow': SinkType.SQL_QUERY,
    'Exec': SinkType.SQL_QUERY,
    'Prepare': SinkType.SQL_QUERY,

    # os/exec - Command Injection
    'Command': SinkType.COMMAND_EXEC,
    'CommandContext': SinkType.COMMAND_EXEC,
    'Run': SinkType.COMMAND_EXEC,
    'Start': SinkType.COMMAND_EXEC,
    'Output': SinkType.COMMAND_EXEC,
    'CombinedOutput': SinkType.COMMAND_EXEC,

    # os - File operations
    'Open': SinkType.FILE_ACCESS,
    'OpenFile': SinkType.FILE_ACCESS,
    'Create': SinkType.FILE_ACCESS,
    'ReadFile': SinkType.FILE_ACCESS,
    'WriteFile': SinkType.FILE_ACCESS,
    'Remove': SinkType.FILE_ACCESS,
    'RemoveAll': SinkType.FILE_ACCESS,
    'Mkdir': SinkType.FILE_ACCESS,
    'MkdirAll': SinkType.FILE_ACCESS,

    # net/http - SSRF
    'Get': SinkType.SSRF,
    'Post': SinkType.SSRF,
    'Do': SinkType.SSRF,
    'NewRequest': SinkType.SSRF,

    # html/template - XSS
    'Execute': SinkType.XSS,
    'ExecuteTemplate': SinkType.XSS,
    'Write': SinkType.XSS,

    # encoding/json - Deserialization
    'Unmarshal': SinkType.DESERIALIZATION,
    'Decode': SinkType.DESERIALIZATION,
    'NewDecoder': SinkType.DESERIALIZATION,

    # encoding/xml
    'Unmarshal': SinkType.DESERIALIZATION,

    # log
    'Print': SinkType.LOG_OUTPUT,
    'Printf': SinkType.LOG_OUTPUT,
    'Println': SinkType.LOG_OUTPUT,
}

GO_SANITIZERS = {
    # html/template (auto-escapes)
    'HTMLEscapeString': {SinkType.XSS},
    'HTMLEscaper': {SinkType.XSS},
    'JSEscapeString': {SinkType.XSS},
    'JSEscaper': {SinkType.XSS},
    'URLQueryEscaper': {SinkType.XSS, SinkType.SSRF},

    # url package
    'QueryEscape': {SinkType.XSS, SinkType.SSRF},
    'PathEscape': {SinkType.FILE_ACCESS, SinkType.SSRF},

    # strconv
    'Atoi': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'ParseInt': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'ParseFloat': {SinkType.SQL_QUERY},
    'ParseBool': {SinkType.SQL_QUERY},

    # path/filepath
    'Clean': {SinkType.FILE_ACCESS},
    'Base': {SinkType.FILE_ACCESS},

    # Prepared statements (when using ?)
    'Prepare': {SinkType.SQL_QUERY},
}

GO_CONFIG = LanguageDataflowConfig(
    language='go',
    taint_sources=GO_TAINT_SOURCES,
    sink_methods=GO_SINK_METHODS,
    sanitizers=GO_SANITIZERS,
)


# ============================================================================
# C# LANGUAGE SUPPORT
# ============================================================================

CSHARP_TAINT_SOURCES = {
    # ASP.NET Core
    'QueryString': TaintSource.HTTP_PARAMETER,
    'Query': TaintSource.HTTP_PARAMETER,
    'Form': TaintSource.HTTP_PARAMETER,
    'Headers': TaintSource.HTTP_HEADER,
    'Cookies': TaintSource.COOKIE,
    'Body': TaintSource.HTTP_BODY,
    'Path': TaintSource.PATH_VARIABLE,
    'RouteValues': TaintSource.PATH_VARIABLE,

    # HttpRequest
    'Request.QueryString': TaintSource.HTTP_PARAMETER,
    'Request.Form': TaintSource.HTTP_PARAMETER,
    'Request.Headers': TaintSource.HTTP_HEADER,
    'Request.Cookies': TaintSource.COOKIE,
    'Request.InputStream': TaintSource.HTTP_BODY,
    'Request.Path': TaintSource.PATH_VARIABLE,

    # Environment
    'GetEnvironmentVariable': TaintSource.ENVIRONMENT,
    'GetEnvironmentVariables': TaintSource.ENVIRONMENT,

    # File I/O
    'ReadAllText': TaintSource.FILE_INPUT,
    'ReadAllLines': TaintSource.FILE_INPUT,
    'ReadAllBytes': TaintSource.FILE_INPUT,
    'ReadLine': TaintSource.FILE_INPUT,
    'Read': TaintSource.FILE_INPUT,

    # Database
    'ExecuteReader': TaintSource.DATABASE,
    'GetString': TaintSource.DATABASE,
    'GetValue': TaintSource.DATABASE,
    'Read': TaintSource.DATABASE,

    # Console
    'ReadLine': TaintSource.USER_INPUT,
    'Read': TaintSource.USER_INPUT,
}

CSHARP_SINK_METHODS = {
    # SQL - SqlCommand
    'ExecuteNonQuery': SinkType.SQL_QUERY,
    'ExecuteReader': SinkType.SQL_QUERY,
    'ExecuteScalar': SinkType.SQL_QUERY,
    'ExecuteSqlRaw': SinkType.SQL_QUERY,
    'ExecuteSqlRawAsync': SinkType.SQL_QUERY,
    'FromSqlRaw': SinkType.SQL_QUERY,
    'SqlQuery': SinkType.SQL_QUERY,

    # Process - Command Injection
    'Start': SinkType.COMMAND_EXEC,
    'Process.Start': SinkType.COMMAND_EXEC,

    # File I/O
    'WriteAllText': SinkType.FILE_ACCESS,
    'WriteAllLines': SinkType.FILE_ACCESS,
    'WriteAllBytes': SinkType.FILE_ACCESS,
    'Open': SinkType.FILE_ACCESS,
    'OpenRead': SinkType.FILE_ACCESS,
    'OpenWrite': SinkType.FILE_ACCESS,
    'Create': SinkType.FILE_ACCESS,
    'Delete': SinkType.FILE_ACCESS,
    'Move': SinkType.FILE_ACCESS,
    'Copy': SinkType.FILE_ACCESS,

    # HttpClient - SSRF
    'GetAsync': SinkType.SSRF,
    'PostAsync': SinkType.SSRF,
    'SendAsync': SinkType.SSRF,
    'GetStringAsync': SinkType.SSRF,

    # Response - XSS
    'Write': SinkType.XSS,
    'WriteAsync': SinkType.XSS,
    'Content': SinkType.XSS,

    # Serialization
    'Deserialize': SinkType.DESERIALIZATION,
    'DeserializeObject': SinkType.DESERIALIZATION,
    'BinaryFormatter.Deserialize': SinkType.DESERIALIZATION,

    # LDAP
    'FindOne': SinkType.LDAP_QUERY,
    'FindAll': SinkType.LDAP_QUERY,

    # XPath
    'SelectNodes': SinkType.XPATH_QUERY,
    'SelectSingleNode': SinkType.XPATH_QUERY,
    'Evaluate': SinkType.XPATH_QUERY,

    # Logging
    'Log': SinkType.LOG_OUTPUT,
    'LogInformation': SinkType.LOG_OUTPUT,
    'LogWarning': SinkType.LOG_OUTPUT,
    'LogError': SinkType.LOG_OUTPUT,
    'LogDebug': SinkType.LOG_OUTPUT,
}

CSHARP_SANITIZERS = {
    # HTML encoding
    'HtmlEncode': {SinkType.XSS},
    'HtmlAttributeEncode': {SinkType.XSS},
    'JavaScriptStringEncode': {SinkType.XSS},
    'UrlEncode': {SinkType.XSS, SinkType.SSRF},

    # URL encoding
    'EscapeDataString': {SinkType.SSRF},
    'EscapeUriString': {SinkType.SSRF},

    # Path sanitization
    'GetFileName': {SinkType.FILE_ACCESS},
    'GetFullPath': {SinkType.FILE_ACCESS},

    # Parameterized queries
    'AddWithValue': {SinkType.SQL_QUERY},
    'Add': {SinkType.SQL_QUERY},

    # Type conversion
    'Parse': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'TryParse': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'Convert.ToInt32': {SinkType.SQL_QUERY},
    'Convert.ToInt64': {SinkType.SQL_QUERY},
}

CSHARP_SOURCE_ANNOTATIONS = {
    '[FromQuery]': TaintSource.HTTP_PARAMETER,
    '[FromForm]': TaintSource.HTTP_PARAMETER,
    '[FromBody]': TaintSource.HTTP_BODY,
    '[FromHeader]': TaintSource.HTTP_HEADER,
    '[FromRoute]': TaintSource.PATH_VARIABLE,
    '[Bind]': TaintSource.HTTP_PARAMETER,
}

CSHARP_CONFIG = LanguageDataflowConfig(
    language='csharp',
    taint_sources=CSHARP_TAINT_SOURCES,
    sink_methods=CSHARP_SINK_METHODS,
    sanitizers=CSHARP_SANITIZERS,
    source_annotations=CSHARP_SOURCE_ANNOTATIONS,
)


# ============================================================================
# KOTLIN LANGUAGE SUPPORT
# ============================================================================

# Kotlin inherits Java sources/sinks but adds its own
KOTLIN_TAINT_SOURCES = {
    # Ktor framework
    'call.parameters': TaintSource.HTTP_PARAMETER,
    'call.request.queryParameters': TaintSource.HTTP_PARAMETER,
    'call.request.headers': TaintSource.HTTP_HEADER,
    'call.request.cookies': TaintSource.COOKIE,
    'call.receive': TaintSource.HTTP_BODY,
    'call.request.path': TaintSource.PATH_VARIABLE,

    # Spring (same as Java)
    'getParameter': TaintSource.HTTP_PARAMETER,
    'getHeader': TaintSource.HTTP_HEADER,
    'getBody': TaintSource.HTTP_BODY,

    # Android
    'getIntent': TaintSource.USER_INPUT,
    'getStringExtra': TaintSource.USER_INPUT,
    'getIntExtra': TaintSource.USER_INPUT,
    'getBundleExtra': TaintSource.USER_INPUT,
    'getData': TaintSource.USER_INPUT,
    'getExtras': TaintSource.USER_INPUT,

    # SharedPreferences
    'getString': TaintSource.FILE_INPUT,
    'getInt': TaintSource.FILE_INPUT,

    # Environment
    'System.getenv': TaintSource.ENVIRONMENT,
    'System.getProperty': TaintSource.ENVIRONMENT,

    # File I/O
    'readText': TaintSource.FILE_INPUT,
    'readLines': TaintSource.FILE_INPUT,
    'readBytes': TaintSource.FILE_INPUT,
    'bufferedReader': TaintSource.FILE_INPUT,
}

KOTLIN_SINK_METHODS = {
    # SQL - Android SQLite
    'rawQuery': SinkType.SQL_QUERY,
    'execSQL': SinkType.SQL_QUERY,
    'compileStatement': SinkType.SQL_QUERY,

    # SQL - Exposed/JDBC
    'exec': SinkType.SQL_QUERY,
    'executeQuery': SinkType.SQL_QUERY,
    'executeUpdate': SinkType.SQL_QUERY,

    # Command execution
    'exec': SinkType.COMMAND_EXEC,
    'Runtime.getRuntime().exec': SinkType.COMMAND_EXEC,
    'ProcessBuilder': SinkType.COMMAND_EXEC,

    # File operations
    'writeText': SinkType.FILE_ACCESS,
    'writeBytes': SinkType.FILE_ACCESS,
    'createNewFile': SinkType.FILE_ACCESS,
    'delete': SinkType.FILE_ACCESS,
    'mkdir': SinkType.FILE_ACCESS,

    # Network - SSRF
    'URL': SinkType.SSRF,
    'openConnection': SinkType.SSRF,
    'HttpURLConnection': SinkType.SSRF,

    # Android WebView - XSS
    'loadUrl': SinkType.XSS,
    'loadData': SinkType.XSS,
    'loadDataWithBaseURL': SinkType.XSS,
    'evaluateJavascript': SinkType.XSS,

    # Android Intent
    'startActivity': SinkType.COMMAND_EXEC,
    'startService': SinkType.COMMAND_EXEC,
    'sendBroadcast': SinkType.COMMAND_EXEC,

    # Serialization
    'readObject': SinkType.DESERIALIZATION,
    'decodeFromString': SinkType.DESERIALIZATION,

    # Logging
    'Log.d': SinkType.LOG_OUTPUT,
    'Log.i': SinkType.LOG_OUTPUT,
    'Log.w': SinkType.LOG_OUTPUT,
    'Log.e': SinkType.LOG_OUTPUT,
    'Log.v': SinkType.LOG_OUTPUT,
}

KOTLIN_SANITIZERS = {
    # Same as Java
    'HtmlCompat.toHtml': {SinkType.XSS},
    'TextUtils.htmlEncode': {SinkType.XSS},
    'URLEncoder.encode': {SinkType.XSS, SinkType.SSRF},
    'Uri.encode': {SinkType.SSRF},

    # Kotlin stdlib
    'toIntOrNull': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'toLongOrNull': {SinkType.SQL_QUERY},
    'toDoubleOrNull': {SinkType.SQL_QUERY},

    # PreparedStatement
    'setString': {SinkType.SQL_QUERY},
    'setInt': {SinkType.SQL_QUERY},
}

KOTLIN_SOURCE_ANNOTATIONS = {
    '@RequestParam': TaintSource.HTTP_PARAMETER,
    '@PathVariable': TaintSource.PATH_VARIABLE,
    '@RequestBody': TaintSource.HTTP_BODY,
    '@RequestHeader': TaintSource.HTTP_HEADER,
}

KOTLIN_CONFIG = LanguageDataflowConfig(
    language='kotlin',
    taint_sources=KOTLIN_TAINT_SOURCES,
    sink_methods=KOTLIN_SINK_METHODS,
    sanitizers=KOTLIN_SANITIZERS,
    source_annotations=KOTLIN_SOURCE_ANNOTATIONS,
)


# ============================================================================
# PHP LANGUAGE SUPPORT
# ============================================================================

PHP_TAINT_SOURCES = {
    # Superglobals (special handling needed)
    '$_GET': TaintSource.HTTP_PARAMETER,
    '$_POST': TaintSource.HTTP_PARAMETER,
    '$_REQUEST': TaintSource.HTTP_PARAMETER,
    '$_COOKIE': TaintSource.COOKIE,
    '$_SERVER': TaintSource.HTTP_HEADER,
    '$_FILES': TaintSource.FILE_INPUT,
    '$_ENV': TaintSource.ENVIRONMENT,
    '$_SESSION': TaintSource.USER_INPUT,

    # Input functions
    'file_get_contents': TaintSource.FILE_INPUT,
    'fread': TaintSource.FILE_INPUT,
    'fgets': TaintSource.FILE_INPUT,
    'fgetc': TaintSource.FILE_INPUT,
    'file': TaintSource.FILE_INPUT,
    'readfile': TaintSource.FILE_INPUT,

    # HTTP
    'getallheaders': TaintSource.HTTP_HEADER,
    'apache_request_headers': TaintSource.HTTP_HEADER,

    # Input
    'readline': TaintSource.USER_INPUT,
    'stream_get_contents': TaintSource.FILE_INPUT,

    # Database
    'fetch_assoc': TaintSource.DATABASE,
    'fetch_array': TaintSource.DATABASE,
    'fetch_row': TaintSource.DATABASE,
    'fetch_object': TaintSource.DATABASE,
    'fetchAll': TaintSource.DATABASE,
    'fetch': TaintSource.DATABASE,

    # Laravel
    'input': TaintSource.HTTP_PARAMETER,
    'query': TaintSource.HTTP_PARAMETER,
    'post': TaintSource.HTTP_PARAMETER,
    'all': TaintSource.HTTP_PARAMETER,
    'get': TaintSource.HTTP_PARAMETER,
    'cookie': TaintSource.COOKIE,
    'header': TaintSource.HTTP_HEADER,
    'file': TaintSource.FILE_INPUT,
}

PHP_SINK_METHODS = {
    # SQL Injection
    'mysql_query': SinkType.SQL_QUERY,
    'mysqli_query': SinkType.SQL_QUERY,
    'query': SinkType.SQL_QUERY,
    'exec': SinkType.SQL_QUERY,
    'prepare': SinkType.SQL_QUERY,  # Only if not parameterized
    'raw': SinkType.SQL_QUERY,  # Laravel
    'selectRaw': SinkType.SQL_QUERY,
    'whereRaw': SinkType.SQL_QUERY,
    'havingRaw': SinkType.SQL_QUERY,
    'orderByRaw': SinkType.SQL_QUERY,

    # Command Injection
    'exec': SinkType.COMMAND_EXEC,
    'shell_exec': SinkType.COMMAND_EXEC,
    'system': SinkType.COMMAND_EXEC,
    'passthru': SinkType.COMMAND_EXEC,
    'popen': SinkType.COMMAND_EXEC,
    'proc_open': SinkType.COMMAND_EXEC,
    'pcntl_exec': SinkType.COMMAND_EXEC,
    'backtick': SinkType.COMMAND_EXEC,  # `` operator

    # File operations
    'fopen': SinkType.FILE_ACCESS,
    'file_put_contents': SinkType.FILE_ACCESS,
    'fwrite': SinkType.FILE_ACCESS,
    'fputs': SinkType.FILE_ACCESS,
    'include': SinkType.FILE_ACCESS,
    'include_once': SinkType.FILE_ACCESS,
    'require': SinkType.FILE_ACCESS,
    'require_once': SinkType.FILE_ACCESS,
    'readfile': SinkType.FILE_ACCESS,
    'file_get_contents': SinkType.FILE_ACCESS,
    'unlink': SinkType.FILE_ACCESS,
    'rename': SinkType.FILE_ACCESS,
    'copy': SinkType.FILE_ACCESS,
    'mkdir': SinkType.FILE_ACCESS,
    'rmdir': SinkType.FILE_ACCESS,

    # SSRF
    'curl_exec': SinkType.SSRF,
    'curl_setopt': SinkType.SSRF,
    'file_get_contents': SinkType.SSRF,
    'fopen': SinkType.SSRF,
    'get_headers': SinkType.SSRF,

    # XSS
    'echo': SinkType.XSS,
    'print': SinkType.XSS,
    'printf': SinkType.XSS,

    # Code Injection
    'eval': SinkType.COMMAND_EXEC,
    'assert': SinkType.COMMAND_EXEC,
    'preg_replace': SinkType.COMMAND_EXEC,  # with /e modifier
    'create_function': SinkType.COMMAND_EXEC,

    # Deserialization
    'unserialize': SinkType.DESERIALIZATION,

    # LDAP
    'ldap_search': SinkType.LDAP_QUERY,

    # XPath
    'xpath': SinkType.XPATH_QUERY,

    # Logging
    'error_log': SinkType.LOG_OUTPUT,
    'syslog': SinkType.LOG_OUTPUT,
}

PHP_SANITIZERS = {
    # HTML encoding
    'htmlspecialchars': {SinkType.XSS},
    'htmlentities': {SinkType.XSS},
    'strip_tags': {SinkType.XSS},
    'nl2br': {SinkType.XSS},

    # SQL (these should be used with prepared statements)
    'mysqli_real_escape_string': {SinkType.SQL_QUERY},  # Deprecated approach
    'mysql_real_escape_string': {SinkType.SQL_QUERY},  # Deprecated
    'addslashes': {SinkType.SQL_QUERY},  # Weak

    # URL encoding
    'urlencode': {SinkType.XSS, SinkType.SSRF},
    'rawurlencode': {SinkType.XSS, SinkType.SSRF},

    # Path
    'basename': {SinkType.FILE_ACCESS},
    'realpath': {SinkType.FILE_ACCESS},

    # Shell
    'escapeshellarg': {SinkType.COMMAND_EXEC},
    'escapeshellcmd': {SinkType.COMMAND_EXEC},

    # Type casting
    'intval': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'floatval': {SinkType.SQL_QUERY},
    '(int)': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    '(float)': {SinkType.SQL_QUERY},

    # Filter
    'filter_var': {SinkType.XSS, SinkType.SQL_QUERY, SinkType.SSRF},
    'filter_input': {SinkType.XSS, SinkType.SQL_QUERY},
}

PHP_CONFIG = LanguageDataflowConfig(
    language='php',
    taint_sources=PHP_TAINT_SOURCES,
    sink_methods=PHP_SINK_METHODS,
    sanitizers=PHP_SANITIZERS,
)


# ============================================================================
# RUBY LANGUAGE SUPPORT
# ============================================================================

RUBY_TAINT_SOURCES = {
    # Rails params
    'params': TaintSource.HTTP_PARAMETER,
    'request.params': TaintSource.HTTP_PARAMETER,
    'request.query_parameters': TaintSource.HTTP_PARAMETER,
    'request.request_parameters': TaintSource.HTTP_PARAMETER,

    # Request
    'request.headers': TaintSource.HTTP_HEADER,
    'request.cookies': TaintSource.COOKIE,
    'request.body': TaintSource.HTTP_BODY,
    'request.path': TaintSource.PATH_VARIABLE,
    'request.url': TaintSource.PATH_VARIABLE,
    'request.raw_post': TaintSource.HTTP_BODY,

    # Environment
    'ENV': TaintSource.ENVIRONMENT,
    'ENV.fetch': TaintSource.ENVIRONMENT,

    # File I/O
    'File.read': TaintSource.FILE_INPUT,
    'File.readlines': TaintSource.FILE_INPUT,
    'IO.read': TaintSource.FILE_INPUT,
    'IO.readlines': TaintSource.FILE_INPUT,
    'gets': TaintSource.USER_INPUT,
    'readline': TaintSource.USER_INPUT,

    # Database
    'find_by_sql': TaintSource.DATABASE,
    'connection.execute': TaintSource.DATABASE,
    'select_rows': TaintSource.DATABASE,
    'select_values': TaintSource.DATABASE,

    # Sinatra
    'params': TaintSource.HTTP_PARAMETER,
    'request.env': TaintSource.HTTP_HEADER,
}

RUBY_SINK_METHODS = {
    # SQL Injection
    'find_by_sql': SinkType.SQL_QUERY,
    'execute': SinkType.SQL_QUERY,
    'exec_query': SinkType.SQL_QUERY,
    'select_all': SinkType.SQL_QUERY,
    'where': SinkType.SQL_QUERY,  # When using string interpolation
    'order': SinkType.SQL_QUERY,
    'group': SinkType.SQL_QUERY,
    'having': SinkType.SQL_QUERY,
    'pluck': SinkType.SQL_QUERY,
    'calculate': SinkType.SQL_QUERY,

    # Command Injection
    'system': SinkType.COMMAND_EXEC,
    'exec': SinkType.COMMAND_EXEC,
    'spawn': SinkType.COMMAND_EXEC,
    'Open3.capture3': SinkType.COMMAND_EXEC,
    'Open3.popen3': SinkType.COMMAND_EXEC,
    'IO.popen': SinkType.COMMAND_EXEC,
    'Kernel.system': SinkType.COMMAND_EXEC,
    'Kernel.exec': SinkType.COMMAND_EXEC,
    '`': SinkType.COMMAND_EXEC,  # Backticks
    '%x': SinkType.COMMAND_EXEC,

    # File operations
    'File.open': SinkType.FILE_ACCESS,
    'File.write': SinkType.FILE_ACCESS,
    'File.delete': SinkType.FILE_ACCESS,
    'File.rename': SinkType.FILE_ACCESS,
    'FileUtils.cp': SinkType.FILE_ACCESS,
    'FileUtils.mv': SinkType.FILE_ACCESS,
    'FileUtils.rm': SinkType.FILE_ACCESS,
    'send_file': SinkType.FILE_ACCESS,

    # SSRF
    'Net::HTTP.get': SinkType.SSRF,
    'URI.open': SinkType.SSRF,
    'open-uri': SinkType.SSRF,
    'HTTParty.get': SinkType.SSRF,
    'RestClient.get': SinkType.SSRF,
    'Faraday.get': SinkType.SSRF,

    # XSS
    'render': SinkType.XSS,
    'html_safe': SinkType.XSS,
    'raw': SinkType.XSS,
    'safe_join': SinkType.XSS,

    # Code Injection
    'eval': SinkType.COMMAND_EXEC,
    'instance_eval': SinkType.COMMAND_EXEC,
    'class_eval': SinkType.COMMAND_EXEC,
    'module_eval': SinkType.COMMAND_EXEC,
    'send': SinkType.COMMAND_EXEC,
    'public_send': SinkType.COMMAND_EXEC,
    'constantize': SinkType.COMMAND_EXEC,

    # Deserialization
    'YAML.load': SinkType.DESERIALIZATION,
    'Marshal.load': SinkType.DESERIALIZATION,
    'JSON.parse': SinkType.DESERIALIZATION,

    # ERB rendering
    'ERB.new': SinkType.XSS,

    # Logging
    'logger.info': SinkType.LOG_OUTPUT,
    'logger.debug': SinkType.LOG_OUTPUT,
    'logger.warn': SinkType.LOG_OUTPUT,
    'logger.error': SinkType.LOG_OUTPUT,
    'Rails.logger': SinkType.LOG_OUTPUT,
}

RUBY_SANITIZERS = {
    # HTML encoding
    'ERB::Util.html_escape': {SinkType.XSS},
    'CGI.escapeHTML': {SinkType.XSS},
    'h': {SinkType.XSS},  # Rails helper
    'sanitize': {SinkType.XSS},
    'strip_tags': {SinkType.XSS},

    # URL encoding
    'CGI.escape': {SinkType.XSS, SinkType.SSRF},
    'URI.encode_www_form': {SinkType.SSRF},
    'ERB::Util.url_encode': {SinkType.SSRF},

    # Path
    'File.basename': {SinkType.FILE_ACCESS},
    'Pathname.new': {SinkType.FILE_ACCESS},

    # Shell
    'Shellwords.escape': {SinkType.COMMAND_EXEC},
    'Shellwords.shellescape': {SinkType.COMMAND_EXEC},

    # Type conversion
    'to_i': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'to_f': {SinkType.SQL_QUERY},
    'Integer': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},

    # ActiveRecord parameterization
    'sanitize_sql': {SinkType.SQL_QUERY},
    'sanitize_sql_array': {SinkType.SQL_QUERY},
    'quote': {SinkType.SQL_QUERY},

    # Safe YAML
    'YAML.safe_load': {SinkType.DESERIALIZATION},
}

RUBY_CONFIG = LanguageDataflowConfig(
    language='ruby',
    taint_sources=RUBY_TAINT_SOURCES,
    sink_methods=RUBY_SINK_METHODS,
    sanitizers=RUBY_SANITIZERS,
)


# ============================================================================
# RUST LANGUAGE SUPPORT
# ============================================================================

RUST_TAINT_SOURCES = {
    # std::env
    'env::var': TaintSource.ENVIRONMENT,
    'env::var_os': TaintSource.ENVIRONMENT,
    'env::vars': TaintSource.ENVIRONMENT,
    'env::args': TaintSource.USER_INPUT,

    # std::fs
    'fs::read_to_string': TaintSource.FILE_INPUT,
    'fs::read': TaintSource.FILE_INPUT,
    'read_line': TaintSource.FILE_INPUT,
    'read_to_string': TaintSource.FILE_INPUT,

    # std::io
    'stdin': TaintSource.USER_INPUT,
    'BufRead::read_line': TaintSource.USER_INPUT,

    # Actix-web
    'Query': TaintSource.HTTP_PARAMETER,
    'Form': TaintSource.HTTP_PARAMETER,
    'Path': TaintSource.PATH_VARIABLE,
    'Json': TaintSource.HTTP_BODY,
    'web::Query': TaintSource.HTTP_PARAMETER,
    'web::Path': TaintSource.PATH_VARIABLE,
    'web::Form': TaintSource.HTTP_PARAMETER,
    'web::Json': TaintSource.HTTP_BODY,

    # Rocket
    'param': TaintSource.PATH_VARIABLE,
    'Form': TaintSource.HTTP_PARAMETER,
    'Json': TaintSource.HTTP_BODY,

    # Axum
    'Query': TaintSource.HTTP_PARAMETER,
    'Path': TaintSource.PATH_VARIABLE,
    'Json': TaintSource.HTTP_BODY,

    # reqwest response
    'text': TaintSource.FILE_INPUT,
    'bytes': TaintSource.FILE_INPUT,
    'json': TaintSource.FILE_INPUT,

    # Database
    'query': TaintSource.DATABASE,
    'query_as': TaintSource.DATABASE,
    'fetch_one': TaintSource.DATABASE,
    'fetch_all': TaintSource.DATABASE,
}

RUST_SINK_METHODS = {
    # SQL (sqlx, diesel, rusqlite)
    'query': SinkType.SQL_QUERY,
    'execute': SinkType.SQL_QUERY,
    'sql_query': SinkType.SQL_QUERY,
    'raw_sql': SinkType.SQL_QUERY,

    # Command execution
    'Command::new': SinkType.COMMAND_EXEC,
    'spawn': SinkType.COMMAND_EXEC,
    'output': SinkType.COMMAND_EXEC,
    'status': SinkType.COMMAND_EXEC,

    # File operations
    'File::create': SinkType.FILE_ACCESS,
    'File::open': SinkType.FILE_ACCESS,
    'fs::write': SinkType.FILE_ACCESS,
    'fs::remove_file': SinkType.FILE_ACCESS,
    'fs::remove_dir': SinkType.FILE_ACCESS,
    'fs::create_dir': SinkType.FILE_ACCESS,

    # Network - SSRF
    'get': SinkType.SSRF,
    'post': SinkType.SSRF,
    'Client::get': SinkType.SSRF,
    'Client::post': SinkType.SSRF,

    # Deserialization
    'from_str': SinkType.DESERIALIZATION,
    'from_slice': SinkType.DESERIALIZATION,
    'from_reader': SinkType.DESERIALIZATION,
    'deserialize': SinkType.DESERIALIZATION,

    # Logging
    'info!': SinkType.LOG_OUTPUT,
    'debug!': SinkType.LOG_OUTPUT,
    'warn!': SinkType.LOG_OUTPUT,
    'error!': SinkType.LOG_OUTPUT,
    'log::info': SinkType.LOG_OUTPUT,

    # Unsafe
    'unsafe': SinkType.COMMAND_EXEC,  # Special handling for unsafe blocks
}

RUST_SANITIZERS = {
    # html_escape crate
    'encode_text': {SinkType.XSS},
    'encode_quoted_attribute': {SinkType.XSS},

    # url crate
    'Url::parse': {SinkType.SSRF},
    'form_urlencoded::byte_serialize': {SinkType.XSS, SinkType.SSRF},

    # Path handling
    'Path::new': {SinkType.FILE_ACCESS},
    'canonicalize': {SinkType.FILE_ACCESS},

    # Type parsing
    'parse': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'from_str': {SinkType.SQL_QUERY},

    # Parameterized queries (sqlx with $1, diesel with .bind())
    'bind': {SinkType.SQL_QUERY},

    # Shell escaping (shell-escape crate)
    'escape': {SinkType.COMMAND_EXEC},
}

RUST_CONFIG = LanguageDataflowConfig(
    language='rust',
    taint_sources=RUST_TAINT_SOURCES,
    sink_methods=RUST_SINK_METHODS,
    sanitizers=RUST_SANITIZERS,
)


# ============================================================================
# SWIFT LANGUAGE SUPPORT
# ============================================================================

SWIFT_TAINT_SOURCES = {
    # URLComponents
    'URLComponents.queryItems': TaintSource.HTTP_PARAMETER,
    'URL.query': TaintSource.HTTP_PARAMETER,
    'URLQueryItem.value': TaintSource.HTTP_PARAMETER,

    # URLRequest
    'URLRequest.allHTTPHeaderFields': TaintSource.HTTP_HEADER,
    'URLRequest.value': TaintSource.HTTP_HEADER,

    # UserDefaults
    'UserDefaults.string': TaintSource.FILE_INPUT,
    'UserDefaults.object': TaintSource.FILE_INPUT,
    'UserDefaults.data': TaintSource.FILE_INPUT,

    # File operations
    'String(contentsOf:)': TaintSource.FILE_INPUT,
    'Data(contentsOf:)': TaintSource.FILE_INPUT,
    'FileManager.contents': TaintSource.FILE_INPUT,

    # ProcessInfo
    'ProcessInfo.environment': TaintSource.ENVIRONMENT,

    # Network response
    'URLSession.dataTask': TaintSource.FILE_INPUT,
    'URLSession.data': TaintSource.FILE_INPUT,

    # Vapor framework
    'req.query': TaintSource.HTTP_PARAMETER,
    'req.content': TaintSource.HTTP_BODY,
    'req.parameters': TaintSource.PATH_VARIABLE,
    'req.headers': TaintSource.HTTP_HEADER,

    # Clipboard
    'UIPasteboard.string': TaintSource.USER_INPUT,

    # Text fields
    'UITextField.text': TaintSource.USER_INPUT,
    'UITextView.text': TaintSource.USER_INPUT,

    # Deep links
    'URL.host': TaintSource.USER_INPUT,
    'URL.path': TaintSource.USER_INPUT,
    'URL.absoluteString': TaintSource.USER_INPUT,
}

SWIFT_SINK_METHODS = {
    # SQL (SQLite.swift, GRDB)
    'execute': SinkType.SQL_QUERY,
    'run': SinkType.SQL_QUERY,
    'prepare': SinkType.SQL_QUERY,
    'sqlite3_exec': SinkType.SQL_QUERY,

    # Process/Command
    'Process.run': SinkType.COMMAND_EXEC,
    'Process.launch': SinkType.COMMAND_EXEC,

    # File operations
    'FileManager.createFile': SinkType.FILE_ACCESS,
    'FileManager.removeItem': SinkType.FILE_ACCESS,
    'FileManager.moveItem': SinkType.FILE_ACCESS,
    'FileManager.copyItem': SinkType.FILE_ACCESS,
    'write(to:)': SinkType.FILE_ACCESS,
    'write(toFile:)': SinkType.FILE_ACCESS,

    # Network - SSRF
    'URLSession.dataTask': SinkType.SSRF,
    'URLSession.data': SinkType.SSRF,
    'URLSession.download': SinkType.SSRF,

    # WebView - XSS
    'WKWebView.load': SinkType.XSS,
    'WKWebView.loadHTMLString': SinkType.XSS,
    'UIWebView.loadRequest': SinkType.XSS,
    'evaluateJavaScript': SinkType.XSS,

    # URL schemes
    'UIApplication.open': SinkType.SSRF,
    'UIApplication.canOpenURL': SinkType.SSRF,

    # Deserialization
    'JSONDecoder.decode': SinkType.DESERIALIZATION,
    'PropertyListDecoder.decode': SinkType.DESERIALIZATION,
    'NSKeyedUnarchiver.unarchiveObject': SinkType.DESERIALIZATION,
    'NSKeyedUnarchiver.unarchivedObject': SinkType.DESERIALIZATION,

    # Logging
    'print': SinkType.LOG_OUTPUT,
    'NSLog': SinkType.LOG_OUTPUT,
    'os_log': SinkType.LOG_OUTPUT,
    'Logger.log': SinkType.LOG_OUTPUT,
}

SWIFT_SANITIZERS = {
    # URL encoding
    'addingPercentEncoding': {SinkType.XSS, SinkType.SSRF},
    'removingPercentEncoding': {SinkType.XSS},

    # HTML (not built-in, but common libraries)
    'htmlEscape': {SinkType.XSS},

    # Path handling
    'lastPathComponent': {SinkType.FILE_ACCESS},
    'standardizedFileURL': {SinkType.FILE_ACCESS},
    'resolvingSymlinksInPath': {SinkType.FILE_ACCESS},

    # Type conversion
    'Int.init': {SinkType.SQL_QUERY, SinkType.COMMAND_EXEC},
    'Double.init': {SinkType.SQL_QUERY},

    # Parameterized queries
    'bind': {SinkType.SQL_QUERY},

    # Secure coding
    'NSSecureCoding': {SinkType.DESERIALIZATION},
}

SWIFT_CONFIG = LanguageDataflowConfig(
    language='swift',
    taint_sources=SWIFT_TAINT_SOURCES,
    sink_methods=SWIFT_SINK_METHODS,
    sanitizers=SWIFT_SANITIZERS,
)


# ============================================================================
# REGISTRY
# ============================================================================

LANGUAGE_CONFIGS: Dict[str, LanguageDataflowConfig] = {
    'go': GO_CONFIG,
    'csharp': CSHARP_CONFIG,
    'cs': CSHARP_CONFIG,  # Alias
    'kotlin': KOTLIN_CONFIG,
    'kt': KOTLIN_CONFIG,  # Alias
    'php': PHP_CONFIG,
    'ruby': RUBY_CONFIG,
    'rb': RUBY_CONFIG,  # Alias
    'rust': RUST_CONFIG,
    'rs': RUST_CONFIG,  # Alias
    'swift': SWIFT_CONFIG,
}


def get_language_config(language: str) -> Optional[LanguageDataflowConfig]:
    """Get dataflow configuration for a language."""
    return LANGUAGE_CONFIGS.get(language.lower())


def get_all_taint_sources(language: str) -> Dict[str, TaintSource]:
    """Get all taint sources for a language."""
    config = get_language_config(language)
    return config.taint_sources if config else {}


def get_all_sinks(language: str) -> Dict[str, SinkType]:
    """Get all sinks for a language."""
    config = get_language_config(language)
    return config.sink_methods if config else {}


def get_all_sanitizers(language: str) -> Dict[str, Set[SinkType]]:
    """Get all sanitizers for a language."""
    config = get_language_config(language)
    return config.sanitizers if config else {}


def is_taint_source(language: str, method_name: str) -> Optional[TaintSource]:
    """Check if a method is a taint source for the given language."""
    config = get_language_config(language)
    if not config:
        return None
    return config.taint_sources.get(method_name)


def is_sink(language: str, method_name: str) -> Optional[SinkType]:
    """Check if a method is a sink for the given language."""
    config = get_language_config(language)
    if not config:
        return None
    return config.sink_methods.get(method_name)


def is_sanitizer(language: str, method_name: str, sink_type: SinkType) -> bool:
    """Check if a method sanitizes taint for a specific sink type."""
    config = get_language_config(language)
    if not config:
        return False
    sanitized_sinks = config.sanitizers.get(method_name, set())
    return sink_type in sanitized_sinks


def get_source_annotation(language: str, annotation: str) -> Optional[TaintSource]:
    """Check if an annotation marks a taint source."""
    config = get_language_config(language)
    if not config:
        return None
    return config.source_annotations.get(annotation)


# ============================================================================
# COMBINED LOOKUP (Merges with Java/Python/JavaScript)
# ============================================================================

def get_combined_sources() -> Dict[str, Dict[str, TaintSource]]:
    """Get all taint sources across all languages."""
    return {lang: config.taint_sources for lang, config in LANGUAGE_CONFIGS.items()}


def get_combined_sinks() -> Dict[str, Dict[str, SinkType]]:
    """Get all sinks across all languages."""
    return {lang: config.sink_methods for lang, config in LANGUAGE_CONFIGS.items()}


def get_combined_sanitizers() -> Dict[str, Dict[str, Set[SinkType]]]:
    """Get all sanitizers across all languages."""
    return {lang: config.sanitizers for lang, config in LANGUAGE_CONFIGS.items()}
