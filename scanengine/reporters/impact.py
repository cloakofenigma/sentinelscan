"""
Impact descriptions for security findings.

Maps CWE IDs, OWASP categories, and rule tags to human-readable
impact statements for reports.
"""

# CWE-based impact descriptions
CWE_IMPACT = {
    "CWE-89": "An attacker can execute arbitrary SQL queries against the database, potentially reading, modifying, or deleting sensitive data. This may lead to full database compromise, authentication bypass, or data exfiltration.",
    "CWE-78": "An attacker can execute arbitrary operating system commands on the server, leading to full system compromise, data theft, malware installation, or lateral movement within the network.",
    "CWE-22": "An attacker can access files and directories outside the intended path, potentially reading sensitive configuration files, source code, credentials, or system files such as /etc/passwd.",
    "CWE-79": "An attacker can inject malicious scripts into web pages viewed by other users, enabling session hijacking, credential theft, defacement, or redirection to malicious sites.",
    "CWE-918": "An attacker can force the server to make requests to internal resources, potentially accessing internal services, cloud metadata endpoints (e.g., AWS IMDSv1), or scanning internal networks.",
    "CWE-502": "An attacker can execute arbitrary code by supplying crafted serialized objects, leading to remote code execution, denial of service, or complete system compromise.",
    "CWE-862": "Missing authorization checks allow unauthorized users to access restricted functionality or data, potentially leading to privilege escalation, data leakage, or unauthorized actions.",
    "CWE-863": "Incorrect authorization logic allows users to perform actions or access resources beyond their intended permissions, leading to horizontal or vertical privilege escalation.",
    "CWE-639": "An attacker can access other users' data by manipulating direct object references (e.g., changing an ID parameter), leading to unauthorized data access or modification.",
    "CWE-532": "Sensitive information written to log files can be exposed to unauthorized parties through log aggregation systems, shared storage, or compromised log management infrastructure.",
    "CWE-798": "Hardcoded credentials in source code can be extracted by anyone with access to the codebase or compiled binaries, providing unauthorized access to systems, APIs, or databases.",
    "CWE-327": "Use of weak or broken cryptographic algorithms can allow attackers to decrypt sensitive data, forge signatures, or bypass integrity checks.",
    "CWE-328": "Use of weak hashing algorithms (e.g., MD5, SHA1) for passwords or integrity checks can allow attackers to recover original values through brute-force or rainbow table attacks.",
    "CWE-352": "Without CSRF protection, an attacker can trick authenticated users into performing unintended actions (e.g., changing passwords, making transactions) by crafting malicious web pages.",
    "CWE-942": "Overly permissive CORS configuration allows malicious websites to make authenticated requests to the application, potentially accessing sensitive data or performing actions on behalf of users.",
    "CWE-16": "Security misconfiguration can expose the application to various attacks depending on the specific misconfiguration, including unauthorized access, information disclosure, or denial of service.",
    "CWE-330": "Use of predictable random values for security-sensitive operations (tokens, session IDs, cryptographic keys) allows attackers to predict or brute-force these values.",
}

# Tag-based impact descriptions (fallback when CWE is not available)
TAG_IMPACT = {
    "sql-injection": "Attackers can manipulate database queries to read, modify, or delete data. May lead to authentication bypass or full database compromise.",
    "command-injection": "Attackers can execute arbitrary system commands, leading to full server compromise.",
    "path-traversal": "Attackers can read or write files outside the intended directory, potentially accessing sensitive data.",
    "xss": "Attackers can execute scripts in users' browsers, stealing sessions, credentials, or performing actions on their behalf.",
    "ssrf": "Attackers can make the server access internal resources or external services, bypassing firewalls and access controls.",
    "idor": "Attackers can access other users' data by manipulating object references in requests.",
    "logging": "Sensitive data in logs may be exposed through log management systems or shared access to log files.",
    "sensitive-data": "Exposure of sensitive information can lead to identity theft, account compromise, or regulatory violations.",
    "authentication": "Weak authentication controls can allow unauthorized access to user accounts and protected resources.",
    "authorization": "Broken authorization can allow users to escalate privileges or access restricted functionality.",
    "csrf": "Attackers can trick users into performing unintended actions while authenticated.",
    "cors": "Misconfigured CORS allows cross-origin attacks, enabling data theft from authenticated sessions.",
    "secrets": "Exposed secrets (API keys, passwords, tokens) provide direct unauthorized access to external services or systems.",
    "credentials": "Hardcoded or exposed credentials allow unauthorized access to systems and services.",
    "deserialization": "Unsafe deserialization can lead to remote code execution or denial of service.",
    "crypto": "Weak cryptography can be broken by attackers, exposing encrypted data or allowing forgery.",
    "spring": "Framework misconfiguration may weaken the overall security posture of the application.",
    "mybatis": "SQL injection through MyBatis interpolation can lead to unauthorized database access.",
    "security-config": "Permissive security configuration reduces the effectiveness of security controls.",
    "missing-validation": "Missing input validation allows malformed or malicious data to reach application logic.",
}

# Severity-based generic impact (last resort)
SEVERITY_IMPACT = {
    "critical": "This vulnerability poses an immediate and severe risk. Exploitation can lead to full system compromise, mass data breach, or complete loss of confidentiality, integrity, and availability.",
    "high": "This vulnerability poses a significant risk. Exploitation can lead to unauthorized access to sensitive data, privilege escalation, or disruption of critical functionality.",
    "medium": "This vulnerability poses a moderate risk. Exploitation may require specific conditions but can lead to partial data exposure or degraded security controls.",
    "low": "This vulnerability poses a limited risk. Exploitation is unlikely or impact is minimal, but it represents a deviation from security best practices.",
    "info": "This is an informational observation about the security posture. No direct exploitation risk, but may indicate areas for improvement.",
}


def get_impact(finding) -> str:
    """Get impact description for a finding."""
    # 1. Try CWE-based impact
    if finding.cwe and finding.cwe in CWE_IMPACT:
        return CWE_IMPACT[finding.cwe]

    # 2. Try tag-based impact
    if finding.tags:
        for tag in finding.tags:
            tag_lower = tag.lower()
            if tag_lower in TAG_IMPACT:
                return TAG_IMPACT[tag_lower]
            # Try partial match
            for key, val in TAG_IMPACT.items():
                if key in tag_lower or tag_lower in key:
                    return val

    # 3. Fall back to severity-based
    sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
    return SEVERITY_IMPACT.get(sev, SEVERITY_IMPACT["medium"])
