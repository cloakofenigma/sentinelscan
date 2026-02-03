"""
Prompt Templates for LLM-based Security Analysis
"""

from __future__ import annotations

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from string import Template


@dataclass
class PromptTemplate:
    """A reusable prompt template"""
    name: str
    system: str
    user_template: str
    description: str = ""

    def format(self, **kwargs) -> str:
        """Format the user template with provided values"""
        return Template(self.user_template).safe_substitute(**kwargs)

    def get_messages(self, **kwargs) -> tuple:
        """Get system prompt and formatted user message"""
        return self.system, self.format(**kwargs)


class SecurityPrompts:
    """Collection of security analysis prompts"""

    # System prompt for security analysis
    SECURITY_ANALYST_SYSTEM = """You are an expert application security analyst specializing in code review and vulnerability assessment. Your role is to:

1. Analyze code for security vulnerabilities with precision
2. Explain vulnerabilities in clear, technical terms
3. Assess real-world exploitability and impact
4. Provide actionable remediation guidance
5. Distinguish between true vulnerabilities and false positives

Always be thorough but concise. Focus on security-relevant details. When uncertain, explain your reasoning and confidence level."""

    # Vulnerability explanation prompt
    EXPLAIN_VULNERABILITY = PromptTemplate(
        name="explain_vulnerability",
        description="Generate detailed explanation of a security vulnerability",
        system=SECURITY_ANALYST_SYSTEM,
        user_template="""Analyze this security finding and provide a detailed explanation.

**Finding:**
- Rule: $rule_id - $rule_name
- Severity: $severity
- CWE: $cwe
- File: $file_path:$line_number

**Vulnerable Code:**
```$language
$code_snippet
```

$context

**Provide your analysis in this JSON format:**
```json
{
    "summary": "One-sentence summary of the vulnerability",
    "explanation": "Detailed technical explanation of the vulnerability",
    "attack_vector": "How an attacker could exploit this",
    "impact": {
        "confidentiality": "low/medium/high",
        "integrity": "low/medium/high",
        "availability": "low/medium/high",
        "description": "Business impact description"
    },
    "exploitability": {
        "difficulty": "trivial/easy/moderate/difficult",
        "prerequisites": ["list of prerequisites for exploitation"],
        "description": "Assessment of real-world exploitability"
    },
    "confidence": "high/medium/low",
    "confidence_reasoning": "Why you are confident/uncertain about this finding"
}
```"""
    )

    # Remediation generation prompt
    GENERATE_REMEDIATION = PromptTemplate(
        name="generate_remediation",
        description="Generate fix suggestions for a vulnerability",
        system=SECURITY_ANALYST_SYSTEM,
        user_template="""Generate remediation guidance for this security vulnerability.

**Finding:**
- Rule: $rule_id - $rule_name
- Severity: $severity
- CWE: $cwe
- File: $file_path:$line_number

**Vulnerable Code:**
```$language
$code_snippet
```

$context

**Provide remediation in this JSON format:**
```json
{
    "primary_fix": {
        "description": "Description of the recommended fix",
        "code": "The fixed code snippet",
        "explanation": "Why this fix works"
    },
    "alternative_fixes": [
        {
            "description": "Alternative approach",
            "code": "Alternative code if applicable",
            "tradeoffs": "Pros and cons of this approach"
        }
    ],
    "prevention": [
        "Best practices to prevent this type of vulnerability"
    ],
    "testing": "How to verify the fix works",
    "references": ["Relevant documentation or resources"]
}
```"""
    )

    # False positive analysis prompt
    ANALYZE_FALSE_POSITIVE = PromptTemplate(
        name="analyze_false_positive",
        description="Determine if a finding is a false positive",
        system=SECURITY_ANALYST_SYSTEM,
        user_template="""Analyze this security finding to determine if it's a true vulnerability or a false positive.

**Finding:**
- Rule: $rule_id - $rule_name
- Severity: $severity
- CWE: $cwe
- File: $file_path:$line_number

**Flagged Code:**
```$language
$code_snippet
```

**Extended Context (surrounding code, related functions):**
```$language
$extended_context
```

$additional_context

**Analyze and respond in this JSON format:**
```json
{
    "verdict": "true_positive/false_positive/uncertain",
    "confidence": "high/medium/low",
    "reasoning": "Detailed explanation of your analysis",
    "evidence": {
        "for_vulnerability": ["Evidence supporting this is a real vulnerability"],
        "against_vulnerability": ["Evidence suggesting this is a false positive"]
    },
    "mitigating_factors": ["Any factors that reduce the risk"],
    "recommendation": "What action should be taken"
}
```"""
    )

    # Batch analysis prompt for multiple findings
    BATCH_ANALYZE = PromptTemplate(
        name="batch_analyze",
        description="Analyze multiple findings in a single request",
        system=SECURITY_ANALYST_SYSTEM,
        user_template="""Analyze these security findings and prioritize them.

**Findings:**
$findings_list

**Code Context:**
```$language
$code_context
```

**Provide analysis in this JSON format:**
```json
{
    "findings": [
        {
            "id": "finding identifier",
            "verdict": "true_positive/false_positive/uncertain",
            "adjusted_severity": "critical/high/medium/low/info",
            "priority_rank": 1,
            "brief_explanation": "Short explanation"
        }
    ],
    "summary": {
        "true_positives": 0,
        "false_positives": 0,
        "uncertain": 0,
        "top_priorities": ["List of most critical findings to address"]
    }
}
```"""
    )

    # Code review prompt for general analysis
    CODE_REVIEW = PromptTemplate(
        name="code_review",
        description="General security code review",
        system=SECURITY_ANALYST_SYSTEM,
        user_template="""Perform a security code review on this code.

**File:** $file_path
**Language:** $language

**Code:**
```$language
$code
```

**Focus areas:** $focus_areas

**Provide your review in this JSON format:**
```json
{
    "findings": [
        {
            "line": 0,
            "severity": "critical/high/medium/low/info",
            "category": "vulnerability category",
            "title": "Short title",
            "description": "Description of the issue",
            "cwe": "CWE-XXX if applicable",
            "recommendation": "How to fix"
        }
    ],
    "positive_observations": ["Good security practices observed"],
    "overall_risk": "high/medium/low",
    "summary": "Brief summary of the security posture"
}
```"""
    )

    # Dataflow analysis prompt
    DATAFLOW_ANALYSIS = PromptTemplate(
        name="dataflow_analysis",
        description="Analyze data flow for taint tracking",
        system=SECURITY_ANALYST_SYSTEM,
        user_template="""Analyze the data flow in this code to determine if tainted data reaches a dangerous sink.

**Source (user input):**
- Type: $source_type
- Variable: $source_variable
- Location: $source_location

**Sink (dangerous operation):**
- Type: $sink_type
- Location: $sink_location

**Code path:**
```$language
$code_path
```

**Analyze and respond in this JSON format:**
```json
{
    "tainted_flow_exists": true/false,
    "confidence": "high/medium/low",
    "flow_description": "Description of how data flows from source to sink",
    "sanitization_present": true/false,
    "sanitization_details": "Description of any sanitization found",
    "is_exploitable": true/false,
    "exploitability_reasoning": "Why this is/isn't exploitable",
    "recommendation": "What should be done"
}
```"""
    )

    # Spring-specific analysis
    SPRING_SECURITY_REVIEW = PromptTemplate(
        name="spring_security_review",
        description="Review Spring Security configuration",
        system=SECURITY_ANALYST_SYSTEM,
        user_template="""Review this Spring Security configuration for security issues.

**Security Configuration:**
```java
$security_config
```

**Related Endpoints:**
$endpoints

**Application Context:**
$app_context

**Provide your review in this JSON format:**
```json
{
    "issues": [
        {
            "severity": "critical/high/medium/low",
            "category": "category",
            "description": "Issue description",
            "location": "Where in config",
            "recommendation": "How to fix"
        }
    ],
    "authentication_assessment": "Assessment of authentication setup",
    "authorization_assessment": "Assessment of authorization setup",
    "csrf_status": "enabled/disabled/partial",
    "cors_status": "Assessment of CORS configuration",
    "overall_security_posture": "Summary assessment"
}
```"""
    )

    # MyBatis SQL analysis
    MYBATIS_SQL_REVIEW = PromptTemplate(
        name="mybatis_sql_review",
        description="Review MyBatis mapper for SQL injection",
        system=SECURITY_ANALYST_SYSTEM,
        user_template="""Review this MyBatis mapper for SQL injection vulnerabilities.

**Mapper File:** $file_path

**SQL Statement:**
```xml
$sql_statement
```

**Statement Context:**
- ID: $statement_id
- Type: $statement_type
- Parameters: $parameters

**Analyze and respond in this JSON format:**
```json
{
    "vulnerable": true/false,
    "vulnerability_type": "SQL injection type if vulnerable",
    "confidence": "high/medium/low",
    "vulnerable_parameters": ["List of vulnerable parameter usages"],
    "safe_parameters": ["List of safely used parameters"],
    "explanation": "Detailed explanation",
    "fix": {
        "description": "How to fix",
        "safe_code": "The fixed XML/SQL"
    }
}
```"""
    )

    @classmethod
    def get_prompt(cls, name: str) -> Optional[PromptTemplate]:
        """Get a prompt template by name"""
        prompts = {
            'explain_vulnerability': cls.EXPLAIN_VULNERABILITY,
            'generate_remediation': cls.GENERATE_REMEDIATION,
            'analyze_false_positive': cls.ANALYZE_FALSE_POSITIVE,
            'batch_analyze': cls.BATCH_ANALYZE,
            'code_review': cls.CODE_REVIEW,
            'dataflow_analysis': cls.DATAFLOW_ANALYSIS,
            'spring_security_review': cls.SPRING_SECURITY_REVIEW,
            'mybatis_sql_review': cls.MYBATIS_SQL_REVIEW,
        }
        return prompts.get(name)

    @classmethod
    def list_prompts(cls) -> List[str]:
        """List all available prompt names"""
        return [
            'explain_vulnerability',
            'generate_remediation',
            'analyze_false_positive',
            'batch_analyze',
            'code_review',
            'dataflow_analysis',
            'spring_security_review',
            'mybatis_sql_review',
        ]
