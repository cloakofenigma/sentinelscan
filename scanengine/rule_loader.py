"""
Rule loader - parses YAML rule files into Rule objects
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from .models import Rule, RulePattern, Remediation, Severity, Confidence

logger = logging.getLogger(__name__)


class RuleLoader:
    """Loads and parses security rules from YAML files"""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or Path(__file__).parent.parent / "rules"
        self.rules: List[Rule] = []
        self._loaded_files: List[str] = []

    def load_all_rules(self) -> List[Rule]:
        """Load all rules from the rules directory"""
        self.rules = []
        self._loaded_files = []

        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return self.rules

        # Find all YAML files recursively
        yaml_files = list(self.rules_dir.rglob("*.yaml")) + list(self.rules_dir.rglob("*.yml"))

        for yaml_file in yaml_files:
            try:
                rules = self.load_rules_from_file(yaml_file)
                self.rules.extend(rules)
                self._loaded_files.append(str(yaml_file))
                logger.info(f"Loaded {len(rules)} rules from {yaml_file.name}")
            except Exception as e:
                logger.error(f"Failed to load rules from {yaml_file}: {e}")

        logger.info(f"Total rules loaded: {len(self.rules)}")
        return self.rules

    def load_rules_from_file(self, filepath: Path) -> List[Rule]:
        """Load rules from a single YAML file"""
        rules = []

        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not data:
            return rules

        # Get metadata for context
        metadata = data.get('metadata', {})

        # Parse each rule
        raw_rules = data.get('rules', [])
        for raw_rule in raw_rules:
            try:
                rule = self._parse_rule(raw_rule, metadata)
                if rule:
                    rules.append(rule)
            except Exception as e:
                rule_id = raw_rule.get('id', 'unknown')
                logger.error(f"Failed to parse rule {rule_id}: {e}")

        return rules

    def _parse_rule(self, raw: Dict[str, Any], metadata: Dict[str, Any]) -> Optional[Rule]:
        """Parse a single rule from raw YAML data"""
        if not raw.get('id') or not raw.get('name'):
            return None

        # Parse severity
        severity_str = raw.get('severity', 'medium').lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.MEDIUM

        # Parse confidence
        confidence_str = raw.get('confidence', 'medium').lower()
        try:
            confidence = Confidence(confidence_str)
        except ValueError:
            confidence = Confidence.MEDIUM

        # Parse patterns
        patterns = self._parse_patterns(raw.get('detection', {}))

        # Parse remediation
        remediation = self._parse_remediation(raw.get('remediation', {}))

        return Rule(
            id=raw['id'],
            name=raw['name'],
            description=raw.get('description', ''),
            severity=severity,
            confidence=confidence,
            cwe=raw.get('cwe'),
            owasp=raw.get('owasp') or metadata.get('category'),
            cve=raw.get('cve'),
            tags=raw.get('tags', []),
            languages=raw.get('languages', []),
            file_patterns=raw.get('file_patterns', []),
            patterns=patterns,
            remediation=remediation,
            references=raw.get('references', []),
            enabled=raw.get('enabled', True),
        )

    def _parse_patterns(self, detection: Dict[str, Any]) -> List[RulePattern]:
        """Parse detection patterns from rule"""
        patterns = []

        # Handle patterns list
        raw_patterns = detection.get('patterns', [])
        for raw in raw_patterns:
            if isinstance(raw, str):
                patterns.append(RulePattern(pattern=raw))
            elif isinstance(raw, dict):
                patterns.append(RulePattern(
                    pattern=raw.get('pattern', ''),
                    language=raw.get('language'),
                    description=raw.get('description'),
                    context=raw.get('context'),
                    missing=raw.get('missing'),
                    case_insensitive=raw.get('case_insensitive', False),
                ))

        return patterns

    def _parse_remediation(self, raw: Dict[str, Any]) -> Optional[Remediation]:
        """Parse remediation section"""
        if not raw:
            return None

        description = raw.get('description', '')
        code_examples = {}

        # Parse code examples
        code_example = raw.get('code_example', {})
        if isinstance(code_example, dict):
            code_examples = code_example
        elif isinstance(code_example, str):
            code_examples['default'] = code_example

        return Remediation(
            description=description,
            code_examples=code_examples,
        )

    def get_rules_for_language(self, language: str) -> List[Rule]:
        """Get rules applicable to a specific language"""
        language = language.lower()
        return [
            rule for rule in self.rules
            if not rule.languages or language in [l.lower() for l in rule.languages]
        ]

    def get_rules_by_severity(self, severity: Severity) -> List[Rule]:
        """Get rules of a specific severity"""
        return [rule for rule in self.rules if rule.severity == severity]

    def get_rules_by_tag(self, tag: str) -> List[Rule]:
        """Get rules with a specific tag"""
        tag = tag.lower()
        return [rule for rule in self.rules if tag in [t.lower() for t in rule.tags]]

    def get_enabled_rules(self) -> List[Rule]:
        """Get only enabled rules"""
        return [rule for rule in self.rules if rule.enabled]

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Get a specific rule by ID"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    @property
    def stats(self) -> Dict[str, Any]:
        """Get statistics about loaded rules"""
        severity_counts = {}
        for severity in Severity:
            severity_counts[severity.value] = len(self.get_rules_by_severity(severity))

        return {
            'total_rules': len(self.rules),
            'enabled_rules': len(self.get_enabled_rules()),
            'files_loaded': len(self._loaded_files),
            'by_severity': severity_counts,
        }
