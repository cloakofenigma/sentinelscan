"""
LLM Integration Module for SentinelScan
Phase 4: LLM-based vulnerability analysis
"""

from .client import LLMClient, LLMConfig, create_llm_client
from .prompts import PromptTemplate, SecurityPrompts
from .analyzer import LLMSecurityAnalyzer, EnhancedFinding, AnalysisResult, create_llm_analyzer
from .context import ContextAssembler, CodeContext, create_context_assembler

__all__ = [
    'LLMClient',
    'LLMConfig',
    'create_llm_client',
    'PromptTemplate',
    'SecurityPrompts',
    'LLMSecurityAnalyzer',
    'EnhancedFinding',
    'AnalysisResult',
    'create_llm_analyzer',
    'ContextAssembler',
    'CodeContext',
    'create_context_assembler',
]
