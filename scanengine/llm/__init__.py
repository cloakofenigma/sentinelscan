"""
LLM Integration Module for SentinelScan
Phase 4: LLM-based vulnerability analysis
Phase 8: Advanced LLM features (cost estimation, prioritization, parallel analysis)
"""

from .client import LLMClient, LLMConfig, create_llm_client
from .prompts import PromptTemplate, SecurityPrompts
from .analyzer import LLMSecurityAnalyzer, EnhancedFinding, AnalysisResult, create_llm_analyzer
from .context import ContextAssembler, CodeContext, create_context_assembler
from .phase8 import (
    Phase8Analyzer,
    CostEstimator,
    CostEstimate,
    FindingPrioritizer,
    PrioritizedFinding,
    ParallelAnalyzer,
    create_phase8_analyzer,
)

__all__ = [
    # Phase 4 - Core LLM
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
    # Phase 8 - Advanced LLM
    'Phase8Analyzer',
    'CostEstimator',
    'CostEstimate',
    'FindingPrioritizer',
    'PrioritizedFinding',
    'ParallelAnalyzer',
    'create_phase8_analyzer',
]
