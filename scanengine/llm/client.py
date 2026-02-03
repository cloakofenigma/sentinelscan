"""
LLM Client - Interface to Claude API for security analysis
"""

from __future__ import annotations

import os
import time
import json
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger(__name__)

# Check for anthropic SDK
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("anthropic SDK not installed. LLM features will be disabled.")


@dataclass
class LLMConfig:
    """Configuration for LLM client"""
    api_key: Optional[str] = None
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.0  # Deterministic for security analysis
    timeout: int = 120
    max_retries: int = 3
    retry_delay: float = 1.0
    cache_enabled: bool = True
    cache_dir: Optional[Path] = None

    def __post_init__(self):
        if self.api_key is None:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        if self.cache_dir is None:
            self.cache_dir = Path.home() / ".cache" / "sentinelscan" / "llm"


@dataclass
class LLMResponse:
    """Response from LLM"""
    content: str
    model: str
    input_tokens: int
    output_tokens: int
    stop_reason: str
    cached: bool = False
    latency_ms: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> Dict[str, Any]:
        return {
            'content': self.content,
            'model': self.model,
            'input_tokens': self.input_tokens,
            'output_tokens': self.output_tokens,
            'total_tokens': self.total_tokens,
            'stop_reason': self.stop_reason,
            'cached': self.cached,
            'latency_ms': self.latency_ms,
        }


@dataclass
class UsageStats:
    """Track LLM usage statistics"""
    total_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_latency_ms: float = 0.0
    errors: int = 0

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    @property
    def avg_latency_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_latency_ms / self.total_requests

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        if total == 0:
            return 0.0
        return self.cache_hits / total

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_requests': self.total_requests,
            'total_input_tokens': self.total_input_tokens,
            'total_output_tokens': self.total_output_tokens,
            'total_tokens': self.total_tokens,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate': f"{self.cache_hit_rate:.1%}",
            'avg_latency_ms': f"{self.avg_latency_ms:.0f}",
            'errors': self.errors,
        }


class LLMClient:
    """
    Client for interacting with Claude API for security analysis.
    Features:
    - Automatic retries with exponential backoff
    - Response caching for repeated queries
    - Token usage tracking
    - Structured output parsing
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.stats = UsageStats()
        self._client = None
        self._cache: Dict[str, LLMResponse] = {}

        if ANTHROPIC_AVAILABLE and self.config.api_key:
            self._client = anthropic.Anthropic(api_key=self.config.api_key)
            logger.info(f"LLM client initialized with model: {self.config.model}")
        else:
            if not ANTHROPIC_AVAILABLE:
                logger.warning("Anthropic SDK not available")
            elif not self.config.api_key:
                logger.warning("No API key provided")

        # Ensure cache directory exists
        if self.config.cache_enabled and self.config.cache_dir:
            self.config.cache_dir.mkdir(parents=True, exist_ok=True)

    @property
    def is_available(self) -> bool:
        """Check if LLM client is properly configured"""
        return self._client is not None

    def _get_cache_key(self, messages: List[Dict], system: Optional[str] = None) -> str:
        """Generate cache key for a request"""
        content = json.dumps({
            'messages': messages,
            'system': system,
            'model': self.config.model,
            'temperature': self.config.temperature,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _load_from_cache(self, cache_key: str) -> Optional[LLMResponse]:
        """Load response from cache"""
        if not self.config.cache_enabled:
            return None

        # Check memory cache
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Check disk cache
        if self.config.cache_dir:
            cache_file = self.config.cache_dir / f"{cache_key}.json"
            if cache_file.exists():
                try:
                    data = json.loads(cache_file.read_text())
                    response = LLMResponse(
                        content=data['content'],
                        model=data['model'],
                        input_tokens=data['input_tokens'],
                        output_tokens=data['output_tokens'],
                        stop_reason=data['stop_reason'],
                        cached=True,
                    )
                    self._cache[cache_key] = response
                    return response
                except Exception as e:
                    logger.debug(f"Failed to load cache: {e}")

        return None

    def _save_to_cache(self, cache_key: str, response: LLMResponse):
        """Save response to cache"""
        if not self.config.cache_enabled:
            return

        # Save to memory cache
        self._cache[cache_key] = response

        # Save to disk cache
        if self.config.cache_dir:
            cache_file = self.config.cache_dir / f"{cache_key}.json"
            try:
                cache_file.write_text(json.dumps(response.to_dict()))
            except Exception as e:
                logger.debug(f"Failed to save cache: {e}")

    def chat(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        use_cache: bool = True,
    ) -> LLMResponse:
        """
        Send a chat request to the LLM.

        Args:
            messages: List of message dicts with 'role' and 'content'
            system: Optional system prompt
            max_tokens: Override max tokens
            temperature: Override temperature
            use_cache: Whether to use caching for this request

        Returns:
            LLMResponse with the model's response
        """
        if not self.is_available:
            raise RuntimeError("LLM client not available. Check API key and SDK installation.")

        # Check cache
        cache_key = self._get_cache_key(messages, system) if use_cache else None
        if cache_key:
            cached = self._load_from_cache(cache_key)
            if cached:
                self.stats.cache_hits += 1
                self.stats.total_requests += 1
                return cached
            self.stats.cache_misses += 1

        # Prepare request
        request_params = {
            'model': self.config.model,
            'max_tokens': max_tokens or self.config.max_tokens,
            'messages': messages,
        }

        if system:
            request_params['system'] = system

        if temperature is not None:
            request_params['temperature'] = temperature
        elif self.config.temperature is not None:
            request_params['temperature'] = self.config.temperature

        # Send request with retries
        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                response = self._client.messages.create(**request_params)
                latency_ms = (time.time() - start_time) * 1000

                # Parse response
                llm_response = LLMResponse(
                    content=response.content[0].text if response.content else "",
                    model=response.model,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    stop_reason=response.stop_reason,
                    latency_ms=latency_ms,
                )

                # Update stats
                self.stats.total_requests += 1
                self.stats.total_input_tokens += llm_response.input_tokens
                self.stats.total_output_tokens += llm_response.output_tokens
                self.stats.total_latency_ms += latency_ms

                # Cache response
                if cache_key:
                    self._save_to_cache(cache_key, llm_response)

                return llm_response

            except anthropic.RateLimitError as e:
                last_error = e
                wait_time = self.config.retry_delay * (2 ** attempt)
                logger.warning(f"Rate limited, waiting {wait_time}s (attempt {attempt + 1})")
                time.sleep(wait_time)

            except anthropic.APIError as e:
                last_error = e
                self.stats.errors += 1
                if attempt < self.config.max_retries - 1:
                    wait_time = self.config.retry_delay * (2 ** attempt)
                    logger.warning(f"API error: {e}, retrying in {wait_time}s")
                    time.sleep(wait_time)

            except Exception as e:
                last_error = e
                self.stats.errors += 1
                logger.error(f"Unexpected error: {e}")
                break

        raise RuntimeError(f"LLM request failed after {self.config.max_retries} attempts: {last_error}")

    def analyze(
        self,
        prompt: str,
        code: str,
        context: Optional[str] = None,
        system: Optional[str] = None,
    ) -> LLMResponse:
        """
        Convenience method for code analysis.

        Args:
            prompt: The analysis prompt/question
            code: The code to analyze
            context: Optional additional context
            system: Optional system prompt

        Returns:
            LLMResponse with analysis result
        """
        # Build message content
        content_parts = []

        if context:
            content_parts.append(f"Context:\n{context}\n")

        content_parts.append(f"Code:\n```\n{code}\n```\n")
        content_parts.append(f"Task:\n{prompt}")

        messages = [{"role": "user", "content": "\n".join(content_parts)}]

        return self.chat(messages, system=system)

    def analyze_json(
        self,
        prompt: str,
        code: str,
        context: Optional[str] = None,
        system: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze code and return structured JSON response.

        Args:
            prompt: The analysis prompt (should request JSON output)
            code: The code to analyze
            context: Optional additional context
            system: Optional system prompt

        Returns:
            Parsed JSON response as dict
        """
        response = self.analyze(prompt, code, context, system)

        # Try to parse JSON from response
        content = response.content.strip()

        # Handle markdown code blocks
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]

        try:
            return json.loads(content.strip())
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            # Return raw content wrapped in dict
            return {"raw_response": response.content, "parse_error": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics"""
        return self.stats.to_dict()

    def clear_cache(self):
        """Clear the response cache"""
        self._cache.clear()
        if self.config.cache_dir and self.config.cache_dir.exists():
            for cache_file in self.config.cache_dir.glob("*.json"):
                cache_file.unlink()
        logger.info("LLM cache cleared")


def create_llm_client(
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-20250514",
    cache_enabled: bool = True,
) -> LLMClient:
    """Factory function to create an LLM client"""
    config = LLMConfig(
        api_key=api_key,
        model=model,
        cache_enabled=cache_enabled,
    )
    return LLMClient(config)
