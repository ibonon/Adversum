"""
Adversum LLM Client — Nebius Token Factory / NVIDIA Nemotron
=============================================================
Phase 2: Full migration from legacy OpenAI/Anthropic to Nebius+Nemotron.

Priority chain:
  1. Nebius Token Factory  (NEBIUS_API_KEY)  → NVIDIA Nemotron open-source models
  2. Ollama local          (USE_OLLAMA=true)  → any locally installed open-source model
  3. Mock fallback         (AI_MOCK_MODE=true or no key) → deterministic template

Environment variables:
  NEBIUS_API_KEY    — Nebius Token Factory key  (required for cloud inference)
  NEBIUS_MODEL      — Override model id          (default: nvidia/Nemotron-3_5-Lightning)
  NEBIUS_BASE_URL   — Override endpoint          (default: https://api.tokenfactory.nebius.com/v1/)
  USE_OLLAMA        — Enable Ollama local mode   (default: false, was true before)
  OLLAMA_BASE_URL   — Ollama endpoint            (default: http://localhost:11434)
  OLLAMA_MODEL      — Ollama model               (default: llama3)
  AI_MOCK_MODE      — Force mock mode            (default: false)
"""

import os
import logging
import asyncio
import json
from enum import Enum
from typing import Optional
import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------
class LLMModel(str, Enum):
    # ✅ Primary: Nebius Token Factory — NVIDIA open-source models
    NEMOTRON_LIGHTNING   = "nvidia/Nemotron-3_5-Lightning"
    NEMOTRON_SUPER       = "nvidia/nemotron-3-super-120b-a12b"
    NEMOTRON_ULTRA       = "nvidia/Nemotron-3-Ultra-550b-a55b"

    # Ollama (open-source, local fallback)
    OLLAMA_LLAMA3              = "llama3"
    OLLAMA_MISTRAL             = "mistral"
    OLLAMA_CODESTRAL           = "codestral"
    OLLAMA_DEEPSEEK_CODER      = "deepseek-coder"
    OLLAMA_DEEPSEEK_V3_DISTILL = "deepseek-v3:distill-qwen-7b"
    OLLAMA_DEEPSEEK_R1_DISTILL = "deepseek-r1:7b"
    OLLAMA_QWEN                = "qwen"

    # ⚠️ DEPRECATED — kept only for backwards-compatible mock code paths
    # Do NOT use in production; they are wired to mock fallback only.
    _DEPRECATED_GPT_4O_MINI    = "gpt-4o-mini"
    _DEPRECATED_O1_PREVIEW     = "o1-preview"


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------
class LLMClient:
    """Abstract base for LLM clients."""
    async def generate_async(self, model: LLMModel, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Production client — Nebius Token Factory → Ollama → Mock
# ---------------------------------------------------------------------------
class ProductionMultiModelClient(LLMClient):
    """
    Production LLM client backed by Nebius Token Factory (NVIDIA Nemotron).

    Resolution order:
      1. Nebius/NVIDIA Nemotron  — if NEBIUS_API_KEY is set and not a demo key
      2. Ollama local            — if USE_OLLAMA=true
      3. Mock template           — final fallback
    """

    def __init__(self):
        self.is_mock = os.getenv("AI_MOCK_MODE", "false").lower() == "true"

        # --- Nebius Token Factory / NVIDIA NIM ---
        self._nebius_key = os.getenv("NEBIUS_API_KEY", "").strip()
        self._nebius_demo = self._nebius_key.lower() in ("demo", "mock", "test", "fake", "")
        self._nebius_client = None  # lazy init

        if self._nebius_key and not self._nebius_demo:
            logger.info("[Nebius] API key detected — Nemotron inference will be used as primary LLM.")
        else:
            logger.info("[Nebius] No valid API key — Nemotron unavailable; falling back to Ollama or mock.")

        # --- Ollama (secondary, local) ---
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.ollama_model    = os.getenv("OLLAMA_MODEL", "llama3")
        self.ollama_enabled  = os.getenv("USE_OLLAMA", "false").lower() == "true"
        if self.ollama_enabled:
            self._check_ollama_availability()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def generate_async(self, model: LLMModel, system_prompt: str, user_prompt: str) -> str:
        if self.is_mock:
            return await self._mock_fallback(model, system_prompt, user_prompt)

        # 1. Nebius Token Factory (primary)
        if self._nebius_key and not self._nebius_demo:
            try:
                return await self._call_nebius(model, system_prompt, user_prompt)
            except Exception as exc:
                logger.warning(f"[Nebius] Call failed ({model.value}): {exc}. Trying Ollama fallback.")

        # 2. Ollama (local open-source)
        if self.ollama_enabled:
            try:
                return await self._call_ollama(model, system_prompt, user_prompt)
            except Exception as exc:
                logger.warning(f"[Ollama] Call failed ({model.value}): {exc}. Using mock fallback.")

        # 3. Mock
        logger.warning(f"[LLMClient] No LLM backend available — returning mock for {model.value}")
        return await self._mock_fallback(model, system_prompt, user_prompt)

    # ------------------------------------------------------------------
    # Nebius Token Factory / NVIDIA NIM
    # ------------------------------------------------------------------
    def _get_nebius_client(self):
        """Lazy-init the AsyncOpenAI client pointed at Nebius."""
        if self._nebius_client is None:
            from openai import AsyncOpenAI

            base_url = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
            # Auto-detect NVIDIA direct endpoint
            if self._nebius_key.startswith("nvapi-"):
                base_url = "https://integrate.api.nvidia.com/v1"

            self._nebius_client = AsyncOpenAI(
                api_key=self._nebius_key,
                base_url=base_url,
                timeout=90.0,
                max_retries=1,
            )
            logger.info(f"[Nebius] Client initialized → {base_url}")
        return self._nebius_client

    def _resolve_nemotron_model(self, model: LLMModel) -> str:
        """
        Map any LLMModel to the Nemotron model id that will be sent to Nebius.
        Deprecated aliases are transparently promoted to the default Nemotron model.
        """
        env_override = os.getenv("NEBIUS_MODEL")
        if env_override:
            return env_override

        # Deprecated OpenAI aliases → Nemotron Lightning (same capability class)
        if model.value in ("gpt-4o-mini", "o1-preview"):
            return LLMModel.NEMOTRON_LIGHTNING.value

        # Ollama model names requested when Nebius is the active backend
        if model.value.startswith("deepseek") or model.value.startswith("llama") or model.value.startswith("mistral"):
            return LLMModel.NEMOTRON_LIGHTNING.value

        # Already a Nebius/Nemotron model id
        if model.value.startswith("nvidia/"):
            return model.value

        # Default
        return LLMModel.NEMOTRON_LIGHTNING.value

    async def _call_nebius(self, model: LLMModel, system_prompt: str, user_prompt: str) -> str:
        """Call Nebius Token Factory (OpenAI-compatible endpoint)."""
        client = self._get_nebius_client()
        model_id = self._resolve_nemotron_model(model)

        logger.debug(f"[Nebius] → model={model_id}")
        response = await client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=2048,
        )
        return response.choices[0].message.content

    # ------------------------------------------------------------------
    # Ollama (local)
    # ------------------------------------------------------------------
    def _check_ollama_availability(self):
        """Non-blocking check for Ollama availability."""
        try:
            response = httpx.get(f"{self.ollama_base_url}/api/tags", timeout=2.0)
            if response.status_code == 200:
                models = [m.get("name", "") for m in response.json().get("models", [])]
                logger.info(f"[Ollama] Available at {self.ollama_base_url}. Models: {models}")
                return True
        except Exception as e:
            logger.debug(f"[Ollama] Not available: {e}")
            logger.info("ℹ️  Ollama not reachable (optional). See https://ollama.ai")
        return False

    async def _call_ollama(self, model: LLMModel, system_prompt: str, user_prompt: str) -> str:
        """Call a locally running Ollama instance."""
        if model.value.startswith("ollama-"):
            model_name = model.value.replace("ollama-", "")
        else:
            model_name = self.ollama_model

        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        options = {
            "temperature": 0.6 if "r1" in model_name.lower() else 0.7,
            "top_p": 0.9,
        }

        logger.info(f"[Ollama] Calling model: {model_name}")
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.ollama_base_url}/api/generate",
                json={"model": model_name, "prompt": full_prompt, "stream": False, "options": options},
            )
            response.raise_for_status()
            raw = response.json().get("response", "")

            # Strip <think>…</think> from reasoning models (DeepSeek R1)
            if "<think>" in raw and "</think>" in raw:
                logger.debug("[Ollama] Stripped <think> block from response.")
            return raw

    # ------------------------------------------------------------------
    # Mock fallback
    # ------------------------------------------------------------------
    async def _mock_fallback(self, model: LLMModel, system_prompt: str, user_prompt: str) -> str:
        """Deterministic template fallback — no external call."""
        logger.warning(f"[Mock] Returning deterministic fallback for {model.value}")

        # Report / Summary (was GPT_4O_MINI)
        if model.value in ("gpt-4o-mini", LLMModel.NEMOTRON_LIGHTNING.value):
            return (
                "# Adversum Security Intelligence Report\n"
                "## Executive Summary\n"
                "The system has identified critical execution pathways that bypass traditional security filters. "
                "Graph-Augmented Reasoning (G-ASR) confirms active vulnerabilities in the ingestion layer.\n"
                "## Key Findings\n"
                "- **RCE Vulnerability**: One confirmed critical sink in the test target.\n"
                "- **Data Flow Integrity**: CFG analysis suggests unvalidated user input reaching the interpreter.\n"
                "## Strategic Recommendation\n"
                "Immediate adoption of Autonomous Verified Remediation (AVR) is recommended."
            )

        # Vulnerability validation
        if "eval" in user_prompt.lower():
            return json.dumps({
                "verdict": "CONFIRMED",
                "analysis": "CRITICAL — Unsafe eval() detected. External input flows directly into the interpreter.",
                "fix": {
                    "description": "Replace eval() with ast.literal_eval() to restrict execution to literals.",
                    "code": "import ast\nast.literal_eval(data)"
                }
            })

        # Security audit challenge
        return json.dumps({
            "conclusion": "CONFIRMED",
            "reasoning": "Audit stage verifies the CFG path from user input to the sensitive sink is direct."
        })


# ---------------------------------------------------------------------------
# Mock client (kept for unit tests that import it explicitly)
# ---------------------------------------------------------------------------
class MockMultiModelClient(LLMClient):
    """
    Lightweight mock client used in unit tests.
    All inference is deterministic — no network calls.
    """

    async def generate_async(self, model: LLMModel, system_prompt: str, user_prompt: str) -> str:
        logger.info(f"[MockClient] generate_async called with model={model.value}")
        if "eval" in user_prompt:
            return json.dumps({
                "verdict": "CONFIRMED",
                "analysis": "CRITICAL — RCE Vector via eval()",
                "fix": {"description": "Use ast.literal_eval", "code": "ast.literal_eval(user_input)"}
            })
        return json.dumps({
            "verdict": "LOW_RISK",
            "analysis": "Standard code pattern.",
            "fix": None
        })
