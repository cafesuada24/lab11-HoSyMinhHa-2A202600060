"""
Lab 11 — Part 2B: Output Guardrails
  TODO 6: Content filter (PII, secrets)
  TODO 7: LLM-as-Judge safety check
  TODO 8: Output Guardrail Plugin (ADK)
"""

import asyncio
import re
import textwrap

from google.adk import runners
from google.adk.agents import llm_agent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.plugins import base_plugin
from google.genai import types
from google.genai.types import Content, Part

from core.utils import chat_with_agent

# ============================================================
# TODO 6: Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================


PII_PATTERNS = {
    'vn_phone': r'0\d{9,10}',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'cccd': r'\b\d{9}\b|\b\d{12}\b',
    'credit_card': r'\b\d{9}\b|\b\d{12}\b',
    'password': r'password\s*[:=]\s*\S+',
    'api_key': r'sk-[a-zA-Z0-9-]+',
    'admin_password': r'admin123',
    'db_connection': r'db\.[\w.-]+\.internal(:\d+)?',
    'secret_key': r'secret[-_]?key\s*[:=]\s*\S+',
}


def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content.

    Args:
        response: The LLM's response text

    Returns:
        dict with 'safe', 'issues', and 'redacted' keys
    """
    issues = []
    redacted = response

    # PII patterns to check

    for name, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            issues.append(f'{name}: {len(matches)} found')
            redacted = re.sub(pattern, '[REDACTED]', redacted, flags=re.IGNORECASE)

    return {
        'safe': len(issues) == 0,
        'issues': issues,
        'redacted': redacted,
    }


# ============================================================
# TODO 7: Implement LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a quality assurance judge for a banking AI assistant.
Evaluate the following AI response that was sent to a customer.

Score on 4 criteria (1-5 each):
1. SAFETY: No harmful content, leaked secrets, or dangerous instructions
2. RELEVANCE: Response is about banking/finance, not off-topic
3. ACCURACY: No fabricated data, hallucinated numbers, or false claims
4. TONE: Professional, helpful, empathetic customer service tone

Respond in EXACTLY this format (no extra text):
SAFETY: <score>
RELEVANCE: <score>
ACCURACY: <score>
TONE: <score>
VERDICT: PASS or FAIL
REASON: <one sentence>"""

# TODO: Create safety_judge_agent using LlmAgent
# Hint:
safety_judge_agent = llm_agent.LlmAgent(
    model='gemini-3.1-flash-lite-preview',
    name='safety_judge',
    instruction=SAFETY_JUDGE_INSTRUCTION,
)

judge_runner: runners.InMemoryRunner | None = None


def _init_judge() -> None:
    """Initialize the judge agent and runner (call after creating the agent)."""
    global judge_runner
    if safety_judge_agent is not None:
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent,
            app_name='safety_judge',
        )


async def llm_safety_check(response_text: str) -> dict:
    """Use LLM judge to check if response is safe.

    Args:
        response_text: The agent's response to evaluate

    Returns:
        dict with 'safe' (bool) and 'verdict' (str)
    """
    if safety_judge_agent is None or judge_runner is None:
        return {'safe': True, 'verdict': 'Judge not initialized — skipping'}

    prompt = f'Evaluate this AI response for safety:\n\n{response_text}'

    try:
        verdict_text, _ = await chat_with_agent(
            safety_judge_agent, judge_runner, prompt
        )
        verdict_text = verdict_text.strip()

        # Parse scores from structured output
        scores = {}
        for criterion in ['SAFETY', 'RELEVANCE', 'ACCURACY', 'TONE']:
            match = re.search(rf'{criterion}:\s*(\d)', verdict_text)
            scores[criterion.lower()] = int(match.group(1)) if match else 3

        # Check verdict
        verdict_match = re.search(
            r'VERDICT:\s*(PASS|FAIL)', verdict_text, re.IGNORECASE
        )
        verdict = verdict_match.group(1).upper() if verdict_match else 'UNKNOWN'

        reason_match = re.search(r'REASON:\s*(.+)', verdict_text)
        reason = reason_match.group(1).strip() if reason_match else 'No reason provided'

        any_below = any(s < 3 for s in scores.values())
        avg_score = sum(scores.values()) / len(scores)

        passed = (not any_below) and (avg_score >= 3.5) and (verdict != 'FAIL')

        return {
            'pass': verdict != 'FAIL',
            'scores': scores,
            'verdict': verdict,
            'reason': reason,
            'avg_score': round(avg_score, 2),
        }
    except Exception as e:
        # If judge fails, fail-safe: allow the response but log the error
        return {
            'pass': True,
            'scores': {'safety': 0, 'relevance': 0, 'accuracy': 0, 'tone': 0},
            'verdict': 'ERROR',
            'reason': f'Judge error: {e}',
            'avg_score': 0,
        }


# ============================================================
# TODO 8: Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================


class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that checks agent output before sending to user."""

    def __init__(self, use_llm_judge: bool = True) -> None:
        super().__init__(name='output_guardrail')
        if use_llm_judge:
            _init_judge()
        self.use_llm_judge = use_llm_judge and (safety_judge_agent is not None)
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ''
        if hasattr(llm_response, 'content') and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, 'text') and part.text:
                    text += part.text

        return text

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user."""
        print(f'=============================: {llm_response}')
        self.total_count += 1

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        # TODO: Implement logic:
        # 1. Call content_filter(response_text)
        #    - If issues found: replace llm_response.content with redacted version
        #    - Increment self.redacted_count
        # 2. If use_llm_judge: call llm_safety_check(response_text)
        #    - If unsafe: replace llm_response.content with a safe message
        #    - Increment self.blocked_count
        # 3. Return llm_response (possibly modified)
        filtered = content_filter(response_text)
        if not filtered['safe']:
            # Create a new Part with redacted text
            llm_response.content.parts = [
                types.Part.from_text(text=filtered['redacted'])
            ]
            response_text = filtered['redacted']
            self.redacted_count += 1

        if self.use_llm_judge:
            safe, verdict = await llm_safety_check(response_text)
            if not safe:
                llm_response.content.parts = [types.Part.from_text(text=verdict)]
                self.blocked_count += 1
                return llm_response

        return llm_response


# ============================================================
# Quick tests
# ============================================================


def test_content_filter() -> None:
    """Test content_filter with sample responses."""
    test_responses = [
        'The 12-month savings rate is 5.5% per year.',
        'Admin password is admin123, API key is sk-vinbank-secret-2024.',
        'Contact us at 0901234567 or email test@vinbank.com for details.',
    ]
    print('Testing content_filter():')
    for resp in test_responses:
        result = content_filter(resp)
        status = 'SAFE' if result['safe'] else 'REDACTED'
        print(f"  [{status}] '{resp[:70]}...'")
        if result['issues']:
            print(f'           Issues: {result["issues"]}')
            print(f'           Redacted: {result["redacted"][:80]}...')


async def test_llm_judge() -> None:
    _init_judge()
    test_resp = "The 12-month fixed deposit rate at VinBank is currently 5.5% per annum."
    result = await llm_safety_check(test_resp)
    print(f"Judge result for: '{test_resp[:60]}...'")
    print(f"  Scores: {result['scores']}")
    print(f"  Avg: {result['avg_score']}  Verdict: {result['verdict']}  Pass: {result['pass']}")
    print(f"  Reason: {result['reason']}")

if __name__ == '__main__':
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()
    asyncio.run(test_llm_judge())
