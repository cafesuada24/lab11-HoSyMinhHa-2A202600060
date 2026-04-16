"""
Lab 11 — Unified Security Pipeline
"""
from core.ratelimiter import RateLimiter
from core.auditing import AuditLogger
from core.monitoring import SecurityMonitor
from guardrails.input_guardrails import detect_injection, topic_filter
from guardrails.toxicity_guardrail import ToxicityGuardrail
from guardrails.output_guardrails import llm_safety_check

# Initialize shared components
rate_limiter = RateLimiter(max_calls=5, period=60)
audit_logger = AuditLogger()
monitor = SecurityMonitor()
toxicity_guardrail = ToxicityGuardrail()

async def run_security_pipeline(user_input: str, user_id: str = "default", use_judge: bool = False):
    """Unified security pipeline."""
    
    # 1. Rate Limiting
    rate_status = rate_limiter.allow_request(user_id=user_id)
    if not rate_status["allowed"]:
        audit_logger.log("rate_limited", {"input": user_input, "user_id": user_id})
        monitor.record_event("rate_limit", True)
        return {"allowed": False, "reason": "Rate limit exceeded"}

    # 2. Input Guardrails
    if detect_injection(user_input):
        audit_logger.log("blocked", {"input": user_input, "reason": "Injection detected"})
        monitor.record_event("block", True)
        return {"allowed": False, "reason": "Injection detected"}

    if topic_filter(user_input):
        audit_logger.log("blocked", {"input": user_input, "reason": "Off-topic"})
        monitor.record_event("block", True)
        return {"allowed": False, "reason": "Off-topic query"}

    # 3. Toxicity Detection
    if toxicity_guardrail.is_toxic(user_input):
        audit_logger.log("blocked", {"input": user_input, "reason": "Toxicity detected"})
        monitor.record_event("block", True)
        return {"allowed": False, "reason": "Toxicity detected"}

    # 4. Optional Judge
    if use_judge:
        # Assuming llm_safety_check takes the text and returns a boolean/tuple
        if not llm_safety_check(user_input):
            audit_logger.log("blocked", {"input": user_input, "reason": "Judge failed safety"})
            monitor.record_event("block", True)
            return {"allowed": False, "reason": "Safety check failed"}

    monitor.record_event("pass", False)
    return {"allowed": True}
