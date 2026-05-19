# Authproof + CrewAI / LangGraph agent — minimal integration example
# Run: python authproof-cloud/templates/crewai-langraph-template.py
# Pure stdlib only. Shows one PERMIT (read inbox) and one DENY (send email).
import time, random, string

# Step 1: Build a receipt — in production use AuthProofClient.delegate() instead.
def create_receipt(allowed_actions, denied_actions, ttl_hours=1):
    now = int(time.time())
    rid = "auth-" + str(now) + "-" + "".join(random.choices(string.ascii_lowercase, k=5))
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    return {
        "delegationId":   rid,
        "issuedAt":       iso(now),
        "allowedActions": allowed_actions,
        "deniedActions":  denied_actions,
        "timeWindow":     {"start": iso(now), "end": iso(now + ttl_hours * 3600)},
    }

# Step 2: Scope check — denied takes precedence; ALL words in a pattern must match.
def check_scope(action, receipt):
    a = action.lower()
    for denied in receipt["deniedActions"]:
        if all(w in a for w in denied.lower().split()):
            return False, f"action matches denied pattern: '{denied}'"
    for allowed in receipt["allowedActions"]:
        if all(w in a for w in allowed.lower().split()):
            return True, f"action within allowed scope: '{allowed}'"
    return False, "action not found in allowed scope"

# Step 3: Simulate a CrewAI / LangGraph tool pre-check — always verify before executing.
def agent_tool_call(action, receipt):
    permitted, reason = check_scope(action, receipt)
    print(f"[{'PERMIT' if permitted else 'DENY'}] {action!r}")
    print(f"  Reason: {reason}\n")
    return permitted

# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    receipt = create_receipt(
        allowed_actions=["read email inbox", "summarize emails"],
        denied_actions=["send email", "delete email", "reply"],
        ttl_hours=2,
    )
    print(f"Receipt: {receipt['delegationId']}")
    print(f"Expires: {receipt['timeWindow']['end']}\n")

    agent_tool_call("Read the email inbox and list unread messages", receipt)  # PERMIT
    agent_tool_call("Send a reply email to the last sender", receipt)          # DENY
