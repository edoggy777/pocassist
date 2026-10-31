"""impact_rules.py - rule-based impact type of a vulnerability claim, and how a PoC proves that kind of impact.
No project imports, so poc_loop / poc_assist / build_impact can all use it."""
import re

TEMPLATES = {
    "theft": "Record the attacker's and victim's balances before the attack; assert the attacker gained "
             "(assertGt(attackerAfter, attackerBefore)) and/or the victim lost.",
    "accounting": "Take a baseline of the wrong number (vm.snapshotState, do the honest path, read it, revertToState), "
                  "then do the attack path and assert the number differs from what correct accounting gives.",
    "dos": "After the attack, call the VICTIM's normal function and vm.expectRevert(<the specific error>) on it; "
           "never a bare expectRevert().",
    "stuck": "After the attack, assert funds remain where nobody can get them (contract balance > 0, side-effect "
             "tokens minted to an address that can't use them) and that the rightful owner didn't receive them.",
    "access": "Call the restricted/unchecked function as an unprivileged attacker (vm.prank(attacker)) with the "
              "bad input, then assert the state change that should have been impossible (and that it hurts someone).",
    "fee_bypass": "Compute the normal fee for the same size (or run it with fees on vs off); assert the attack path "
                  "paid less than that (often 0).",
}
LABELS = list(TEMPLATES)

SYSTEM = ("You classify a smart-contract vulnerability claim by the kind of impact a PoC must assert. "
          "Answer with JSON: {\"impact\": one of " + ", ".join(LABELS) + ", \"assert\": how to assert it}.")

RULES = [
    ("fee_bypass", r"\bfees?\b.{0,40}\b(bypass|avoid|evad|skip|zero|not (?:paid|charged)|without paying)"
                   r"|\b(bypass|avoid|evad|skip)\w*\b.{0,40}\bfees?\b"),
    ("access", r"\b(anyone can|allows? anyone|any(?:one|body) (?:is able|may)|arbitrary|unauthori[sz]ed|"
               r"(?:missing|lack of|no|without) (?:access control|caller check|ownership check|permission check)|"
               r"missing (?:input )?validation|outside (?:the )?\w* ?range|not validated|lets? (?:others|anyone)|on behalf of (?:another|other|any)|for (?:another|other) (?:user|account|address)|can ?not be (?:paused|blocked|stopped|disabled)|(?:pause|freeze|block)\w* (?:is )?(?:bypass|not enforced|ineffective|does ?n.?t))\b"),
    ("dos", r"\b(do[sS]\w*|deny\w*|denies|denial[- ]of[- ]service|grief\w*|brick\w*|block(?:s|ed|ing)?|prevent\w*|"
            r"unable to|cannot|can'?t|fail\w*|revert\w*|stop\w* (?:function\w*|working)|permanently (?:stuck|disabled))\b"),
    ("stuck", r"\b(stuck|locked|lock(?:s|ed)? (?:up|forever|redemption|funds|withdraw\w*|assets|tokens|collateral)|"
              r"not (?:returned|refunded|sent back|forwarded)|residual|lost forever|"
              r"cannot be (?:withdrawn|recovered|claimed))\b"),
    ("theft", r"\b(steal\w*|stole|drain\w*|theft|extract\w*|free (?:tokens|money|mint)|receive more|"
              r"more than (?:they|he|she|deposited|owed)|los[es] (?:user )?funds|loss of (?:user )?funds)\b"),
    ("accounting", r"\b(incorrect\w*|wrong\w*|miscalculat\w*|inflat\w*|dilut\w*|accounting|exchange rate|"
                   r"price|reward\w*|shares?|interest|rounding|precision|overvalu\w*|undervalu\w*|accru\w*|"
                   r"profit and loss|apr|apy)\b"),
]
FROM_DESCRIPTION = ("stuck", "theft", "accounting")    # dos/access/fee/stuck only when the TITLE says so


def strip_code(text: str) -> str:
    text = re.sub(r"```.*?```", " [code omitted] ", text, flags=re.S)
    text = re.sub(r"https?://\S+", "", text)
    return re.sub(r"\s+", " ", text).strip()


def label_of(title: str, desc: str) -> str | None:
    """The impact type from the claim's wording: the title decides first, then (value-type impacts only)
    the opening of the description. None = no rule matched."""
    head = title + " " + strip_code(desc)[:1500]
    order = ["fee_bypass", "access", "stuck", "dos", "theft"]
    rules = dict(RULES)
    for lab in order:
        if re.search(rules[lab], title, re.I):
            return lab
    for lab in FROM_DESCRIPTION:
        if re.search(rules[lab], head, re.I):
            return lab
    return None


def section(title: str, desc: str) -> str:
    """The prompt section every writer prompt gets (empty if no rule matched)."""
    lab = label_of(title, desc)
    return (f"// ===== IMPACT TYPE (rule-based, from the claim's wording; verify it): {lab}\n"
            f"// How a PoC proves this kind of impact: {TEMPLATES[lab]}\n\n") if lab else ""


# ---- precondition axis: findings whose bug only manifests under a hostile token/state ----
# Orthogonal to the impact label above: a fee-on-transfer bug can be theft OR accounting etc.
# A PoC for one of these must actually INSTANTIATE the hostile precondition in setup. The ATTACK
# knockout cannot see a missing precondition (it only removes the attack), so a PoC that runs the
# attack against a benign mock (plain ERC20) tests the happy path and passes falsely (boost M-04).
# Unlike impact labels, the precondition is often stated only in the description, so check both.
PRECONDITIONS = [
    ("fee_on_transfer",
     r"\bfee[-\s]?on[-\s]?transfer\b|\btransfer[-\s]?fee\b|\bfee[-\s]?taking\b|\bdeflationary\b|"
     r"\btokens?\s+that\s+(?:take|charge|deduct)s?\s+a\s+fee\b|"
     r"\b(?:charges?|deducts?|takes?|withholds?)\s+a\s+fee\s+on\s+(?:each\s+|every\s+)?transfer\b"),
]


def precondition_of(title: str, desc: str) -> str | None:
    """The hostile-token/state precondition the finding keys on, or None. Separate from label_of():
    a finding can carry an impact label AND a precondition. Checked in title and description both."""
    hay = (title or "") + " " + strip_code(desc or "")[:2000]
    for name, pat in PRECONDITIONS:
        if re.search(pat, hay, re.I):
            return name
    return None
