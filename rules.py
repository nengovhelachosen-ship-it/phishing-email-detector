"""Rule-based phishing indicators and the three-level verdict.

Usage in the Streamlit app:
    from rules import analyse, verdict
    score, reasons = analyse(email_text)
    level = verdict(model_says_phishing, score)   # "Phishing", "Suspicious" or "Safe"
"""
import re

CRED = r"password|passcode|\bpin\b|\botp\b|banking details|bank details|bank account|account number|id number|card number|student number|branch code|login details|bank login"
ACTION = r"log ?in|sign ?in|re-?authenticate|verify|confirm your|enter your|re-?enter|reply with|send your|download|open the attach|click|update your"
LINK = r"https?://|www\.|\blink\b|click|secure link|at the link|using the link|through the link"
URGENT = r"\btoday\b|within \d+ ?(hours?|minutes?)|expires? in|final warning|immediately|urgent|act now|limited (stock|spots)|before the link expires|\b\d+ hours\b|in one hour|within 24"
THREAT = r"suspend|deregister|blocked|locked|deleted|permanent|legal action|closed unless|will be closed|lose incoming|returned if|will be returned|compromised|unauthori[sz]ed"
PAYPRESS = r"pay now|pay the|processing fee|delivery fee|customs fee|gift cards?|guaranteed|invest r|claim (your|it|yours)|release the (funds|payment)|pay online now|enter your card|reimburse|send me the codes?"
REASSURE = r"never ask|no action is needed|no action needed|in person|do not send|do not click|official (university )?(website|page)|from the university website|paper form|report them|visit the .{0,40}office|at the .{0,40}(office|desk)|through the university website"

MONEYLURE = r"refunds?|you have won|winner|cash prize|prize|lottery|free money|unclaimed|inheritance|pre-?approved"
FILELURE = r"download|open (the )?attach|attached (document|file)|shared (a )?(document|file)|document details|pdf document|open the (file|document)"


def analyse(text):
    """Return (score, reasons). Higher score means more phishing signs."""
    t = str(text).lower()
    cred = bool(re.search(CRED, t))
    act = bool(re.search(ACTION, t))
    link = bool(re.search(LINK, t))
    urg = bool(re.search(URGENT, t))
    thr = bool(re.search(THREAT, t))
    pay = bool(re.search(PAYPRESS, t))
    money = bool(re.search(MONEYLURE, t))
    filel = bool(re.search(FILELURE, t))
    score, reasons = 0, []
    if cred and (act or link):
        score += 3
        reasons.append("Asks for passwords, banking or ID details together with a login, link or reply request")
    elif cred:
        score += 1
        reasons.append("Mentions passwords or banking details")
    if urg:
        score += 1
        reasons.append("Uses urgency or a deadline")
    if thr:
        score += 1
        reasons.append("Threatens suspension, blocking, deletion or legal action")
    if link and (urg or thr or pay):
        score += 1
        reasons.append("Pushes you to follow a link under pressure")
    if pay:
        score += 2
        reasons.append("Asks for payment or fees, gift cards, or promises easy money")
    if money and filel:
        score += 3
        reasons.append("Money, refund or prize wording combined with a request to download or open a file")
    elif money and link:
        score += 2
        reasons.append("Money, refund or prize wording combined with a link")
    elif filel and (urg or thr):
        score += 2
        reasons.append("Pushes you to open or download a file under pressure")
    if re.search(REASSURE, t):
        score -= 3
        reasons.append("Has reassurance wording typical of genuine notices (lowers the score)")
    return max(score, 0), reasons


def verdict(model_says_phishing, score):
    """Combine the model's flag with the rule score into one of three levels."""
    flag = bool(model_says_phishing)
    if score >= 3 or (flag and score >= 1):
        return "Phishing"
    if flag or score == 2:
        return "Suspicious"
    return "Safe"
