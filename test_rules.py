from rules import analyse, verdict

PHISH = ("Your SPU student email account will be suspended in 24 hours. Click "
         "http://spu-mail-verify.example/login to confirm your password and keep your account active.")
GENUINE = ("IT Services: your campus password will expire in 5 days. To change it, go to the official "
           "IT self-service page from the university website or visit the helpdesk. "
           "We will never ask for your password by email.")


def test_phishing_scores_high():
    score, reasons = analyse(PHISH)
    assert score >= 3
    assert reasons


def test_genuine_notice_scores_low():
    score, _ = analyse(GENUINE)
    assert score < 3


def test_empty_text_scores_zero():
    assert analyse("") == (0, [])


def test_verdict_levels():
    assert verdict(False, 0) == "Safe"
    assert verdict(True, 0) == "Suspicious"
    assert verdict(False, 2) == "Suspicious"
    assert verdict(True, 1) == "Phishing"
    assert verdict(False, 3) == "Phishing"
