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


def test_refund_download_lure_scores_high():
    score, reasons = analyse("A refund of R2,300 is available for you. Download the attached document details.")
    assert score >= 3
    assert any("refund" in r.lower() for r in reasons)


def test_genuine_refund_notice_stays_low():
    text = ("Your refund of R1,200 for the overpaid registration fee will be paid into the bank "
            "account on file within 10 working days. No action is needed from you.")
    score, _ = analyse(text)
    assert score < 2


def test_file_request_under_threat_scores_high():
    score, _ = analyse("Invoice overdue: open the attached file to view the payment details. Legal action will begin tomorrow.")
    assert score >= 3
