import os
import re
import shutil
import joblib
import pytesseract
import streamlit as st

from PIL import Image
from datetime import datetime

from firebase_service import AuthError, FirebaseClient, FirebaseConfig, FirebaseError
from image_utils import base64_to_bytes, image_to_base64
from rules import analyse, verdict

# Use the default Windows install location when Tesseract is not on PATH.
WINDOWS_TESSERACT = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if not shutil.which("tesseract") and os.path.exists(WINDOWS_TESSERACT):
    pytesseract.pytesseract.tesseract_cmd = WINDOWS_TESSERACT

st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide"
)

# ---- Model settings --------------------------------------------------------
# To switch to the SVM exported from Colab, change these four lines:
#   MODEL_NAME = "SVM", MODEL_FILE = "phishing_svm_model.pkl",
#   VECTORIZER_FILE = "tfidf_vectorizer_clean.pkl", USE_CLEAN_TEXT = True
MODEL_NAME = "LightGBM"
MODEL_FILE = "phishing_lightgbm_model.pkl"
VECTORIZER_FILE = "tfidf_vectorizer.pkl"
USE_CLEAN_TEXT = False
# ----------------------------------------------------------------------------

HEADER_RE = re.compile(r"^(message-id|date|from|to|cc|bcc|sent|x-[\w-]+|received|mime-version|"
                       r"content-[\w-]+|in-reply-to|references):.*$", re.M)
URL_RE = re.compile(r"(https?://\S+|www\.\S+)")
EMAIL_RE = re.compile(r"\S+@\S+")
YEAR_RE = re.compile(r"\b(19|20)\d{2}\b")

FINAL_LABEL = {"Phishing": "PHISHING", "Suspicious": "POTENTIALLY SUSPICIOUS", "Safe": "SAFE"}
INPUT_METHOD_KEYS = {
    "📋 Paste Email": "paste",
    "🖼️ Upload Screenshot": "screenshot",
    "📄 Upload Text File": "text_file",
}
INPUT_METHOD_LABELS = {key: label for label, key in INPUT_METHOD_KEYS.items()}


def clean_text(t):
    """Same cleaning used when the SVM was trained in Colab."""
    t = str(t).lower()
    t = HEADER_RE.sub(" ", t)
    t = URL_RE.sub(" urltoken ", t)
    t = EMAIL_RE.sub(" emailaddr ", t)
    t = YEAR_RE.sub(" ", t)
    t = re.sub(r"\d+", " numtoken ", t)
    t = re.sub(r"[^a-z\s]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


@st.cache_resource
def load_model():
    return joblib.load(MODEL_FILE), joblib.load(VECTORIZER_FILE)


model, vectorizer = load_model()


# ---- Firebase accounts and per-user history ---------------------------------

def get_client():
    if "firebase_client" not in st.session_state:
        try:
            config = FirebaseConfig.load(st.secrets)
        except FirebaseError as exc:
            st.error(str(exc))
            st.stop()
        except Exception:
            # st.secrets raises when no secrets.toml exists; fall back to env vars.
            try:
                config = FirebaseConfig.load(None)
            except FirebaseError as exc:
                st.error(str(exc))
                st.stop()
        st.session_state.firebase_client = FirebaseClient(config)
    return st.session_state.firebase_client


def reset_user_state():
    for key in ("user", "history_cache", "image_cache", "last_result"):
        st.session_state.pop(key, None)


def current_user():
    """Signed-in session with a valid ID token, or None."""
    user = st.session_state.get("user")
    if user is None:
        return None
    try:
        fresh = client.fresh(user)
    except AuthError as exc:
        reset_user_state()
        st.session_state.auth_notice = str(exc)
        return None
    st.session_state.user = fresh
    return fresh


def load_history(user):
    if st.session_state.get("history_cache") is None:
        st.session_state.history_cache = client.list_history(user)
    return st.session_state.history_cache


def format_time(value):
    if isinstance(value, datetime):
        return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    return "—"


def show_auth_page():
    st.title("🛡️ Phishing Email Detector")
    st.write("Sign in to analyse emails and keep a private history of your results.")

    notice = st.session_state.pop("auth_notice", None)
    if notice:
        st.info(notice)

    sign_in_tab, sign_up_tab, reset_tab = st.tabs(["🔑 Sign in", "🆕 Create account", "❓ Forgot password"])

    with sign_in_tab:
        with st.form("sign_in_form"):
            email = st.text_input("Email", key="sign_in_email")
            password = st.text_input("Password", type="password", key="sign_in_password")
            submitted = st.form_submit_button("Sign in", use_container_width=True)
        if submitted:
            if not email.strip() or not password:
                st.warning("Please enter your email and password.")
            else:
                try:
                    with st.spinner("Signing in..."):
                        st.session_state.user = client.sign_in(email, password)
                    st.rerun()
                except FirebaseError as exc:
                    st.error(str(exc))

    with sign_up_tab:
        with st.form("sign_up_form"):
            name = st.text_input("Display name (optional)", max_chars=60)
            email = st.text_input("Email", key="sign_up_email")
            password = st.text_input("Password (at least 6 characters)", type="password", key="sign_up_password")
            confirm = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Create account", use_container_width=True)
        if submitted:
            if not email.strip() or not password:
                st.warning("Please enter an email and password.")
            elif password != confirm:
                st.warning("Passwords do not match.")
            elif len(password) < 6:
                st.warning("Password must be at least 6 characters.")
            else:
                try:
                    with st.spinner("Creating your account..."):
                        st.session_state.user = client.sign_up(email, password, name)
                    st.rerun()
                except FirebaseError as exc:
                    st.error(str(exc))

    with reset_tab:
        with st.form("reset_form"):
            email = st.text_input("Email", key="reset_email")
            submitted = st.form_submit_button("Send reset link", use_container_width=True)
        if submitted:
            if not email.strip():
                st.warning("Please enter your email.")
            else:
                try:
                    client.send_password_reset(email)
                    st.success("If an account exists for that email, a password reset link has been sent.")
                except AuthError as exc:
                    if exc.code == "EMAIL_NOT_FOUND":
                        st.success("If an account exists for that email, a password reset link has been sent.")
                    else:
                        st.error(str(exc))


client = get_client()
user = current_user()

if user is None:
    with st.sidebar:
        st.title("🛡️ Phishing Detector")
        st.write(f"**Model:** TF-IDF + {MODEL_NAME} + rules")
    show_auth_page()
    st.stop()

try:
    history = load_history(user)
except FirebaseError as exc:
    history = []
    st.error(f"Could not load your history: {exc}")


def predict_email(email):
    text = clean_text(email) if USE_CLEAN_TEXT else email
    features = vectorizer.transform([text])
    flag = int(model.predict(features)[0])
    phishing_prob = None
    if hasattr(model, "predict_proba"):
        phishing_prob = float(model.predict_proba(features)[0][1])
    return flag, phishing_prob


with st.sidebar:
    st.title("🛡️ Phishing Detector")
    st.write(f"👤 **{user.display_name or user.email}**")
    if user.display_name:
        st.caption(user.email)
    if st.button("🚪 Sign out", use_container_width=True):
        reset_user_state()
        st.rerun()
    st.divider()
    page = st.radio("Navigation", ["🏠 Home", "📜 Detection History", "ℹ️ About"])
    st.divider()
    st.write(f"**Model:** TF-IDF + {MODEL_NAME} + rules")


if page == "🏠 Home":
    st.title("🛡️ Phishing Email Detector")
    st.write("Analyse an email and determine whether it is likely to be safe or phishing.")
    st.divider()

    # Filled at the end of the page so the counts include a just-saved detection.
    metrics_area = st.container()

    st.divider()
    st.subheader("Choose how you want to provide the email")

    input_method = st.radio(
        "Input method:",
        ["📋 Paste Email", "🖼️ Upload Screenshot", "📄 Upload Text File"],
        horizontal=True
    )

    email_text = ""
    source_name = ""
    screenshot = None

    if input_method == "📋 Paste Email":
        email_text = st.text_area(
            "Paste Email Text", height=300,
            placeholder="Paste the complete email here..."
        )
        source_name = "Pasted email"

    elif input_method == "🖼️ Upload Screenshot":
        uploaded_file = st.file_uploader("Upload an email screenshot", type=["png", "jpg", "jpeg"])
        if uploaded_file is not None:
            source_name = uploaded_file.name
            image = Image.open(uploaded_file)
            screenshot = image
            st.image(image, caption="Uploaded Email Screenshot", use_container_width=True)
            with st.spinner("Extracting text from screenshot..."):
                email_text = pytesseract.image_to_string(image)
            if email_text.strip():
                st.success("Email text extracted successfully.")
                with st.expander("View extracted text"):
                    st.text(email_text)
            else:
                st.warning("No readable text was found in the screenshot.")

    elif input_method == "📄 Upload Text File":
        uploaded_file = st.file_uploader("Upload an email text file", type=["txt"])
        if uploaded_file is not None:
            source_name = uploaded_file.name
            email_text = uploaded_file.read().decode("utf-8", errors="ignore")
            st.success(f"Uploaded: {uploaded_file.name}")
            with st.expander("View uploaded email"):
                st.text(email_text)

    if st.button("🔍 DETECT EMAIL", use_container_width=True):
        if not email_text.strip():
            st.warning("Please provide an email first.")
        else:
            flag, phishing_prob = predict_email(email_text)
            score, reasons = analyse(email_text)
            level = verdict(flag == 1, score)
            final_result = FINAL_LABEL[level]
            ml_label = "PHISHING" if flag == 1 else "SAFE"
            shown_reasons = reasons or ["No obvious rule-based phishing indicators were detected."]

            entry = {
                "inputMethod": INPUT_METHOD_KEYS[input_method],
                "source": source_name,
                "modelName": MODEL_NAME,
                "modelPrediction": ml_label,
                "phishingProbability": phishing_prob,
                "finalResult": final_result,
                "ruleScore": int(score),
                "reasons": shown_reasons,
                "emailText": email_text,
            }
            image_note = None
            if screenshot is not None:
                try:
                    entry["imageBase64"], entry["imageMime"] = image_to_base64(screenshot)
                except (ValueError, OSError) as exc:
                    image_note = f"The screenshot could not be stored ({exc}); the result was saved without it."
            try:
                with st.spinner("Saving to your history..."):
                    client.add_history(user, entry)
                st.session_state.history_cache = None
                st.toast("Saved to your detection history.", icon="💾")
                if image_note:
                    st.warning(image_note)
            except FirebaseError as exc:
                st.warning(f"The result could not be saved to your history: {exc}")
            try:
                history = load_history(user)
            except FirebaseError:
                pass

            st.divider()

            if final_result == "PHISHING":
                st.error("🚨 PHISHING EMAIL")
            elif final_result == "POTENTIALLY SUSPICIOUS":
                st.warning("⚠️ POTENTIALLY SUSPICIOUS EMAIL")
            else:
                st.success("✅ SAFE EMAIL")

            st.subheader("🤖 Machine-Learning Prediction (raw)")
            st.write(f"**{MODEL_NAME} prediction:** " + ml_label)
            if phishing_prob is not None:
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Safe Probability", f"{(1 - phishing_prob) * 100:.2f}%")
                with col2:
                    st.metric("Phishing Probability", f"{phishing_prob * 100:.2f}%")

            st.subheader("🔎 Security Analysis")
            st.write(f"**Rule score:** {score}")
            st.write("**Detected indicators:**")
            for reason in shown_reasons:
                st.write("• " + reason)

            st.subheader("📊 How the verdict is decided")
            st.write(
                "Phishing: the rules find strong signs, or the model and at least one rule agree. "
                "Potentially suspicious: only the model, or only a moderate rule score, raises a flag. "
                "Safe: neither does. Rules count signs of asking for credentials, urgency, threats and "
                "payment pressure, and genuine-notice wording lowers the score."
            )

            if flag == 0 and final_result != "SAFE":
                st.warning(
                    "The machine-learning model alone classified this email as SAFE, "
                    "but the rule-based indicators raised its risk level. Verify the sender "
                    "before clicking links or downloading files."
                )

            st.info(
                "⚠️ This system is a decision-support tool. A prediction does not "
                "guarantee that an email is safe or malicious."
            )

    counts = {"PHISHING": 0, "POTENTIALLY SUSPICIOUS": 0, "SAFE": 0}
    for item in history:
        if item.get("finalResult") in counts:
            counts[item["finalResult"]] += 1

    with metrics_area:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("📧 Emails Analysed", len(history))
        with col2:
            st.metric("🚨 Phishing", counts["PHISHING"])
        with col3:
            st.metric("⚠️ Suspicious", counts["POTENTIALLY SUSPICIOUS"])
        with col4:
            st.metric("✅ Safe", counts["SAFE"])

elif page == "📜 Detection History":
    st.title("📜 Detection History")

    if "image_cache" not in st.session_state:
        st.session_state.image_cache = {}

    if not history:
        st.info("No emails have been analysed yet.")
    else:
        st.write(f"**{len(history)}** email(s) saved to your account.")

        for item in history:
            result = item.get("finalResult", "")
            if result == "PHISHING":
                icon = "🚨"
            elif result == "POTENTIALLY SUSPICIOUS":
                icon = "⚠️"
            else:
                icon = "✅"

            entry_id = item["id"]
            with st.expander(f"{icon} {result} | {format_time(item.get('createdAt'))}"):
                method = item.get("inputMethod", "")
                st.write("**Input method:**", INPUT_METHOD_LABELS.get(method, method))
                st.write("**Source:**", item.get("source") or "—")
                st.write("**Machine-learning prediction:**",
                         f"{item.get('modelPrediction', '—')} ({item.get('modelName', MODEL_NAME)})")
                if item.get("phishingProbability") is not None:
                    st.write("**Model phishing probability:**", f"{item['phishingProbability'] * 100:.2f}%")
                st.write("**Rule score:**", item.get("ruleScore", 0))
                st.write("**Final assessment:**", result)
                st.write("**Email text:**")
                st.text(item.get("emailText", ""))
                st.write("**Detected indicators:**")
                for reason in item.get("reasons", []):
                    st.write("• " + reason)

                if item.get("hasImage") and st.checkbox("🖼️ Show screenshot", key=f"show_img_{entry_id}"):
                    if entry_id not in st.session_state.image_cache:
                        try:
                            with st.spinner("Loading screenshot..."):
                                st.session_state.image_cache[entry_id] = client.get_history_image(user, entry_id)
                        except FirebaseError as exc:
                            st.error(f"Could not load the screenshot: {exc}")
                    image_b64, _ = st.session_state.image_cache.get(entry_id, (None, None))
                    if image_b64:
                        st.image(base64_to_bytes(image_b64), caption="Stored screenshot", width="stretch")

                if st.button("🗑️ Delete this entry", key=f"delete_{entry_id}"):
                    try:
                        client.delete_history(user, entry_id)
                        st.session_state.history_cache = None
                        st.session_state.image_cache.pop(entry_id, None)
                        st.rerun()
                    except FirebaseError as exc:
                        st.error(f"Could not delete the entry: {exc}")

        st.divider()
        confirm_clear = st.checkbox("I understand this permanently deletes all my saved history.")
        if st.button("🗑️ Clear History", disabled=not confirm_clear):
            try:
                with st.spinner("Deleting history..."):
                    client.clear_history(user)
                st.session_state.history_cache = None
                st.session_state.image_cache = {}
                st.rerun()
            except FirebaseError as exc:
                st.error(f"Could not clear your history: {exc}")

elif page == "ℹ️ About":
    st.title("ℹ️ About the Phishing Email Detector")
    st.write("This application combines machine learning with rule-based checks to label email messages as Safe, Potentially Suspicious or Phishing.")

    st.subheader("How it works")
    st.write(
        "1. The user provides an email by pasting text, uploading a screenshot, or uploading a text file.\n\n"
        "2. Screenshots are processed using OCR to extract the email text.\n\n"
        "3. The text is transformed using TF-IDF.\n\n"
        f"4. The trained {MODEL_NAME} model predicts whether the email looks like phishing.\n\n"
        "5. A rule layer looks for requests for credentials, urgency, threats and payment pressure, "
        "and lowers the score for wording typical of genuine notices.\n\n"
        "6. The model flag and the rule score are combined into one of three levels.\n\n"
        "7. The result is saved to your account's private history in Firebase Cloud Firestore "
        "(screenshots are compressed and stored as base64 text)."
    )

    st.subheader("Models evaluated")
    st.write("• Logistic Regression\n\n• SVM\n\n• XGBoost\n\n• LightGBM")

    st.subheader("Model used in this app")
    st.success(MODEL_NAME)
    st.caption("Results so far come from small test sets and are preliminary. See the project report for details.")
