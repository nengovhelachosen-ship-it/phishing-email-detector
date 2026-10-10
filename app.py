import re
import joblib
import pytesseract
import streamlit as st

from PIL import Image
from datetime import datetime

from rules import analyse, verdict

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

if "history" not in st.session_state:
    st.session_state.history = []


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
    page = st.radio("Navigation", ["🏠 Home", "📜 Detection History", "ℹ️ About"])
    st.divider()
    st.write(f"**Model:** TF-IDF + {MODEL_NAME} + rules")


if page == "🏠 Home":
    st.title("🛡️ Phishing Email Detector")
    st.write("Analyse an email and determine whether it is likely to be safe or phishing.")
    st.divider()

    counts = {"PHISHING": 0, "POTENTIALLY SUSPICIOUS": 0, "SAFE": 0}
    for item in st.session_state.history:
        counts[item["Final Result"]] += 1

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📧 Emails Analysed", len(st.session_state.history))
    with col2:
        st.metric("🚨 Phishing", counts["PHISHING"])
    with col3:
        st.metric("⚠️ Suspicious", counts["POTENTIALLY SUSPICIOUS"])
    with col4:
        st.metric("✅ Safe", counts["SAFE"])

    st.divider()
    st.subheader("Choose how you want to provide the email")

    input_method = st.radio(
        "Input method:",
        ["📋 Paste Email", "🖼️ Upload Screenshot", "📄 Upload Text File"],
        horizontal=True
    )

    email_text = ""
    source_name = ""

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

            st.session_state.history.insert(0, {
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Input Method": input_method,
                "Source": source_name,
                "Model Prediction": ml_label,
                "Phishing Probability": phishing_prob,
                "Final Result": final_result,
                "Email Preview": email_text[:200],
                "Reasons": shown_reasons
            })

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

elif page == "📜 Detection History":
    st.title("📜 Detection History")

    if not st.session_state.history:
        st.info("No emails have been analysed yet.")
    else:
        st.write(f"**{len(st.session_state.history)}** email(s) analysed during this session.")

        for item in st.session_state.history:
            if item["Final Result"] == "PHISHING":
                icon = "🚨"
            elif item["Final Result"] == "POTENTIALLY SUSPICIOUS":
                icon = "⚠️"
            else:
                icon = "✅"

            with st.expander(f"{icon} {item['Final Result']} | {item['Time']}"):
                st.write("**Input method:**", item["Input Method"])
                st.write("**Source:**", item["Source"])
                st.write("**Machine-learning prediction:**", item["Model Prediction"])
                if item["Phishing Probability"] is not None:
                    st.write("**Model phishing probability:**", f"{item['Phishing Probability'] * 100:.2f}%")
                st.write("**Final assessment:**", item["Final Result"])
                st.write("**Email preview:**")
                st.text(item["Email Preview"])
                st.write("**Detected indicators:**")
                for reason in item["Reasons"]:
                    st.write("• " + reason)

        st.divider()
        if st.button("🗑️ Clear History"):
            st.session_state.history = []
            st.rerun()

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
        "7. The result is stored in the session history."
    )

    st.subheader("Models evaluated")
    st.write("• Logistic Regression\n\n• SVM\n\n• XGBoost\n\n• LightGBM")

    st.subheader("Model used in this app")
    st.success(MODEL_NAME)
    st.caption("Results so far come from small test sets and are preliminary. See the project report for details.")
