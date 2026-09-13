import streamlit as st
import joblib
import re
import pytesseract

from PIL import Image
from datetime import datetime


@st.cache_resource
def load_model():
    model = joblib.load("phishing_lightgbm_model.pkl")
    vectorizer = joblib.load("tfidf_vectorizer.pkl")
    return model, vectorizer

model, vectorizer = load_model()

st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide"
)

if "history" not in st.session_state:
    st.session_state.history = []


def predict_email(email):
    email_tfidf = vectorizer.transform([email])
    prediction = model.predict(email_tfidf)[0]
    probabilities = model.predict_proba(email_tfidf)[0]
    return prediction, probabilities[0], probabilities[1]


def analyze_email(email):
    text = email.lower()
    reasons = []
    risk_score = 0

    urls = re.findall(r"https?://\S+|www\.\S+", email)
    if urls:
        risk_score += 2
        reasons.append("Contains one or more URLs or links.")

    download_words = [
        "download", "download here", "download document",
        "download file", "click to download", "download the document"
    ]
    if any(word in text for word in download_words):
        risk_score += 2
        reasons.append("Requests or encourages the user to download a document or file.")

    document_words = [
        "shared a document", "shared a file", "document details",
        "pdf document", "attached document", "shared document"
    ]
    if any(word in text for word in document_words):
        risk_score += 1
        reasons.append("Contains a shared-document or file-related message.")

    refund_words = [
        "refund", "refund payment", "money refund",
        "claim your refund", "refund available", "refund request"
    ]
    if any(word in text for word in refund_words):
        risk_score += 2
        reasons.append("Contains refund or unexpected-money language.")

    urgent_words = [
        "urgent", "immediately", "act now", "action required",
        "within 24 hours", "within 24 hrs", "account suspended",
        "account will be closed", "verify immediately",
        "last warning", "final warning"
    ]
    if any(word in text for word in urgent_words):
        risk_score += 2
        reasons.append("Uses urgent or threatening language.")

    sensitive_words = [
        "password", "username", "login", "verify your account",
        "credit card", "bank account", "pin", "otp",
        "one time password", "personal information", "security code"
    ]
    if any(word in text for word in sensitive_words):
        risk_score += 3
        reasons.append("Contains language related to sensitive account or personal information.")

    prize_words = [
        "you have won", "winner", "cash prize", "reward",
        "lottery", "congratulations", "claim your prize", "free money"
    ]
    if any(word in text for word in prize_words):
        risk_score += 3
        reasons.append("Contains unexpected prize, reward, or winnings language.")

    financial_words = [
        "payment", "transfer money", "send money", "refund",
        "bank", "invoice", "payment failed", "transaction", "account balance"
    ]
    if any(word in text for word in financial_words):
        risk_score += 1
        reasons.append("Contains financial or payment-related language.")

    suspicious_phrases = [
        "click here", "click the link", "verify your identity",
        "confirm your account", "update your account", "security alert",
        "unusual activity", "suspicious activity",
        "your account has been compromised"
    ]
    if any(phrase in text for phrase in suspicious_phrases):
        risk_score += 2
        reasons.append("Contains suspicious account or verification phrases.")

    if email.count("!") >= 3:
        risk_score += 1
        reasons.append("Uses multiple exclamation marks.")

    if not reasons:
        reasons.append("No obvious rule-based phishing indicators were detected.")

    return reasons, risk_score


with st.sidebar:
    st.title("🛡️ Phishing Detector")
    page = st.radio("Navigation", ["🏠 Home", "📜 Detection History", "ℹ️ About"])
    st.divider()
    st.write("**Model:** TF-IDF + LightGBM")


if page == "🏠 Home":
    st.title("🛡️ Phishing Email Detector")
    st.write("Analyse an email and determine whether it is likely to be safe or phishing.")
    st.divider()

    total = len(st.session_state.history)
    phishing_count = 0
    safe_count = 0
    for item in st.session_state.history:
        if item["Result"] == "PHISHING":
            phishing_count += 1
        else:
            safe_count += 1

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("📧 Emails Analysed", total)
    with col2:
        st.metric("🚨 Phishing", phishing_count)
    with col3:
        st.metric("✅ Safe", safe_count)

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
            prediction, safe_prob, phishing_prob = predict_email(email_text)
            reasons, risk_score = analyze_email(email_text)

            # Blend the rule-based risk score into the ML probability instead
            # of only using risk_score as a hard on/off override. Each risk
            # point nudges the phishing probability up by 5 percentage points,
            # capped at 100%.
            combined_phishing_prob = min(1.0, phishing_prob + (risk_score * 0.05))
            combined_safe_prob = 1.0 - combined_phishing_prob

            if prediction == 1:
                result = "PHISHING"
                confidence = phishing_prob
            else:
                result = "SAFE"
                confidence = safe_prob

            if combined_phishing_prob >= 0.60:
                final_result = "PHISHING"
            elif combined_phishing_prob >= 0.35:
                final_result = "POTENTIALLY SUSPICIOUS"
            else:
                final_result = "SAFE"

            st.session_state.history.insert(0, {
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Input Method": input_method,
                "Source": source_name,
                "Result": result,
                "Final Result": final_result,
                "Confidence": confidence,
                "Combined Phishing Probability": combined_phishing_prob,
                "Email Preview": email_text[:200],
                "Reasons": reasons
            })

            st.divider()

            if final_result == "PHISHING":
                st.error("🚨 PHISHING EMAIL")
            elif final_result == "POTENTIALLY SUSPICIOUS":
                st.warning("⚠️ POTENTIALLY SUSPICIOUS EMAIL")
            else:
                st.success("✅ SAFE EMAIL")

            st.subheader("🤖 Machine-Learning Prediction (raw)")
            ml_label = "PHISHING" if prediction == 1 else "SAFE"
            st.write("**LightGBM prediction:** " + ml_label)

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Safe Probability", f"{safe_prob * 100:.2f}%")
            with col2:
                st.metric("Phishing Probability", f"{phishing_prob * 100:.2f}%")

            st.subheader("🔎 Security Analysis")
            st.write(f"**Security risk score:** {risk_score}")

            if risk_score >= 4:
                st.warning("Multiple suspicious indicators were detected.")
            elif risk_score > 0:
                st.info("Some potentially suspicious indicators were detected.")
            else:
                st.success("No obvious rule-based indicators were detected.")

            st.write("**Detected indicators:**")
            for reason in reasons:
                st.write("• " + reason)

            st.subheader("📊 Combined Assessment")
            st.write(
                "The final verdict blends the raw ML probability with the "
                "rule-based risk score, since the model alone can miss "
                "phishing styles it wasn't trained on."
            )

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Combined Safe Probability", f"{combined_safe_prob * 100:.2f}%")
            with col2:
                st.metric("Combined Phishing Probability", f"{combined_phishing_prob * 100:.2f}%")

            if prediction == 0 and final_result != "SAFE":
                st.warning(
                    "The machine-learning model alone classified this email as SAFE, "
                    "but the combined assessment (including rule-based indicators) "
                    "raised its risk level. Users should verify the sender before "
                    "clicking links or downloading files."
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
                st.write("**Machine-learning prediction:**", item["Result"])
                st.write("**Final assessment:**", item["Final Result"])
                st.write("**Confidence:**", f"{item['Confidence'] * 100:.2f}%")
                st.write("**Combined phishing probability:**", f"{item['Combined Phishing Probability'] * 100:.2f}%")
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
    st.write("This application uses machine learning to classify email messages as Safe or Phishing.")

    st.subheader("How it works")
    st.write(
        "1. The user provides an email by pasting text, uploading a screenshot, or uploading a text file.\n\n"
        "2. Screenshots are processed using OCR to extract the email text.\n\n"
        "3. The extracted text is transformed using TF-IDF.\n\n"
        "4. The TF-IDF features are analysed by the trained LightGBM model.\n\n"
        "5. The application displays the machine-learning prediction and probability.\n\n"
        "6. A security-indicator layer checks for common suspicious characteristics.\n\n"
        "7. The result is stored in the session history."
    )

    st.subheader("Models evaluated")
    st.write("• Logistic Regression\n\n• XGBoost\n\n• LightGBM")

    st.subheader("Final model")
    st.success("LightGBM")
    st.write("Phishing Recall: 98.02%")
