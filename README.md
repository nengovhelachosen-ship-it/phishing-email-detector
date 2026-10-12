# Phishing Email Detector

Streamlit app that combines a TF-IDF + LightGBM model with rule-based checks to label
emails as Safe, Potentially Suspicious or Phishing. Users sign in with Firebase
Authentication and each user's detection history (including screenshots, stored as
base64 text) is saved privately in Cloud Firestore.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Screenshot OCR needs the [Tesseract](https://github.com/tesseract-ocr/tesseract) binary
(`packages.txt` installs it on Streamlit Community Cloud).

## Firebase setup (free Spark plan)

The app uses the Firebase Auth and Firestore REST APIs with each user's ID token, so no
service account is needed and the security rules in `firestore.rules` protect the data.

1. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill in the
   web app `api_key` and `project_id` (`npx firebase-tools apps:sdkconfig WEB`).
   Environment variables `FIREBASE_API_KEY` / `FIREBASE_PROJECT_ID` also work.
   On Streamlit Community Cloud, paste the same values into the app's **Secrets**.
2. Deploy the Email/Password provider, security rules and index settings:

   ```bash
   npx firebase-tools deploy --only auth,firestore
   ```

The configured project is `phishing-detector-68459` (`.firebaserc`), with a Standard
edition `(default)` Firestore database in `africa-south1`.

### Data model

| Path | Contents |
| --- | --- |
| `users/{uid}` | `email`, `displayName`, `createdAt` |
| `users/{uid}/history/{id}` | detection result, email text, reasons, optional `imageBase64` + `imageMime` |

Screenshots are resized and re-encoded as JPEG until the base64 text is at most
700,000 characters, keeping each document under Firestore's 1 MiB limit. History
entries can only be created, read and deleted by their owner.

## Tests

```bash
pip install pytest
python -m pytest
```
