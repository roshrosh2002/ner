import streamlit as st
from pdfminer.high_level import extract_text
import io
import re
import requests

# Set max file size limits
MAX_SMALL_FILE = 100 * 1024 * 1024  # 100MB
MAX_MEDIUM_FILE = 200 * 1024 * 1024  # 200MB

# Google Gemini API Key
GEMINI_API_KEY = "cat $env:USERPROFILE\.streamlit\secrets.toml"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent"

# ---- Authentication ----
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if "page" not in st.session_state:
    st.session_state["page"] = "Login"

if "uploaded_file" in st.session_state:
    del st.session_state["uploaded_file"]

def set_page(page_name):
    """Navigate between pages."""
    st.session_state["page"] = page_name
    if "uploaded_file" in st.session_state:
        del st.session_state["uploaded_file"]
    st.rerun()

def authenticate():
    """Simple authentication using environment variables from Streamlit secrets."""
    st.title("🔑 Login")
    
    # Retrieve credentials from Streamlit secrets
    stored_username = st.secrets["username_streamlit"]
    stored_password = st.secrets["password_streamlit"]

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == stored_username and password == stored_password:
            st.session_state["authenticated"] = True
            st.session_state["page"] = "Home"
            st.rerun()
        else:
            st.error("Invalid username or password")

# ---- Text Processing ----
def clean_text(text):
    """Cleans extracted text from PDF."""
    return re.sub(r'\s+', ' ', text).strip()

def save_text_to_txt(text):
    """Save cleaned text as a .txt file."""
    return text.encode('utf-8')

# ---- Named Entity Recognition (NER) & Redaction ----
def perform_ner(text):
    """Extract and redact ticket numbers, full customer names, IP addresses, and emails while keeping steps intact."""
    try:
        # Limit text length to prevent API errors
        max_chars = 5000
        if len(text) > max_chars:
            text = text[:max_chars]

        ticket_numbers = re.findall(r'\b(BEMS\d+|SR\d+)\b', text)
        ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)

        customer_names = []
        customer_name_match = re.search(r'Customer:\s*([A-Za-z\s-]+?)(?=\s*HW|\s*,|\n|$)', text, re.IGNORECASE)
        if customer_name_match:
            customer_names.append(customer_name_match.group(1).strip())

        full_entities = ticket_numbers + customer_names + ip_addresses + emails
        sorted_entities = sorted(full_entities, key=lambda entity: text.find(entity))

        redacted_text = redact_entities(text, customer_names, ticket_numbers)

        return {"redacted_text": redacted_text, "entities": sorted_entities}

    except Exception as e:
        return {"redacted_text": text, "entities": [], "error": f"Request failed: {str(e)}"}

def redact_entities(text, customer_names, ticket_numbers):
    """Replace detected sensitive entities with [REDACTED]."""
    for name in customer_names:
        text = re.sub(rf'(Customer:\s*){re.escape(name)}', r'\1[REDACTED]', text, flags=re.IGNORECASE)

    for ticket in ticket_numbers:
        text = re.sub(rf'\b{re.escape(ticket)}\b', '[REDACTED]', text, flags=re.IGNORECASE)

    return text

# ---- PDF Processing ----
def process_pdf(uploaded_file):
    """Process uploaded PDF and extract text with NER redaction."""
    file_size = uploaded_file.size

    if file_size > MAX_MEDIUM_FILE:
        st.error("❌ File too large! Maximum supported size is 200MB.")
        return None

    with st.spinner(f"Processing {file_size / (1024 * 1024):.2f}MB file..."):
        temp_bytes = uploaded_file.read()
        text = extract_text(io.BytesIO(temp_bytes))

        if not text.strip():
            st.error("The PDF doesn't contain extractable text.")
            return None

        cleaned_text = clean_text(text)
        st.write("### Extracted Text from PDF:")
        st.text_area("", cleaned_text, height=200)

        st.write("### Named Entity Recognition (NER) Results:")
        ner_results = perform_ner(cleaned_text)
        st.json(ner_results)

        txt_data = save_text_to_txt(ner_results["redacted_text"])
        st.download_button(
            label="Download Redacted Text (TXT)",
            data=txt_data,
            file_name="redacted_text.txt",
            mime="text/plain"
        )
    return "Processed"

# ---- Authentication & Navigation ----
if not st.session_state["authenticated"]:
    authenticate()
    st.stop()

st.sidebar.title("Navigation")
selected_page = st.sidebar.radio("Go to", ["Home", "Upload PDF (< 100MB)", "Upload PDF (100MB - 200MB)", "Logout"])
st.session_state["page"] = selected_page

if st.session_state["page"] == "Home":
    st.title("🏠 Welcome to the NER Application")
    st.write("Welcome! Navigate through the sidebar to upload a PDF and start processing.")

elif st.session_state["page"] == "Upload PDF (< 100MB)":
    st.title("📄 Upload Small PDF (< 100MB)")
    uploaded_file = st.file_uploader("Choose a PDF file", type=["pdf"], key="small")
    if uploaded_file:
        process_pdf(uploaded_file)

elif st.session_state["page"] == "Upload PDF (100MB - 200MB)":
    st.title("📄 Upload Medium PDF (100MB - 200MB)")
    uploaded_file = st.file_uploader("Choose a PDF file", type=["pdf"], key="medium")
    if uploaded_file:
        process_pdf(uploaded_file)

elif st.session_state["page"] == "Logout":
    st.session_state["authenticated"] = False
    set_page("Login")



