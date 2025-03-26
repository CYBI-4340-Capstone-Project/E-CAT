import os
import pickle
import base64
import logging
import json
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from email.mime.text import MIMEText
import re
import time
from sklearn.feature_extraction.text import TfidfVectorizer

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_credentials(teammate_name):
    """Shows basic usage of the Gmail API."""
    creds = None
    token_file = f'token_{teammate_name}.json'
    client_secret_file = f'client_secret_{teammate_name}.json'

    # Check if the token file exists for the selected teammate
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Use the selected teammate's client_secret file for OAuth
            flow = InstalledAppFlow.from_client_secrets_file(
                client_secret_file, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)

    return creds


def fetch_emails(teammate_name, creds):
    """Fetches 2 emails from the selected teammate's Gmail inbox."""
    service = build('gmail', 'v1', credentials=creds)
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], q="is:unread").execute()
    
    # Get the email bodies from the first two emails
    emails = []
    if 'messages' in results:
        messages = results['messages'][:2]
        for msg in messages:
            msg_info = service.users().messages().get(userId='me', id=msg['id']).execute()
            email_body = msg_info['snippet']  # Simplified to get the email body snippet
            emails.append(email_body)
    
    return emails

def load_model():
    """Load the trained spam classification model."""
    with open('spam_classifier_model.pkl', 'rb') as model_file:
        model = pickle.load(model_file)
    return model

def load_feature_extractor():
    """Load the trained TF-IDF feature extractor."""
    with open('feature_extractor.pkl', 'rb') as extractor_file:
        vectorizer = pickle.load(extractor_file)
    return vectorizer

## classifier function for Flask
def classify_emails(model, vectorizer, email_texts):
    """Classify the given email text as spam or not spam."""
    email_features, vectorizer = vectorize_email(email_texts, vectorizer)  # Ensure both are returned

    # Check if the email_features is a 2D array (required for prediction)
    if len(email_features.shape) == 1:
        email_features = email_features.reshape(1, -1)  # Reshape to 2D if it's 1D

    prediction = model.predict(email_features)
    
    # Convert numerical output to a human-readable label
    label_map = {1: "Spam", 0: "Not Spam"}
    return label_map[prediction[0]]

def vectorize_email(email_texts, vectorizer=None):
    if vectorizer is None:
        vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
        email_features = vectorizer.fit_transform(email_texts).toarray()
    else:
        email_features = vectorizer.transform(email_texts).toarray()
    
    return email_features, vectorizer  # Always return both values
