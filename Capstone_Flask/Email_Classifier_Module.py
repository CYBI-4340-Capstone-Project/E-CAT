import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

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

def vectorize_emails(email_texts, vectorizer):
    """Transform input email text into numerical feature representation."""
    email_features = vectorizer.transform(email_texts).toarray()
    return email_features


## classifier function for Flask
def classify_emails(model, vectorizer, email_texts):
    """Classify the given email text as spam or not spam."""
    email_features = vectorize_emails(email_texts, vectorizer)
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
