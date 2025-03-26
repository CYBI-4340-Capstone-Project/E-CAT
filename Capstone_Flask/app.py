from flask import Flask, render_template, request
from Email_Classifier_Module2 import load_model, load_feature_extractor, classify_emails, get_credentials, fetch_emails

app = Flask(__name__)

# Load the model and vectorizer
model, vectorizer = load_model(), load_feature_extractor()

@app.route('/')
def index():
    return render_template('index.html', pageTitle="Home")

@app.route('/spam-classifier', methods=['GET', 'POST'])
def spam_classifier():
    prediction = None
    email_bodies = []
    vectorized_bodies = []
    if request.method == 'POST':
        # Get the selected teammate from the dropdown
        selected_teammate = request.form['teammate']
        
        # Get credentials for the selected teammate
        creds = get_credentials(selected_teammate)  # This will call the new get_credentials function
        
        # Fetch 2 emails from the selected user's inbox
        emails = fetch_emails(selected_teammate, creds)
        email_bodies = emails  # Save the email bodies
        
        # Classify emails after vectorizing them
        prediction = classify_emails(model, vectorizer, emails)
    
    return render_template(
        'spam_classifier2.html',
        pageTitle="Spam Classifier",
        prediction=prediction,
        email_bodies=email_bodies,
        vectorized_bodies=vectorized_bodies
    )

@app.route('/phishing-classifier', methods=['GET', 'POST'])
def phishing_classifier():
    return render_template('phishing_classifier.html')

@app.route('/malware-classifier', methods=['GET', 'POST'])
def malware_classifier():
    return render_template('malware_classifier.html')

@app.route('/network-classifier', methods=['GET', 'POST'])
def network_classifier():
    return render_template('network_classifier.html')


if __name__ == '__main__':
    app.run(debug=True)
