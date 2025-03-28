from flask import Flask, render_template, request, jsonify
import os
import logging
from Email_Classifier_Module import load_model, load_feature_extractor, classify_emails, get_credentials, fetch_emails

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

UPLOAD_FOLDER = '/home/capstone4340-admin/E-CAT/Capstone_Flask/Databases'  # Adjust as needed
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

@app.route('/network-classifier/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        logging.error("No file part in the request")
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        logging.error("No file selected")
        return jsonify({'message': 'No file selected'}), 400

    if file:
        filename = file.filename  # Or generate a unique filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        logging.info(f"File saved to {filepath}")

        # Start processing the file (replace with your actual processing)
        # process_pcap(filepath)  # Call your processing function here

        return jsonify({'message': 'File uploaded successfully'}), 200
    else:
        logging.error("Upload failed")
        return jsonify({'message': 'Upload failed'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)