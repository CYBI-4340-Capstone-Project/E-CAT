from flask import Flask, render_template, flash, redirect, url_for, session, request, Response, jsonify, abort, send_file
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy #pip install Flask-SQLAlchemy
from pathlib import Path
from argon2 import PasswordHasher       #pip install argon2-cffi
from flask_wtf import FlaskForm         #pip install flask-wtf
from wtforms import StringField, IntegerField, SubmitField, EmailField, TelField, DateField, TextAreaField, RadioField, BooleanField 
from wtforms.validators import data_required, ValidationError
from functools import wraps
#from password_strength import PasswordPolicy, PasswordStats
import os, time, subprocess, requests, platform, string, json
import logging
import shutil  # Add to imports
from werkzeug.utils import secure_filename
from Email_Classifier_Module import load_model, load_feature_extractor, classify_emails, get_credentials, fetch_emails
from extract_features import FeatureExtractor
from preprocess import Preprocessor
from predict import Predictor
import numpy as np
from sqlalchemy import Text
import pickle
import base64
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
import warnings


# Configure logging
log_dir = os.path.join("logs", datetime.now().strftime('%Y-%m-%d'))
try:
    os.makedirs(log_dir, exist_ok=True)  # Ensure the directory exists
except Exception as e:
    print(f"Error creating log directory: {e}")
log_file = os.path.join(log_dir, datetime.now().strftime('app.log'))
print(f"Log file path: {log_file}")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a'  # Append to the log file if it exists
)
app = Flask(__name__)
if __name__ != '__main__': 
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
#Secret key to prevent CSRF, cryptographically signs session cookies
app.config['SECRET_KEY'] = 'insecurePassword'

#Configuring the Database location
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{Path(__file__).parent / './Databases/userAccounts.db'}"

#Initialize the database
db = SQLAlchemy(app)

# Setting default password policy
passLen = 9
passCase = 1
passNum = 1
passSpec = 1

# Salt generator for password hashes
def generateSalt():
    return os.urandom(16)

# Password hash generator
# Function to hash a password
def generateHash(passw):
    ph = PasswordHasher()
    return ph.hash(passw) #automatically stores the salt with the hash
    
def requires_confirmation(route):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if route == 'delete_account_confirm':
                if not session.get('delete_account_confirmed'):
                    flash("Please confirm information to delete your account.")
                    return redirect(url_for('settings_delete_confirm'))
            else: 
                if not session.get('user_authenticated'):
                    flash("Please confirm information in order to access this page.")
                    return redirect(url_for('settings_confirm'))  # Change 'login' to your login route
                # Check if the route is the delete account confirmation
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Finction to strip multiple characters from a string
def stripChars(input: string, strip: string):
    begStr = str(input)
    chars = str(strip)

    for ch in chars:
        if ch in begStr:
            begStr = begStr.replace(ch, '')
            
    return begStr

# Custom WTForms validator to check password complexity 
def validatePassword(form, field):
    uppers = sum(1 for c in field.data if c.isupper())
    digits = sum(1 for c in field.data if c.isdigit())
    specials = 0
    for c in field.data:
        if ord(c) >= 32 and ord(c) <= 47:
            specials += 1
        elif ord(c) >= 58 and ord(c) <= 64:
            specials += 1
        elif ord(c) >= 91 and ord(c) <= 96:
            specials += 1
        elif ord(c) >= 123 and ord(c) <= 126:
            specials += 1
    if len(field.data) < passLen:
        print('len error')
        raise ValidationError('Password must contian at least ' + str(passLen) + ' characters')
    elif uppers < passCase:
        print('case error')
        raise ValidationError('Password must contain at least ' + str(passCase) + ' upper-case character')
    elif digits < passNum:
        print('num error')
        raise ValidationError('Password must contain at least ' + str(passNum) + ' number')
    elif specials < passSpec:
        print('spec error')
        raise ValidationError('Password must contain at least ' + str(passSpec) + ' special character')
    
def split_integer_at_rightmost_digit(input_integer):
    # Convert the integer to a string
    input_str = str(input_integer)

    # Extract the rightmost digit
    rightmost_digit = int(input_str[-1])

    # Extract everything to the left of the rightmost digit
    left_of_rightmost_digit_str = input_str[:-1]

    # Check if the string is not empty before converting to int
    if left_of_rightmost_digit_str:
        left_of_rightmost_digit = int(left_of_rightmost_digit_str)
    else:
        # Handle the case when the string is empty
        left_of_rightmost_digit = 0  # or any default value you prefer

    return left_of_rightmost_digit, rightmost_digit

# Configure upload folders
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'Databases')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the Data model includes PCAP-specific fields (replace existing)
class network_Data(db.Model):
    ID = db.Column(db.Integer, primary_key=True)
    user_ID = db.Column(db.Integer, db.ForeignKey('user_credentials.user_ID'))
    pcap_filename = db.Column(db.String(100), nullable=False)   # e.g., "1.pcap"
    pcap_path = db.Column(db.String(200), nullable=False)   # e.g., ".../Databases/1/1/1.pcap"
    final_path = db.Column(db.String(200))    # For extracted features e.g., ".../Databases/1/1/1_final.csv"
    results_path = db.Column(db.String(200)) #e.g, ".../Databases/1/1/1_results.csv"
    threat_type = db.Column(db.String(50)) # e.g., "BENIGN", "MALWARE", "DOS", etc.
    accuracy = db.Column(db.Float)
    malicious_records = db.Column(db.Integer) # Count of malicious flows
    total_flows = db.Column(db.Integer)     # Total flows analyzed
    analysis_results = db.Column(db.Text)  # Stores JSON-serialized DataFrame
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)

#Creating a model for user preferences

#Creating a model for user credentials
class  UserCredentials(db.Model):
    user_ID = db.Column(db.Integer, primary_key=True)
    user_Name = db.Column(db.String(50),nullable=False)
    user_Email = db.Column(db.String(60), nullable=False, unique=True)
    #user_Phone = db.Column(db.Integer, unique=True)
    #pass_salt = db.Column(db.Integer, nullable=False, unique=True)
    pass_hash = db.Column(db.String, nullable=False) #should be salted already
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    network_data = db.relationship('network_Data', backref='userCred', lazy=True)

#Create a registration form class
class RegisterForm (FlaskForm):
    username = StringField("Username: ", validators=[data_required()])
    email = EmailField("Email: ", validators=[data_required()])
    #phone = TelField("Phone: ")
    password = StringField("Password: ", validators=[data_required(), validatePassword])
    submit = SubmitField("Register")
    
#Create a login form class
class LoginForm (FlaskForm):
    username = StringField("Username: ", validators=[data_required()])
    password = StringField("Password: ", validators=[data_required()])
    submit = SubmitField("Sign in")

class SettingForm(FlaskForm):
    #new_phone = TelField("New Phone: ")
    new_username = StringField("New Username:", validators=[data_required()])
    new_email = EmailField("New Email: ", validators=[data_required()])
    new_password = StringField("New Password: ")
    submit = SubmitField("Apply")

class Settings_ConfirmForm (FlaskForm):
    username = StringField("Confirm Username: ", validators=[data_required()])
    password = StringField("Confirm Password: ", validators=[data_required()])
    submit = SubmitField("Confirm")

#Create a AssessmentForm form class
class AssessmentForm (FlaskForm):
    title = StringField("Assessment Title", validators=[data_required()])
    description = TextAreaField("Description (optional)")
    date = DateField("Due date", validators=[data_required()])
    priority = RadioField("Priority",  choices=['N/A', 'Low', 'Medium', 'High'], validators=[data_required()])
    submit = SubmitField("Submit")

#Creates a context to manage the database
with app.app_context():
    #Drops all tables from the database
    #db.drop_all()

    #Adds tables out of all the modles in the database, unless they already exist
    #db.create_all()

    #LoginCredentials.__table__.create(db.engine)

    #Drops one specific table
    #LoginCredentials.__table__.drop(db.engine)
    pass

#============================================== App routes
#============================================================================================================== Default/Login

# Load the model and vectorizer
model, vectorizer = load_model(), load_feature_extractor()

#Handles the backend of the login page
#======================= Login =======================#
@app.route('/', methods=['POST', 'GET'])
def log_in():
    if session.get('username'):
        return redirect(url_for('homepage'))
    else:
        if(UserCredentials.query.filter_by(user_Name='admin').first() is None):
            # Admin Creds for debugging purposes.  <------------------------------------------------------------------------------------ Remove before release
            #adminSalt = generateSalt()
            adminPass = 'admin'  # Default password (change this before release)
            # Hash the password (Argon2 will handle salting internally)
            adminPassHash = generateHash(adminPass)
            # Create and add the admin user
            adminUser = UserCredentials(
                user_ID=1,
                user_Name='admin',
                user_Email='admin@email.com',
                pass_hash=adminPassHash  # Store only the hash
            )
            db.session.add(adminUser)
            db.session.commit()


            #db.session.add(Preferences(user_ID= UserCredentials.query.filter_by(user_Name='admin').first().user_ID, notifications= 0, study_time= 3600, break_time= 600))
            #db.session.commit()
        # Initializes values to None 
        username = None
        password = None
        passHash = None
        #salt = None
        # Specifies the form class to use
        form = LoginForm()

        #Checks if the submit button has been pressed
        if form.validate_on_submit():
            # Queries the database to see if the username exists
            user = UserCredentials.query.filter_by(user_Name=form.username.data).first()
            # if user exists
            if user:
                # The salt and hash associated with the user's profile are taken from the database
                #salt = user.pass_salt
                #userHash = user.pass_hash
                # A new hash is generated with the password entered into the login form, using the same salt that is within the database
                try: 
                    if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice Try.")
                        return render_template('log_in.html', form=form, username = username, passHash = passHash) #salt = salt
                    ph = PasswordHasher()
                    if ph.verify(user.pass_hash, form.password.data):
                        session['username'] = user.user_Name
                        session['user_id'] = user.user_ID
                        session['user_authenticated'] = None
                        session['delete_account_confirmed'] = None
                        return redirect(url_for('homepage'))
                except:
                    flash("Error: the information you entered does not match our records")

            else:
                if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice try.")
                else:
                    flash("Error: User does not exist the information you entered does not match our records.")

            #Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            password = form.password.data
            form.password.data = ''
            session['user_authenticated'] = None
            session['delete_account_confirmed'] = None
        # Re-rendering the login page after a failed login attempt
        return render_template('log_in.html', form=form, username = username, passHash = passHash) #salt = salt

#======================= Create_Account =======================#
@app.route('/create_account',  methods=['POST', 'GET'])
def Register():
    username = None
    email = None
    #phone = None
    password = None
    passHash = None
    #salt = generateSalt()
    form = RegisterForm()

    # Checks if the submit button has been pressed
    if form.validate_on_submit():
        # Queries the database to see if the email already exists in the database
        user = UserCredentials.query.filter_by(user_Email=form.email.data).first()
        if user is None:
            # If no user exists with the email entered, checks to see if the phone number exists in the database
            #user = UserCredentials.query.filter_by(user_Phone=form.phone.data).first()
            #if user is None:
            # If no user exists with the phone nunmber entered, A hash is generated from the user's password with a random salt
            passHash = generateHash(form.password.data) #, salt
            # A database object is created with the user's information
            user = UserCredentials(user_Name = form.username.data, user_Email = form.email.data, pass_hash = passHash) #pass_salt = salt
            session['username'] = user.user_Name                
            
            # The newly created user object is added to a database session, and committed as an entry to the user_credentials table
            db.session.add(user)
            db.session.commit()
            session['user_id'] = (UserCredentials.query.filter_by(user_Name = form.username.data).first()).user_ID

            # A database object is created alongside the user's account to store their preferences (initialized with default values).
            #prefs = Preferences(user_ID= session.get('user_id'), notifications= 0, study_time= 3600, break_time= 600)
            #db.session.add(prefs)
            #db.session.commit()
            # The user is logged in and redirected to the homepage
            session['user_authenticated'] = None
            session['delete_account_confirmed'] = None
            return redirect(url_for('homepage'))
            
            # If the phone number that was entered is associated with an existing user account, the user is instead brought back to the registration page
            #else:
                #flash("Error: Phone number already in use.")
        # If the email that was entered is associated with an existing user account, the user is instead brought back to the registration page
        else:
            flash("Error: Email already in use.")

        #Clearing the form data after it has been submitted
        username = form.username.data
        form.username.data = ''
        email = form.email.data
        form.email.data = ''
        #phone = form.phone.data
        #form.phone.data = ''
        password = form.password.data
        form.password.data = ''

     # Re-rendering the account creation page after an unsuccessful submission
    session['user_authenticated'] = None
    session['delete_account_confirmed'] = None
    return render_template('create_acct.html', form=form, username = username, email = email, passHash = passHash) #, salt = salt

#======================= Forgot_Password =======================#
@app.route('/Forgot_Password')
def forgotpw():
    if session.get('username'):
        return redirect(url_for('homepage'))
    else:
        # Initializes values to None 
        username = None
        password = None
        passHash = None
        #salt = None
        # Specifies the form class to use
        form = LoginForm()

        #Checks if the submit button has been pressed
        if form.validate_on_submit():
            # Queries the database to see if the username exists
            user = UserCredentials.query.filter_by(user_Name=form.username.data).first()
            # if user exists
            if user is not None:
                # The salt and hash associated with the user's profile are taken from the database
                #salt = user.pass_salt
                userHash = user.pass_hash
                # A new hash is generated with the password entered into the login form, using the same salt that is within the database
                passHash = generateHash(form.password.data) #, salt
                # The newly generated hash is compared to the hash within the database
                if passHash == userHash:
                    session['username'] = user.user_Name
                    session['user_id'] = user.user_ID
                    session['user_authenticated'] = None
                    session['delete_account_confirmed'] = None
                    # If the hashes matched, the user is logged in and redirected to the home page
                    return redirect(url_for('homepage'))
                #Otherwise, the user is not redirected and the form is cleared
                else:
                    #SQL injection easter egg
                    if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice try.")
                    else:
                        flash("Error: the information you entered does not match our records.")
            else:
                if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice try.")
                else:
                    flash("Error: the information you entered does not match our records.")

            #Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            password = form.password.data
            form.password.data = ''
        # Re-rendering the login page after a failed login attempt
        session['user_authenticated'] = None
        session['delete_account_confirmed'] = None
        return render_template('forgotpw.html', form=form, username = username, passHash = passHash) #, salt = salt

#======================= Homepage =======================#
@app.route('/Homepage')
def homepage():
    if session.get('username'):
        greeting = "Hello, " + session['username'] + '.'
        flash(greeting)
        session['user_authenticated'] = None
        session['delete_account_confirmed'] = None
        return render_template('homepage.html')
    else:
        return redirect(url_for('log_in'))

#======================= Spam_Classifier =======================#
@app.route('/Homepage/Spam_Classifier', methods=['GET', 'POST'])
def spam_classifier():
    prediction = None
    email_bodies = []
    vectorized_bodies = []
    if session.get('username'):
        if request.method == 'POST':
            session['user_authenticated'] = None
            session['delete_account_confirmed'] = None
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
            'spam_classifier.html',
            pageTitle="Spam Classifier",
            prediction=prediction,
            email_bodies=email_bodies,
            vectorized_bodies=vectorized_bodies
        )
    else: 
        return redirect(url_for('log_in'))
    
#======================= URL_Classifier =======================#
warnings.filterwarnings("ignore", category=UserWarning)

@app.route('/Homepage/URL_Classifier', methods=['GET', 'POST'])
def url_classifier():
    if not session.get('username'):
        flash('Please log in first', 'error')
        return redirect(url_for('log_in'))
    
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        virustotal_key = request.form.get('virustotal_key', '').strip() or None
        
        if not url:
            flash('Please enter a valid URL', 'error')
            return redirect(url_for('url_classifier'))
        
        try:
            # Initialize scanner
            from url_scanner import URLScanner
            scanner = URLScanner()
            
            # Scan URL
            results = scanner.scan(url, virustotal_key)
            
            # Debug output
            app.logger.info(f"Scan results: {results}")
            
            return render_template('url_classifier.html', 
                                results=results,
                                scanned_url=url)
            
        except Exception as e:
            app.logger.error(f"URL scan failed: {str(e)}")
            flash(f'Analysis failed: {str(e)}', 'error')
    
    return render_template('url_classifier.html')

#======================= Malware_Classifier =======================#
@app.route('/Homepage/Malware_Classifier', methods=['GET', 'POST'])
def malware_classifier():
    if session.get('username'):
        session['user_authenticated'] = None
        session['delete_account_confirmed'] = None
        return render_template('malware_classifier.html')
    else: 
        return redirect(url_for('log_in'))

#======================= Network_Classifier =======================#
@app.route('/Homepage/Network_Classifier', methods=['GET', 'POST'])
def network_classifier():
    if session.get('username'):
        session['user_authenticated'] = None
        session['delete_account_confirmed'] = None
        return render_template('network_classifier.html')
    else: 
        return redirect(url_for('log_in'))

def convert_to_serializable(obj):
    """Convert numpy types to native Python types for JSON serialization"""
    if isinstance(obj, (np.integer, np.int64)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, pd.DataFrame):
        return obj.to_dict(orient='records')
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(x) for x in obj]
    return obj
#======================= Network_Classifier_upload =======================#
@app.route('/Homepage/Network_Classifier/upload', methods=['POST'])
def upload_file():
    if session.get('username'):
        session['user_authenticated'] = None
        session['delete_account_confirmed'] = None
        if 'file' not in request.files:
            logging.error("No file part in the request")
            return jsonify({'message': 'No file part'}), 400

        file = request.files['file']
        # Query the user's information from the database
        user = UserCredentials.query.filter_by(user_Name=session['username']).first()
        # Check if the user is found in the database
        user_id = user.user_ID
        
        if file.filename == '':
            logging.error("No file selected")
            return jsonify({'message': 'No file selected'}), 400

        if file:
            # STEP 1 SAVE PCAP FILE
            user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))# Convert to string just for the os.path.join
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            pcap_filename = secure_filename(file.filename) # would still be "1.pcap"
            pcap_name = os.path.splitext(pcap_filename)[0] # if it's 1.pcap it's now "1"
            pcap_dir = os.path.join(user_dir, pcap_name)

            os.makedirs(pcap_dir, exist_ok=True)

            pcap_path = os.path.join(pcap_dir, pcap_filename)
            file.save(pcap_path) # Should be saving to ./Databases/1/1/1.pcap
                                 # 1st 1 is the user ID which is admin, can be 2, 3, 4...
                                 # 2nd 1 is the pcap_name, removes .pcap
                                 # 3rd 1 is the full pcap_filename, 1.pcap
            logging.info(f"File saved to {pcap_path}")

            # STEP 2 EXTRACT FEATURES FROM PCAP FILE
            extractor = FeatureExtractor()
            extract_result = extractor.process_pcap(pcap_path, user_id=user_id)
            if extract_result['status'] == 'success':
                logging.info(f"Output Directory: {extract_result['output_dir']}")
                logging.info(f"tshark CSV: {extract_result['tshark_csv']}")
                logging.info(f"CIC CSV: {extract_result['cic_csv']}")
            else:
                logging.error("Extract Result: {extract_result['status']}")
                return jsonify({'message': 'Feature Extraction Failed'}), 500
            
            # After feature extraction:
            processed = Preprocessor()
            
            # STEP 3 BUILD DATASET BY FIXING PROTO, DTYPES, NAMES, OR LOAD DATASET
            #final_path = processed.load_dataset(user_id, pcap_name)
            # What if they have the same filename but is resubmitting because it has been changed? 
            # Should we always overwrite or make feature to ask if overwriting? 
            #if final_path is None:
            # 2. Create CIC-formatted file            
            # 3. Build final dataset
            try:
                cic_path = processed.to_cic(user_id, pcap_name)
                final_path = processed.build_dataset(user_id, pcap_name) # e.g., ./Databases/1/1/1_final.csv
            except Exception as e:
                logging.error(f"Preprocessing failed: {str(e)}")
                return jsonify({'error': 'Preprocessing failed'}), 500
                
            # TO IMPLEMENT STEP 4, run prediction
            predictor = Predictor()
            # Update this section in app.py's network_classifier_upload route
            try:                
                prediction_results = predictor.predict(user_id, final_path)
                
                #ensure we have all required fields with defaults
                summary = prediction_results.get('summary', {})
                results_df = prediction_results.get('results_df', pd.DataFrame())
                # Store in database - convert DataFrame to JSON
                existing_entry = network_Data.query.filter_by( # Check if entry already there
                    user_ID = user_id,
                    pcap_filename=pcap_filename
                ).first()
                if existing_entry:
                    logging.info(f"Overwriting existing file: {final_path}")
                # Replace existing record
                    existing_entry.pcap_path = pcap_path,
                    existing_entry.final_path = final_path,
                    existing_entry.results_path = prediction_results['summary']['results_path'],
                    existing_entry.threat_type = prediction_results['summary']['threat_type'],
                    existing_entry.accuracy = float(prediction_results['summary']['accuracy']),
                    existing_entry.malicious_records = int(prediction_results['summary']['malicious_count']),
                    existing_entry.total_flows = int(prediction_results['summary']['total_flows']),
                    existing_entry.analysis_results = prediction_results['results_df'].to_json(orient='records')
                else:
                    # Create new record
                    new_entry = network_Data(
                        user_ID=user_id,
                        pcap_filename=pcap_filename,
                        pcap_path=pcap_path,
                        final_path=final_path,
                        results_path=prediction_results['summary']['results_path'],
                        threat_type=prediction_results['summary']['threat_type'],
                        accuracy=float(prediction_results['summary']['accuracy']),
                        malicious_records=int(prediction_results['summary']['malicious_count']),
                        total_flows=int(prediction_results['summary']['total_flows']),
                        analysis_results=prediction_results['results_df'].to_json(orient='records')
                    )
                    db.session.add(new_entry)

                db.session.commit()
                
                # Convert numpy types to native Python types
                summary = {k: convert_to_serializable(v) 
                        for k, v in prediction_results.get('summary', {}).items()}
                
                # Prepare response
                response = {
                    'threat_type': summary.get('threat_type', 'BENIGN'),
                    'accuracy': summary.get('accuracy', 0.0),
                    'malicious_count': summary.get('malicious_count', 0),
                    'total_flows': summary.get('total_flows', 0),
                    'malicious_flows': convert_to_serializable(
                        prediction_results.get('results_df', pd.DataFrame())
                        [prediction_results.get('results_df', pd.DataFrame())['is_malicious']]
                        .to_dict(orient='records')
                    ),
                    'download_path': f"/Homepage/Network_Classifier/download_results?results_path={summary.get('results_path', '')}" 
                }
                
                return jsonify(response), 200
                
            except Exception as e:
                logging.error(f"Upload failed: {str(e)}")
                return jsonify({
                    'error': str(e),
                    'threat_type': 'BENIGN',
                    'accuracy': 0.0,
                    'malicious_count': 0,
                    'total_flows': 0,
                    'malicious_flows': [],
                    'download_path': ''
                }), 500
        else:
            logging.error("Upload failed")
            return jsonify({'message': 'Upload failed'}), 500
    else: 
        return redirect(url_for('log_in'))
    
@app.route('/Homepage/Network_Classifier/download_results', methods=['GET'])
def download_results():
    try:
        # Get the full results_path from the query parameter
        results_path = request.args.get('results_path')
        
        # Security check - ensure the file exists
        if not results_path or not results_path.endswith('_results.csv'):
            abort(400, "Invalid file type or missing results_path")
        
        if not os.path.exists(results_path):
            abort(404, "File not found")
        
        return send_file(
            results_path,
            as_attachment=True,
            download_name=os.path.basename(results_path),  # Extract the filename for download
            mimetype='text/csv'
        )
    except Exception as e:
        logging.error(f"Download failed: {str(e)}")
        abort(500, "Could not download file")

#======================= Settings =======================#
@app.route('/Homepage/Settings', methods=['POST', 'GET'])
def settings():
    # Initializes values to None 
    new_username = None
    new_email = None
    #new_phone = None
    new_password = None
    user_ID = None
    #salt = None
    id = None
    session['delete_account_confirmed'] = None
    # Specifies the form class to use
    if session.get('username'):
        # Query the user's information from the database
        user = UserCredentials.query.filter_by(user_Name=session['username']).first()
        # Check if the user is found in the database
        id = user.user_ID
        #salt = user.pass_salt
        name_to_update = UserCredentials.query.get_or_404(id)
        form = SettingForm()
        if form.validate_on_submit(): 
            # Check if the new username is empty or equals the current username
            if not form.new_username.data:
                flash("Error: New username cannot be empty")
            # Check if the new username is already taken
            elif form.new_username.data != user.user_Name and UserCredentials.query.filter_by(user_Name=form.new_username.data).first():
                flash("Error: New username is already taken.")
            # Check if the new email is empty or equals the current email
            elif not form.new_email.data:
                flash("Error: New email cannot be empty")
            # Check if the new email is already taken
            elif form.new_email.data != user.user_Email and UserCredentials.query.filter_by(user_Email=form.new_email.data).first():
                flash("Error: New email is already taken.")
            # Check if the new phone number is not empty and contains non-numeric characters
            #elif form.new_phone.data and (not form.new_phone.data.isdigit()):
                #flash("Error: New phone number cannot contain non-numeric characters.")
            # Check if the new phone number is not empty, is different from the current one, and is already taken
            #elif form.new_phone.data and form.new_phone.data != str(user.user_Phone) and UserCredentials.query.filter_by(user_Phone=form.new_phone.data).first():
                #flash("Error: New phone number is already taken.")
            else:
                # Update user information
                session['user_authenticated'] = None
                session['delete_account_confirmed'] = None
                name_to_update.user_Name = form.new_username.data
                name_to_update.user_Email = form.new_email.data
                #name_to_update.user_Phone = form.new_phone.data
                if form.new_password.data:
                    name_to_update.pass_hash = generateHash(form.new_password.data) #, salt
                session['username'] = form.new_username.data
            try: 
                db.session.commit()
                flash("User Information Updated Successfully!")
                # Re-query the user after committing changes
                session['user_authenticated'] = None
                session['delete_account_confirmed'] = None
                name_to_update = UserCredentials.query.get_or_404(id)
                print(f"Session username: {session.get('username')}")
                print(f"User ID: {id}")

                return render_template("settings.html", 
                        form=form, 
                        name_to_update = name_to_update, id=id)
            except: 
                flash("Error! There was an error updating your information. Please try again!")
                session['user_authenticated'] = None
                session['delete_account_confirmed'] = None
                return render_template("settings.html", 
                        form=form,
                        name_to_update = name_to_update, id=id)
        else: 
            flash("Update User...")
            name_to_update = UserCredentials.query.get_or_404(id)
            print('form.errors: ', form.errors)
            print(f"Session username: {session.get('username')}")
            print(f"User ID: {id}")
            new_username = form.new_username.data
            form.new_username.data = ''
            new_email = form.new_email.data
            form.new_email.data = ''
            #new_phone = form.new_phone.data
            #form.new_phone.data = ''
            new_password = form.new_password.data
            form.new_password.data = ''
            session['delete_account_confirmed'] = None
            session['user_authenticated'] = None
            #Clearing the form data after it has been submitted
            return render_template("settings.html", form=form, name_to_update = name_to_update, id = id)
    else:
        return redirect(url_for('log_in'))

#======================= Settings_Edit =======================#
@app.route('/Homepage/Settings/Edit', methods=['POST', 'GET'])
@requires_confirmation(route='edit')
def settings_edit():
    # Initializes values to None 
    new_username = None
    new_email = None
    #new_phone = None
    new_password = None
    user_ID = None
    #salt = None
    id = None
    session['user_authenticated'] = None
    session['delete_account_confirmed'] = None
    # Specifies the form class to use
    if session.get('username'):
        # Query the user's information from the database
        user = UserCredentials.query.filter_by(user_Name=session['username']).first()
        # Check if the user is found in the database
        id = user.user_ID
        #salt = user.pass_salt
        name_to_update = UserCredentials.query.get_or_404(id)
        form = SettingForm()
        if form.validate_on_submit(): 
            # Check if the new username is empty or equals the current username
            if not form.new_username.data:
                flash("Error: New username cannot be empty")
            # Check if the new username is already taken
            elif form.new_username.data != user.user_Name and UserCredentials.query.filter_by(user_Name=form.new_username.data).first():
                flash("Error: New username is already taken.")
            # Check if the new email is empty or equals the current email
            elif not form.new_email.data:
                flash("Error: New email cannot be empty")
            # Check if the new email is already taken
            elif form.new_email.data != user.user_Email and UserCredentials.query.filter_by(user_Email=form.new_email.data).first():
                flash("Error: New email is already taken.")
            # Check if the new phone number is not empty and contains non-numeric characters
            #elif form.new_phone.data and (not form.new_phone.data.isdigit()):
                #flash("Error: New phone number cannot contain non-numeric characters.")
            # Check if the new phone number is not empty, is different from the current one, and is already taken
            #elif form.new_phone.data and form.new_phone.data != str(user.user_Phone) and UserCredentials.query.filter_by(user_Phone=form.new_phone.data).first():
                #flash("Error: New phone number is already taken.")

            else:
                # Update user information
                name_to_update.user_Name = form.new_username.data
                name_to_update.user_Email = form.new_email.data
                #name_to_update.user_Phone = form.new_phone.data
                if form.new_password.data:
                    name_to_update.pass_hash = generateHash(form.new_password.data) #, salt
                session['username'] = form.new_username.data

            try: 
                db.session.commit()
                flash("User Information Updated Successfully!")
                # Re-query the user after committing changes
                name_to_update = UserCredentials.query.get_or_404(id)
                print(f"Session username: {session.get('username')}")
                print(f"User ID: {id}")
                session['user_authenticated'] = None
                session['delete_account_confirmed'] = None
                return render_template("settings.html", 
                        form=form, 
                        name_to_update = name_to_update, 
                        id=id)
            except: 
                flash("Error! There was an error updating your information. Please try again!")
                session['user_authenticated'] = None
                session['delete_account_confirmed'] = None
                return render_template("settings.html", 
                        form=form,
                        name_to_update = name_to_update, 
                        id=id)
        else: 
            flash("Update User...")
            name_to_update = UserCredentials.query.get_or_404(id)
            print('form.errors: ', form.errors)
            print(f"Session username: {session.get('username')}")
            print(f"User ID: {id}")
            new_username = form.new_username.data
            form.new_username.data = ''
            new_email = form.new_email.data
            form.new_email.data = ''
            #new_phone = form.new_phone.data
            #form.new_phone.data = ''
            new_password = form.new_password.data
            form.new_password.data = ''
            session['user_authenticated'] = True
            session['delete_account_confirmed'] = None
            #Clearing the form data after it has been submitted
            return render_template("settings_edit.html", form=form, name_to_update = name_to_update, id = id)
    else: 
        return redirect(url_for('log_in'))

#======================= Settings_Confirm =======================#
@app.route('/Homepage/Settings/Confirm', methods=['POST', 'GET'])
def settings_confirm():
    # Initializes values to None 
    password = None
    username = None
    passHash = None
    #salt = None
    session['user_authenticated'] = None
    session['delete_account_confirmed'] = None
    form = Settings_ConfirmForm()
    # Specifies the form class to use
    if session.get('username'):
        if form.validate_on_submit(): 
            # Query the user's information from the database
            user = UserCredentials.query.filter_by(user_Name=form.username.data).first()
            # Check if the user is found in the database
            #salt = user.pass_salt
            if user: 
                try: 
                    if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice Try.")
                        return render_template("settings_confirm.html", 
                                form=form,
                                username = username, 
                                passHash = passHash) # salt = salt,          
                              
                    ph = PasswordHasher()
                    if ph.verify(user.pass_hash, form.password.data):
                        session['user_authenticated'] = True
                        session['delete_account_confirmed'] = None
                        session['username'] = user.user_Name
                        session['user_id'] = user.user_ID
                        return redirect(url_for('settings_edit'))
                except:
                    flash("Error: the information you entered does not match our records")
                    return render_template("settings_confirm.html", 
                            form=form, 
                            username = username, 
                            passHash = passHash) # salt = salt
            # If user not found
            else:
                if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice try.")
                else:
                    flash("Error: User does not exist the information you entered does not match our records.")
                return render_template("settings_confirm.html", 
                        form=form, 
                        username = username, 
                        passHash = passHash) # salt = salt
        else:
            #Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            password = form.password.data
            form.password.data = ''
            session['user_authenticated'] = None
            session['delete_account_confirmed'] = None
            return render_template("settings_confirm.html", 
                form=form,
                username = username, 
                passHash = passHash) # salt = salt,
    else: 
        return redirect(url_for('log_in'))

#======================= Settings_Delete =======================#
@app.route('/Homepage/Settings/Delete', methods=['GET', 'POST'])
@requires_confirmation(route='delete_account_confirm')
def settings_delete():
    userID = None
    if session.get('username'):
        # Check if the user is found in the database
        userID = session.get('user_id')

        form = SettingForm()
        try: 
            UserCredentials.query.filter_by(user_ID= userID).delete()
            #Preferences.query.filter_by(user_ID= userID).delete()
            #Data.query.filter_by(user_ID= userID).delete()
            db.session.commit()
            session.pop('username')
            session.pop('user_id')
            flash("User Deleted Successfully!!")
            return redirect(url_for('log_in'))
        except: 
            db.session.rollback()
            flash("Whoops! There was a problem deleting the user!")
            name_to_update = UserCredentials.query.get_or_404(id)
            print(f"Session username: {session.get('username')}")
            print(f"User ID: {userID}")
            return render_template('settings.html', 
                    form=form, 
                    name_to_update = name_to_update, id=userID)
    else:
        return redirect(url_for('log_in'))

#======================= Settings_Delete_Confirm =======================#
@app.route('/Homepage/Settings/Delete/Confirm', methods=['GET', 'POST'])
def settings_delete_confirm():
    # Initializes values to None 
    password = None
    username = None
    passHash = None
    #salt = None
    session['user_authenticated'] = None
    session['delete_account_confirmed'] = None
    form = Settings_ConfirmForm()
    # Specifies the form class to use
    if session.get('username'):
        if form.validate_on_submit(): 
            # Query the user's information from the database
            user = UserCredentials.query.filter_by(user_Name=form.username.data).first()
            # Check if the user is found in the database
            #salt = user.pass_salt
            if user: 
                try: 
                    if form.password.data.lower() == "'or 1 = 1": 
                        flash("Nice Try.")
                        return render_template("settings_confirm.html", 
                                form=form,
                                username = username, 
                                passHash = passHash) # salt = salt,       
                    ph = PasswordHasher()
                    if ph.verify(user.pass_hash, form.password.data): 
                        session['user_authenticated'] = True
                        session['delete_account_confirmed'] = True             
                        session['username'] = user.user_Name
                        session['user_id'] = user.user_ID
                        return redirect(url_for('settings_delete'))
                except:
                    flash("Error: the information you entered does not match our records")
                    return render_template("settings_delete_confirm.html", 
                            form=form, 
                            username = username, 
                            passHash = passHash) # salt = salt
            # If user not found
            else:
                if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice try.")
                else:
                    flash("Error: User does not exist the information you entered does not match our records.")
                return render_template("settings_delete_confirm.html", 
                        form=form, 
                        username = username, 
                        passHash = passHash) # salt = salt
        else:
            #Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            password = form.password.data
            form.password.data = ''
            session['user_authenticated'] = None
            session['delete_account_confirmed'] = None
            return render_template("settings_delete_confirm.html", 
                form=form,
                username = username, 
                passHash = passHash) #, salt = salt,
    else: 
        return redirect(url_for('log_in'))

#======================= Logout =======================#
@app.route('/logout')
def log_out():
    if session.get('username'):
        session.pop('username')
    return redirect(url_for('log_in'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)