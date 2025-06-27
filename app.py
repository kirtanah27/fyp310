import os
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.utils import secure_filename
from flask_pymongo import PyMongo
from datetime import datetime
import email
from email import policy
from Automation import download_and_scan_emails
import re
from ip2geotools.databases.noncommercial import DbIpCity
import math # Import the math library for pagination calculations
import imaplib # Import imaplib for credential verification

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/antiphish'
mongo = PyMongo(app)

VIRUSTOTAL_API_KEY = 'fe0a4468c5401bce38514fe6d6b5e7c1926f85edd7a524c9dc5212209554f6ed'
VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/api/v3/files'

# IMAP server details for credential verification
IMAP_SERVER = 'imap.gmail.com'
IMAP_PORT = 993

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    return render_template('index.html')

# New endpoint for credential verification
@app.route('/verify_credentials', methods=['POST'])
def verify_credentials():
    data = request.json
    email_address = data.get('email')
    app_password = data.get('app_password')

    if not email_address or not app_password:
        return jsonify({'success': False, 'message': 'Email and App Password are required.'}), 400

    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(email_address, app_password)
        mail.logout() # Logout immediately after successful login
        return jsonify({'success': True, 'message': 'Authentication successful.'})
    except imaplib.IMAP4.error as e:
        # Common IMAP errors for invalid credentials
        if "AUTHENTICATIONFAILED" in str(e).upper() or "WEBALERT" in str(e).upper():
            return jsonify({'success': False, 'message': 'Invalid Email or App Password. Please check your credentials.'}), 200
        return jsonify({'success': False, 'message': f'IMAP login error: {str(e)}'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during verification: {str(e)}'}), 500


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty file name'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    with open(filepath, 'rb') as f:
        files = {'file': (filename, f)}
        vt_response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, headers=headers)

    if vt_response.status_code != 200:
        return jsonify({
            'error': 'VirusTotal scan failed',
            'status_code': vt_response.status_code,
            'details': vt_response.text
        }), vt_response.status_code

    vt_result = vt_response.json()
    scan_id = vt_result['data']['id'] if 'data' in vt_result else None

    # Get user_email from form data if provided (for manual uploads)
    user_email_for_upload = request.form.get('user_email') # Now expecting user_email from FormData

    mongo.db.uploads.insert_one({
        'filename': filename,
        'upload_time': datetime.utcnow(),
        'scan_id': scan_id,
        'status': 'pending',
        'source': 'manual-upload',
        'user_email': user_email_for_upload # Store the user email for manual uploads
    })
    return jsonify({'message': 'File uploaded', 'scan_id': scan_id, 'filename': filename})

@app.route('/scan_email', methods=['POST'])
def scan_email():
    data = request.json
    email_address = data.get('email') # Get the email address
    password = data.get('password')
    start_date = data.get('start_date') or datetime.utcnow().strftime('%Y-%m-%d')
    if not email_address or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    try:
        # Pass the email_address to the download_and_scan_emails function
        results = download_and_scan_emails(email_address, password, start_date)
        return jsonify({'message': 'Scan complete', 'results': results, 'user_email': email_address}) # Return user_email
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/files')
def show_uploaded_files():
    user_email = request.args.get('user_email') # Get user_email from query parameter
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort', 'date_desc', type=str)
    PER_PAGE = 20
    sort_config = {'date_desc': [('upload_time', -1)], 'date_asc': [('upload_time', 1)]}
    current_sort = sort_config.get(sort_by, sort_config['date_desc'])

    query = {}
    if user_email:
        query['user_email'] = user_email # Filter by user_email if provided

    total_files = mongo.db.uploads.count_documents(query)
    files_cursor = mongo.db.uploads.find(query, {'_id': 0}).sort(current_sort).skip((page - 1) * PER_PAGE).limit(PER_PAGE)
    files = list(files_cursor)
    total_pages = math.ceil(total_files / PER_PAGE)
    return render_template('files.html', files=files, current_page=page, total_pages=total_pages, current_sort=sort_by, user_email=user_email)

# NEW STATUS CHECKING LOGIC
@app.route('/check_status/<path:filename>')
def check_status(filename):
    file_doc = mongo.db.uploads.find_one({'filename': filename})

    if not file_doc:
        return jsonify({'status': 'error', 'message': 'File not found in database'}), 404

    # If status is already final, return it directly from the database to save API calls
    if file_doc.get('status') in ['clean', 'malicious']:
        return jsonify({'status': file_doc['status']})

    scan_id = file_doc.get('scan_id')
    if not scan_id:
        return jsonify({'status': 'error', 'message': 'Scan ID missing for this file'}), 400

    # If status is pending, check VirusTotal for an update
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)

        # If the report is not ready yet, VirusTotal returns 404. We keep our status as 'pending'.
        if response.status_code == 404:
            return jsonify({'status': 'pending'})

        response.raise_for_status() # Raise exception for other errors (like 429 Quota Exceeded)
        report = response.json()

        # Check if the analysis from VirusTotal is actually completed
        if report.get('data', {}).get('attributes', {}).get('status') == 'completed':
            stats = report.get('data', {}).get('attributes', {}).get('stats', {})
            malicious_votes = stats.get('malicious', 0)

            new_status = 'malicious' if malicious_votes > 0 else 'clean'

            # Update the status in our database so we don't have to check again
            mongo.db.uploads.update_one(
                {'filename': filename},
                {'$set': {'status': new_status}}
            )
            return jsonify({'status': new_status})
        else:
            # Report exists but is not completed yet (e.g., it's 'queued')
            return jsonify({'status': 'pending'})

    except requests.exceptions.RequestException as e:
        # Handle API errors like Quota Exceeded or other network issues
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/report/<scan_id>')
def get_report(scan_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()
        return render_template('report.html', report=report)
    else:
        return f"Error fetching report: {response.status_code} - {response.text}", 500

# This is the new, dedicated GET route for your feedback.html page.
@app.route('/feedback_form')
def feedback_form():
    """Renders the feedback form page (feedback.html)."""
    return render_template('feedback.html')

# This is the route where the form from feedback.html POSTs its data.
@app.route('/submit_report', methods=['POST'])
def submit_report():
    if request.method == 'POST':
        name = request.form.get('name')
        email_address = request.form.get('email')
        subject = request.form.get('subject')
        description = request.form.get('description')

        # Basic validation
        if not name or not email_address or not subject or not description:
            return render_template('feedback.html', error_message="Please fill in all required fields."), 400

        try:
            # Save to MongoDB
            mongo.db.feedback.insert_one({
                'name': name,
                'email': email_address,
                'subject': subject,
                'description': description,
                'timestamp': datetime.utcnow()
            })
            # Return a simple success page after saving
            return render_template('feedback_success.html', name=name)
        except Exception as e:
            # Handle potential database errors
            print(f"Error saving feedback to MongoDB: {e}")
            return render_template('feedback.html', error_message=f"An error occurred: {str(e)}"), 500
    # If it's a GET request to /submit_report, redirect to the feedback form page (or index)
    return redirect(url_for('feedback_form'))

# NEW ROUTE: Privacy Policy Page
@app.route('/privacy')
def privacy():
    """Renders the privacy policy page."""
    return render_template('policy.html')


@app.route('/header/<filename>')
def view_email_header(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        with open(filepath, 'r', errors='ignore') as f:
            msg = email.message_from_file(f, policy=policy.default)
            header_info = {k: v for k, v in msg.items()}
            all_header_text = " ".join(str(v) for v in header_info.values())
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            found_ips = set(re.findall(ip_pattern, all_header_text))
            geolocation_data = {}
            for ip in found_ips:
                try:
                    response = DbIpCity.get(ip, api_key='free')
                    geolocation_data[ip] = {"city": response.city, "region": response.region, "country": response.country}
                except Exception:
                    geolocation_data[ip] = {"error": "IP not found or private"}
        return render_template('header.html', header_info=header_info, geolocation_data=geolocation_data)
    except Exception as e:
        return f"Error processing email header: {str(e)}", 500

@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    # This deletion does not filter by user_email. If you want to enforce
    # user-specific deletion, you would need to pass user_email here and
    # add it to the delete_one query.
    try:
        mongo.db.uploads.delete_one({'filename': filename})
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'success': True, 'message': f'{filename} deleted.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete-multiple', methods=['POST'])
def delete_multiple_files():
    # Similar to single delete, this does not filter by user_email.
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        for filename in filenames:
            mongo.db.uploads.delete_one({'filename': filename})
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                os.remove(filepath)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
