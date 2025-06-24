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

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/antiphish'
mongo = PyMongo(app)

# VirusTotal API Key
VIRUSTOTAL_API_KEY = '5ed75f28373e3b0e4b2abc9f854a6d8e71aa6e59b337472781818a9363b5d5b7'
VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/api/v3/files'

# Create uploads folder if not exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    return render_template('index.html')

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

    # Send to VirusTotal
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    with open(filepath, 'rb') as f:
        files = {'file': (filename, f)}
        vt_response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, headers=headers)

    if vt_response.status_code != 200:
        print("VirusTotal upload error:", vt_response.status_code, vt_response.text)
        return jsonify({
            'error': 'VirusTotal scan failed',
            'status_code': vt_response.status_code,
            'details': vt_response.text
        }), vt_response.status_code

    vt_result = vt_response.json()
    scan_id = vt_result['data']['id'] if 'data' in vt_result else None
    

    mongo.db.uploads.insert_one({
        'filename': filename,
        'upload_time': datetime.utcnow(),
        'scan_id': scan_id
    })

    return jsonify({'message': 'File uploaded', 'scan_id': scan_id, 'filename': filename})

@app.route('/scan_email', methods=['POST'])
def scan_email():
    data = request.json
    email_address = data.get('email')
    password = data.get('password')
    start_date = data.get('start_date') or datetime.utcnow().strftime('%Y-%m-%d')

    if not email_address or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    try:
        results = download_and_scan_emails(email_address, password, start_date)
        return jsonify({'message': 'Scan complete', 'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/files')
def show_uploaded_files():
    files = list(mongo.db.uploads.find({}, {'_id': 0}))
    return render_template('files.html', files=files)

@app.route('/report')
def report():
    return render_template('feedback.html')

@app.route('/privacy')
def privacy():
    """Renders the privacy policy page."""
    return render_template('policy.html')

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
            # Return a simple success page or message
            return render_template('feedback_success.html', name=name) # We'll create this HTML
        except Exception as e:
            # Handle potential database errors
            return render_template('feedback.html', error_message=f"An error occurred: {str(e)}"), 500
    # If it's not a POST request, redirect back to the report form
    return redirect(url_for('index'))

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

@app.route('/header/<filename>')
def view_email_header(filename):
    # Open and parse the .eml file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        with open(filepath, 'r', errors='ignore') as f:
            msg = email.message_from_file(f, policy=policy.default)
            headers = msg.items()  
            header_info = {k: v for k, v in headers}  
    
            all_header_text = " ".join(str(v) for v in header_info.values())
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            found_ips = set(re.findall(ip_pattern, all_header_text))
            
            geolocation_data = {}
            for ip in found_ips:
                try:
                    response = DbIpCity.get(ip, api_key='free')
                    geolocation_data[ip] = {
                        "city": response.city,
                        "region": response.region,
                        "country": response.country
                    }
                except Exception:
                    geolocation_data[ip] = {"error": "IP not found or private"}

        return render_template('header.html', header_info=header_info, geolocation_data=geolocation_data)
    
    except Exception as e:
        return f"Error processing email header: {str(e)}", 500
    
@app.route('/check_status/<scan_id>')
def check_status(scan_id):
    """
    Checks the VirusTotal analysis report for a given scan_id
    and returns whether it's flagged as malicious.
    """
    # If no valid scan_id is provided, return an unknown status.
    if not scan_id or scan_id == 'None':
        return jsonify({'status': 'unknown', 'reason': 'No Scan ID provided'}), 400

    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        report = response.json()
        
        # The 'stats' dictionary contains the counts of engine results.
        stats = report.get('data', {}).get('attributes', {}).get('stats', {})
        
        # We consider it malicious if one or more engines flag it.
        malicious_votes = stats.get('malicious', 0)
        
        if malicious_votes > 0:
            return jsonify({'status': 'malicious'})
        else:
            return jsonify({'status': 'clean'})

    except requests.exceptions.HTTPError as http_err:
        # Handle cases where the report is not found or another API error occurs.
        if response.status_code == 404:
            return jsonify({'status': 'not_found', 'message': 'Report not found or not yet generated.'}), 404
        return jsonify({'status': 'error', 'message': f'HTTP error occurred: {http_err}'}), response.status_code
    except Exception as e:
        # Handle other potential errors, like network issues or JSON parsing problems.
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/delete-multiple', methods=['POST'])
def delete_multiple_files():
    try:
        data = request.get_json()
        filenames = data.get('files', [])

        deleted_files = []
        for filename in filenames:
            mongo.db.uploads.delete_one({'filename': filename})

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                deleted_files.append(filename)

        return jsonify({'success': True, 'deleted': deleted_files})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
