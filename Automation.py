def download_and_scan_emails(email_address, app_password, start_date_str):
    import imaplib
    import email
    import os
    import datetime
    import re
    import requests
    from pymongo import MongoClient
    import time # Import the time library for adding a delay

    VIRUSTOTAL_API_KEY = 'fe0a4468c5401bce38514fe6d6b5e7c1926f85edd7a524c9dc5212209554f6ed'
    VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/api/v3/files'
    IMAP_SERVER = 'imap.gmail.com'
    IMAP_PORT = 993
    OUTPUT_DIR = 'uploads'  


    def sanitize_filename(filename):
        sanitized = re.sub(r'[^\w\-.]', '_', filename)
        sanitized = re.sub(r'_+', '_', sanitized)
        sanitized = sanitized.strip('_.')
        if not sanitized:
            return "untitled_email"
        name, ext = os.path.splitext(sanitized)
        if len(sanitized) > 200:
            sanitized = name[:200 - len(ext)] + ext
        return sanitized

    def upload_to_virustotal(filepath, filename):
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (filename, f)}
                vt_response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, headers=headers)

            if vt_response.status_code == 200:
                vt_result = vt_response.json()
                scan_id = vt_result.get('data', {}).get('id')
                return scan_id
            else:
                print(f"VirusTotal upload error for {filename}: {vt_response.status_code} - {vt_response.text}")
                return None
        except Exception as e:
            print(f"Exception during VirusTotal upload for {filename}: {e}")
            return None

    start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d').date()
    imap_date_format = start_date.strftime('%d-%b-%Y')
    search_criteria = f'(SINCE "{imap_date_format}")'

    client = MongoClient("mongodb://localhost:27017/")
    db = client["antiphish"]
    uploads = db["uploads"]

    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(email_address, app_password)
    mail.select("INBOX")

    status, search_data = mail.search(None, search_criteria)
    message_ids = search_data[0].split()

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    scan_results = []

    for msg_id in message_ids:
        status, msg_data = mail.fetch(msg_id, '(RFC822)')
        if status != 'OK':
            continue

        for part in msg_data:
            if isinstance(part, tuple):
                raw_bytes = part[1]
                msg = email.message_from_bytes(raw_bytes)
                subject = msg.get("Subject", "No Subject")
                decoded = email.header.decode_header(subject)
                subject_text = ''.join([
                    seg.decode(enc or 'utf-8', 'ignore') if isinstance(seg, bytes) else str(seg) for seg, enc in decoded
                ])
                clean_subject = sanitize_filename(subject_text)
                filename = f"{msg_id.decode()}_{clean_subject}.eml"
                filepath = os.path.join(OUTPUT_DIR, filename)
                with open(filepath, 'wb') as f:
                    f.write(raw_bytes)

                scan_id = upload_to_virustotal(filepath, filename)

                # MODIFICATION: Add the 'user_email' field
                uploads.insert_one({
                    'filename': filename,
                    'upload_time': datetime.datetime.utcnow(),
                    'scan_id': scan_id,
                    'source': 'gmail-auto',
                    'status': 'pending',
                    'user_email': email_address # Add this line to store the associated email
                })
                # END: MODIFICATION

                scan_results.append({
                    'filename': filename,
                    'scan_id': scan_id
                })
                
                # START: MODIFICATION - Add a delay to respect API limits
                # VirusTotal's public API allows ~4 requests per minute. 15 seconds is safe.
                time.sleep(15) 
                # END: MODIFICATION

                break

    mail.logout()
    return scan_results
