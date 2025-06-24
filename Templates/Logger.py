import email
import re
from email import policy
from email.parser import BytesParser

# Function to parse the .eml file
def parse_eml(file_path):
    # Open the EML file
    with open(file_path, 'rb') as f:
        # Parse the EML content
        msg = BytesParser(policy=policy.default).parse(f)
        
        # Extract email details
        email_details = {
            'From': msg['From'],
            'To': msg['To'],
            'Subject': msg['Subject'],
            'Date': msg['Date'],
            'Body': get_email_body(msg),
            'Attachments': get_attachments(msg),
            'Sender IP': get_sender_ip(msg)  # Get the sender's IP address
        }
        
        return email_details

# Function to extract the email body
def get_email_body(msg):
    # Check if the email is multipart (e.g., HTML and plain text)
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode(part.get_content_charset())
    else:
        return msg.get_payload(decode=True).decode(msg.get_content_charset())

# Function to extract attachments from the email
def get_attachments(msg):
    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            attachment = {
                'filename': filename,
                'content': part.get_payload(decode=True)
            }
            attachments.append(attachment)
    return attachments

# Function to extract the sender's IP address from the 'Received' headers
def get_sender_ip(msg):
    # Get all the 'Received' headers from the email
    received_headers = msg.get_all('Received', [])
    
    # Regex pattern to find an IP address in the 'Received' header
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'

    # Check each 'Received' header for an IP address
    for header in received_headers:
        match = re.search(ip_pattern, header)
        if match:
            return match.group(1)  # Return the first matching IP address
    
    return None  # Return None if no IP address was found

# Example usage
file_path = 'path_to_your_file.eml'  # Path to the .eml file you want to parse
email_data = parse_eml(file_path)

print(email_data)
