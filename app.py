from flask import Flask, request, jsonify, render_template
import os
import re
from werkzeug.utils import secure_filename

app = Flask(__name__)

# CONFIGURATION
UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'log'}

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """Check if the file extension is .log"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    # 1. Check if the post request has the file part
    if 'logfile' not in request.files:
        return render_template('results.html', error="No file part in the request (use key 'logfile')"), 400
    
    file = request.files['logfile']

    # 2. If the user does not select a file, the browser submits an
    # empty file without a filename.
    if file.filename == '':
        return render_template('results.html', error="No file selected for uploading"), 400

    # 3. Handle the file upload
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # 4. Parse the log file
        parsed_entries = []
        failed_logins = {}
        # Regex pattern updated to capture unencoded spaces in path
        log_pattern = r'(\d+\.\d+\.\d+\.\d+).+\[(.*?)\]\s+"(GET|POST)\s(.*?)\sHTTP.*"\s(\d+)'
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    match = re.search(log_pattern, line)
                    if match:
                        ip = match.group(1)
                        time_str = match.group(2)
                        method = match.group(3)
                        path = match.group(4)
                        status = match.group(5)
                        
                        attack = "None"
                        path_lower = path.lower()

                        # SQL Injection
                        if "or 1=1" in path_lower or "union" in path_lower:
                            attack = "SQL Injection"
                        # XSS
                        elif "<script>" in path_lower or "javascript:" in path_lower:
                            attack = "XSS"
                        # Brute Force
                        elif status == "401":
                            failed_logins[ip] = failed_logins.get(ip, 0) + 1
                            if failed_logins[ip] > 3:
                                attack = "Brute Force"

                        entry = {
                            "ip": ip,
                            "time": time_str,
                            "method": method,
                            "path": path,
                            "status": status,
                            "attack": attack
                        }
                        parsed_entries.append(entry)
            
            return render_template(
                'results.html',
                message="File uploaded and parsed successfully",
                parsed_count=len(parsed_entries),
                data=parsed_entries[:50]
            ), 201
            
        except Exception as e:
            return render_template('results.html', error=f"Failed to parse file: {str(e)}"), 500
    else:
        return render_template('results.html', error="Invalid file type. Only .log files are allowed"), 400

@app.route('/')
def index():
    return "LogLens API is running. Use the local upload.html file to upload log files."

if __name__ == '__main__':
    # Run server on http://127.0.0.1:5001/
    app.run(host='127.0.0.1', port=5001, debug=True)
