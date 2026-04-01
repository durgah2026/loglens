from flask import Flask, request, jsonify, render_template, redirect
import os
import re
import json
from collections import defaultdict
from werkzeug.utils import secure_filename

app = Flask(__name__)

# CONFIGURATION
UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'log'}
SUMMARY_PATH = os.path.join(UPLOAD_FOLDER, 'summary.json')
DEMO_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'demo.log')

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """Check if the file extension is .log"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_log_file(filepath):
    """
    Parse a log file and return parsed entries + aggregated summary.
    Reused by both /upload and /demo routes.
    """
    parsed_entries = []
    failed_logins = {}
    log_pattern = r'(\d+\.\d+\.\d+\.\d+).+\[(.*?)\]\s+"(GET|POST)\s(.*?)\sHTTP.*"\s(\d+)'

    attack_type_counts = defaultdict(int)
    ip_counts = defaultdict(int)

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
                # Directory Traversal
                elif "../" in path_lower or "..\\" in path_lower:
                    attack = "Directory Traversal"
                # Brute Force
                elif status == "401":
                    failed_logins[ip] = failed_logins.get(ip, 0) + 1
                    if failed_logins[ip] > 3:
                        attack = "Brute Force"

                # Aggregate data
                if attack != "None":
                    attack_type_counts[attack] += 1
                ip_counts[ip] += 1

                entry = {
                    "ip": ip,
                    "time": time_str,
                    "method": method,
                    "path": path,
                    "status": status,
                    "attack": attack
                }
                parsed_entries.append(entry)

    # Build summary object (top 10 attack types, top 20 IPs)
    top_attack_types = dict(
        sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    )
    top_ips = [
        {"ip": ip, "count": count}
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    summary = {
        "total_parsed": len(parsed_entries),
        "attack_type_counts": top_attack_types,
        "top_offensive_ips": top_ips
    }

    # Save summary.json for chart consumption
    with open(SUMMARY_PATH, 'w') as sf:
        json.dump({"summary": summary}, sf, indent=2)

    return parsed_entries, summary


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

        try:
            parsed_entries, summary = parse_log_file(filepath)

            return render_template(
                'results.html',
                message="File uploaded and parsed successfully",
                parsed_count=len(parsed_entries),
                data=parsed_entries[:50],
                summary=summary
            ), 201

        except Exception as e:
            return render_template('results.html', error=f"Failed to parse file: {str(e)}"), 500
    else:
        return render_template('results.html', error="Invalid file type. Only .log files are allowed"), 400


@app.route('/demo')
def demo():
    """Load the built-in demo.log and render the results dashboard."""
    if not os.path.exists(DEMO_LOG_PATH):
        return render_template('results.html', error="Demo log file not found. Please ensure demo.log exists."), 404

    try:
        parsed_entries, summary = parse_log_file(DEMO_LOG_PATH)

        return render_template(
            'results.html',
            message="Demo log analyzed successfully — this is sample data for demonstration",
            parsed_count=len(parsed_entries),
            data=parsed_entries[:50],
            summary=summary
        )

    except Exception as e:
        return render_template('results.html', error=f"Failed to parse demo file: {str(e)}"), 500


@app.route('/api/summary')
def get_summary():
    """Serve the latest summary.json for chart consumption."""
    if not os.path.exists(SUMMARY_PATH):
        return jsonify({"error": "No summary available. Upload a log file first."}), 404
    with open(SUMMARY_PATH, 'r') as f:
        data = json.load(f)
    return jsonify(data)

@app.route("/")
def home():
    return render_template("upload.html")

if __name__ == '__main__':
    # Run server on http://127.0.0.1:5001/
    app.run(host='127.0.0.1', port=5001, debug=True)
