from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import google.generativeai as genai
import socket
import re
import os
import base64
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

api_key = os.environ.get("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

def ask_ai(prompt, image_data=None, image_type=None):
    if not api_key:
        return "ERROR: GEMINI_API_KEY not set in environment variables"
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        if image_data:
            image_bytes = base64.b64decode(image_data)
            image_part = {"mime_type": image_type, "data": image_bytes}
            response = model.generate_content([prompt, image_part])
        else:
            response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"AI Error: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

@app.route('/api/phishing', methods=['POST'])
def check_phishing():
    try:
        data = request.get_json(force=True)
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        suspicious_patterns = []
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            suspicious_patterns.append("Uses IP address instead of domain")
        if url.count('.') > 4:
            suspicious_patterns.append("Too many subdomains")
        if any(w in url.lower() for w in ['login','verify','secure','account','update','confirm']):
            suspicious_patterns.append("Contains suspicious keywords")
        if len(url) > 100:
            suspicious_patterns.append("Unusually long URL")
        if '@' in url:
            suspicious_patterns.append("Contains @ symbol")

        prompt = f"""You are a cybersecurity expert. Analyze this URL for phishing:
URL: {url}
Pre-detected patterns: {', '.join(suspicious_patterns) if suspicious_patterns else 'None'}

Respond in this exact format:
VERDICT: [SAFE / SUSPICIOUS / DANGEROUS]
RISK_SCORE: [0-100]
REASONS: [bullet points]
ADVICE: [one sentence]"""

        result = ask_ai(prompt)
        verdict_match = re.search(r'VERDICT:\s*(\w+)', result)
        score_match = re.search(r'RISK_SCORE:\s*(\d+)', result)
        reasons_match = re.search(r'REASONS:\s*(.*?)(?=ADVICE:|$)', result, re.DOTALL)
        advice_match = re.search(r'ADVICE:\s*(.*)', result)

        return jsonify({
            'verdict': verdict_match.group(1) if verdict_match else 'UNKNOWN',
            'risk_score': int(score_match.group(1)) if score_match else 50,
            'reasons': reasons_match.group(1).strip() if reasons_match else result,
            'advice': advice_match.group(1).strip() if advice_match else '',
            'patterns': suspicious_patterns
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/password', methods=['POST'])
def check_password():
    try:
        data = request.get_json(force=True)
        password = data.get('password', '')
        if not password:
            return jsonify({'error': 'No password provided'}), 400

        checks = {
            'length': len(password) >= 12,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'numbers': bool(re.search(r'\d', password)),
            'symbols': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'no_common': password.lower() not in ['password','123456','qwerty','admin','letmein']
        }
        score = sum(checks.values()) * 16

        prompt = f"""You are a cybersecurity expert. Analyze password strength:
Length: {len(password)}, Uppercase: {checks['uppercase']}, Lowercase: {checks['lowercase']},
Numbers: {checks['numbers']}, Symbols: {checks['symbols']}, Score: {score}/100

Respond in this exact format:
STRENGTH: [WEAK / FAIR / STRONG / VERY STRONG]
TIPS: [3 improvement tips as bullet points]
EXAMPLE: [one stronger password pattern example]"""

        result = ask_ai(prompt)
        strength_match = re.search(r'STRENGTH:\s*(\w[\w\s]*)', result)
        tips_match = re.search(r'TIPS:\s*(.*?)(?=EXAMPLE:|$)', result, re.DOTALL)
        example_match = re.search(r'EXAMPLE:\s*(.*)', result)

        return jsonify({
            'score': score,
            'strength': strength_match.group(1).strip() if strength_match else 'UNKNOWN',
            'checks': checks,
            'tips': tips_match.group(1).strip() if tips_match else '',
            'example': example_match.group(1).strip() if example_match else ''
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/portscan', methods=['POST'])
def port_scan():
    try:
        data = request.get_json(force=True)
        host = data.get('host', '')
        if not host:
            return jsonify({'error': 'No host provided'}), 400

        common_ports = {
            21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP',
            53:'DNS', 80:'HTTP', 110:'POP3', 143:'IMAP',
            443:'HTTPS', 445:'SMB', 3306:'MySQL', 3389:'RDP',
            5432:'PostgreSQL', 6379:'Redis', 8080:'HTTP-Alt', 27017:'MongoDB'
        }

        open_ports = []
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append({'port': port, 'service': service})
                sock.close()
            except:
                pass

        prompt = f"""You are a cybersecurity expert. Analyze open ports on {host}:
Open ports: {[f"{p['port']}/{p['service']}" for p in open_ports]}

Respond:
RISK_LEVEL: [LOW / MEDIUM / HIGH / CRITICAL]
ANALYSIS: [2-3 sentences]
DANGEROUS_PORTS: [list dangerous ones]
RECOMMENDATION: [what to do]"""

        result = ask_ai(prompt)
        return jsonify({
            'host': host,
            'open_ports': open_ports,
            'total_scanned': len(common_ports),
            'analysis': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/anomaly', methods=['POST'])
def detect_anomaly():
    try:
        data = request.get_json(force=True)
        log_data = data.get('log_data', '')
        if not log_data:
            return jsonify({'error': 'No log data provided'}), 400

        prompt = f"""You are a cybersecurity analyst. Analyze this log data for threats:

{log_data}

Respond:
THREAT_LEVEL: [NONE / LOW / MEDIUM / HIGH / CRITICAL]
ANOMALIES_FOUND: [number]
FINDINGS: [bullet points]
ATTACK_TYPE: [type or None detected]
RECOMMENDATION: [action to take]"""

        result = ask_ai(prompt)
        threat_match = re.search(r'THREAT_LEVEL:\s*(\w+)', result)
        anomalies_match = re.search(r'ANOMALIES_FOUND:\s*(\d+)', result)

        return jsonify({
            'threat_level': threat_match.group(1) if threat_match else 'UNKNOWN',
            'anomalies_count': int(anomalies_match.group(1)) if anomalies_match else 0,
            'full_analysis': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/filescan', methods=['POST'])
def scan_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        filename = secure_filename(file.filename)
        extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
        file_content = file.read(4096)

        dangerous_strings = [b'eval(', b'exec(', b'shell_exec', b'system(',
                             b'<script', b'powershell', b'cmd.exe', b'/etc/passwd', b'rm -rf']
        found_suspicious = [d.decode('utf-8', errors='ignore') for d in dangerous_strings if d in file_content]

        prompt = f"""You are a malware analyst. Analyze this file:
Filename: {filename}, Extension: {extension}
Dangerous extension: {extension in ['exe','bat','sh','vbs','ps1','cmd']}
Suspicious strings: {found_suspicious if found_suspicious else 'None'}

Respond:
VERDICT: [CLEAN / SUSPICIOUS / MALICIOUS]
RISK_SCORE: [0-100]
FINDINGS: [bullet points]
EXPLANATION: [2 sentences]"""

        result = ask_ai(prompt)
        verdict_match = re.search(r'VERDICT:\s*(\w+)', result)
        score_match = re.search(r'RISK_SCORE:\s*(\d+)', result)

        return jsonify({
            'filename': filename,
            'extension': extension,
            'verdict': verdict_match.group(1) if verdict_match else 'UNKNOWN',
            'risk_score': int(score_match.group(1)) if score_match else 0,
            'suspicious_strings': found_suspicious,
            'full_analysis': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/messagescan', methods=['POST'])
def scan_message():
    try:
        message_text = request.form.get('message', '')
        image_file = request.files.get('screenshot')

        if not message_text and not image_file:
            return jsonify({'error': 'No message or screenshot provided'}), 400

        if image_file:
            img_data = base64.standard_b64encode(image_file.read()).decode('utf-8')
            img_type = image_file.content_type or 'image/jpeg'
            prompt = """Analyze this screenshot for scams/phishing. Look for urgency, personal info requests, suspicious links, prizes, threats.
Respond:
VERDICT: [SAFE / SUSPICIOUS / SCAM]
CONFIDENCE: [0-100]
RED_FLAGS: [bullet points]
EXPLANATION: [2 sentences]
ADVICE: [what to do]"""
            result = ask_ai(prompt, img_data, img_type)
        else:
            prompt = f"""Analyze this message for scams/phishing:
Message: {message_text}

Respond:
VERDICT: [SAFE / SUSPICIOUS / SCAM]
CONFIDENCE: [0-100]
RED_FLAGS: [bullet points]
EXPLANATION: [2 sentences]
ADVICE: [what to do]"""
            result = ask_ai(prompt)

        verdict_match = re.search(r'VERDICT:\s*(\w+)', result)
        confidence_match = re.search(r'CONFIDENCE:\s*(\d+)', result)

        return jsonify({
            'verdict': verdict_match.group(1) if verdict_match else 'UNKNOWN',
            'confidence': int(confidence_match.group(1)) if confidence_match else 50,
            'full_analysis': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
