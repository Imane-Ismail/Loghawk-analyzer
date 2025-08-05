import os
import subprocess
import sys
import uuid
from flask import Flask, request, render_template_string, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'json', 'csv'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LogHawkX Analyzer</title>
    <link rel="stylesheet" href="/static/style.css">
    <script>
    function toggleDarkMode() {
        document.body.classList.toggle('dark-mode');
    }
    </script>
</head>
<body>
<header class="hero">
    <h1>🦅 LogHawkX</h1>
    <button onclick="toggleDarkMode()">🌓 Toggle Dark Mode</button>
    <p><strong>About LogHawkX:</strong> A lightweight threat detection tool scanning uploaded log files for signs of attack (e.g., brute-force, PowerShell misuse, or web exploits).</p>
    <p><strong>Supported file types:</strong> .log, .txt, .json, .csv<br>
       <strong>Max size:</strong> 5 MB</p>
</header>

<section>
    <form method="post" enctype="multipart/form-data">
        <label>Select log file:</label>
        <input type="file" name="logfile" accept=".log,.txt,.json,.csv">
        <br><br>
        <label>Or paste logs directly:</label><br>
        <textarea name="logtext" rows="10" cols="70" placeholder="Paste logs here..."></textarea><br>
        <button type="submit">Analyze</button>
    </form>
</section>

{% if output %}
<section>
    <h2>📄 Analysis Summary</h2>
    <pre>{{ output }}</pre>
    <form method="post" action="/download">
        <input type="hidden" name="report" value="{{ output }}">
        <button type="submit">📥 Download Report</button>
    </form>
</section>
{% endif %}
</body>
</html>
'''

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    output = ''
    if request.method == 'POST':
        uploaded_file = request.files.get('logfile')
        pasted_text = request.form.get('logtext')

        if uploaded_file and allowed_file(uploaded_file.filename):
            if uploaded_file.content_length and uploaded_file.content_length > MAX_FILE_SIZE:
                output = "❌ File too large. Max size is 5 MB."
            else:
                filename = secure_filename(uploaded_file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
                uploaded_file.save(filepath)

                result = run_loghawk(filepath)
                output = result or "[-] No suspicious events detected."

        elif pasted_text:
            # Save pasted logs as temp file
            filename = f"{uuid.uuid4().hex}_pasted.log"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            with open(filepath, 'w') as f:
                f.write(pasted_text)

            result = run_loghawk(filepath)
            output = result or "[-] No suspicious events detected."

        else:
            output = "⚠️ Please upload a file or paste logs."

    return render_template_string(HTML_TEMPLATE, output=output)

def run_loghawk(filepath):
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'loghawk.loghawk_cli', '--input', filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"""
❌ Error running LogHawk:
Exit Code: {e.returncode}
STDOUT:
{e.stdout}

STDERR:
{e.stderr}
        """

@app.route('/download', methods=['POST'])
def download_report():
    report_content = request.form.get('report', '')
    report_path = os.path.join(UPLOAD_FOLDER, 'loghawk_report.txt')
    with open(report_path, 'w') as f:
        f.write(report_content)
    return send_file(report_path, as_attachment=True)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
