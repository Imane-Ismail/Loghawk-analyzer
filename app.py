import os
import subprocess
import sys
import uuid
from flask import Flask, request, render_template_string
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'json', 'csv'}

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# HTML template for rendering the upload form and output
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LogHawkX Analyzer</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <header class="hero">
        <h1>🦅 LogHawkX</h1>
        <p>Upload a log file for analysis</p>
    </header>
    <section>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="logfile" required>
            <button type="submit">Analyze</button>
        </form>
    </section>
    {% if output %}
    <section>
        <h2>Analysis Output</h2>
        <pre>{{ output | safe }}</pre>
    </section>
    {% endif %}
</body>
</html>
'''

# Check file extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    output = ''
    if request.method == 'POST':
        if 'logfile' not in request.files:
            output = "⚠️ No file part in request."
        else:
            file = request.files['logfile']
            if file.filename == '':
                output = "⚠️ No file selected."
            elif allowed_file(file.filename):
                # Sanitize and save with unique filename
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
                file.save(filepath)

                # Call the LogHawk CLI with --input argument
                try:
                    result = subprocess.run(
                        [sys.executable, '-m', 'loghawk.loghawk_cli', '--input', filepath],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=True
                    )
                    output = result.stdout
                except subprocess.CalledProcessError as e:
                    output = f"""
❌ Error running LogHawk:
Exit Code: {e.returncode}
STDOUT:
{e.stdout}

STDERR:
{e.stderr}
                    """
            else:
                output = "⚠️ Invalid file type. Allowed: .log, .txt, .json, .csv"
    return render_template_string(HTML_TEMPLATE, output=output)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
