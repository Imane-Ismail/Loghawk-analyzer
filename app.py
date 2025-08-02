import os
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'json', 'csv'}

# Ensure uploads folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# HTML template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>LogHawkX Analyzer</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <header class="hero">
        <h1>LogHawkX</h1>
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
        <pre>{{ output }}</pre>
    </section>
    {% endif %}
</body>
</html>
'''

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
                filepath = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(filepath)

                # Run LogHawk CLI on uploaded file
                try:
                    result = subprocess.run(
                        ['python3', 'loghawk/loghawk_cli.py', filepath],
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
