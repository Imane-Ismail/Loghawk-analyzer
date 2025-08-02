from flask import Flask, request, render_template, redirect
import os
from werkzeug.utils import secure_filename
import subprocess

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return 'No file part'

        file = request.files['logfile']
        if file.filename == '':
            return 'No selected file'

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            try:
                result = subprocess.check_output(['python3', 'loghawk/loghawk.py', filepath], text=True)
            except subprocess.CalledProcessError as e:
                result = f"Error running LogHawk: {e}"

            return render_template('index.html', output=result)

        else:
            return 'Invalid file type. Only .log and .txt files are allowed.'

    return render_template('index.html')

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
