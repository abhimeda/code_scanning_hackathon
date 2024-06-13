import json

from flask import Flask, render_template

app = Flask(__name__)


@app.route('/')
def index():
    # get data 
    file_path = 'output.json'

    # Open the file and load the data
    posts = []
    with open(file_path, 'r') as file:
        posts = json.load(file)
    return render_template('index.html', posts=posts)
