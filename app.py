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

@app.route('/create_issue', methods=['POST'])  
def create_issue():  
    json_payload_from_site = request.get_json()  
    issue_url = create_issue_on_github(json_payload_from_site)  
    return jsonify({'issue_url': issue_url}) 