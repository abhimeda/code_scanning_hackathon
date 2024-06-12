from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    # TEMPORARY DATA
    
    posts = [
        {"author": "Author1", "date": "2023-04-01", "lines": "123 456 789", "suggestions": "Improve readability"},
        {"author": "Author2", "date": "2023-04-02", "lines": "234 567 890", "suggestions": "Optimize performance"},
        {"author": "Author3", "date": "2023-04-03", "lines": "345 678 901", "suggestions": "Refactor for clarity"},
        {"author": "Author4", "date": "2023-04-04", "lines": "456 789 012", "suggestions": "Update documentation"}
    ]
    return render_template('index.html', posts=posts)
