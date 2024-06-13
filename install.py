import subprocess

#1) Download the zip file(https://mkmartifactory.amd.com:443/artifactory/SW-SITARTIFACTS-PROD-LOCAL/prototyping/database-5a7786812dd4-2024-01-11.zip) and extract in root directoy and rename to database
subprocess.run(["curl", "-o", "database.zip", "https://mkmartifactory.amd.com:443/artifactory/SW-SITARTIFACTS-PROD-LOCAL/prototyping/database-5a7786812dd4-2024-01-11.zip"])
subprocess.run(["unzip", "database.zip"])
subprocess.run(["mv", "database-5a7786812dd4-2024-01-11", "database"])

#2) Clone the Tensorflow repository in root directory
subprocess.run(["git", "clone", "https://github.com/tensorflow/tensorflow.git"])

#3) Install pip requirements
subprocess.run(["pip", "install", "-r", "requirements.txt"])

#4) Run python new_analyzer.py
subprocess.run(["python", "new_analyzer.py"])