import json
import subprocess

def analyze_codeql_db(database_name: str) -> None:
    """Runs the CodeQL analyzer on behalf of the user and retrieves the outputted
    sarif file.
    :param name:
    :return:
    """
    # Run the CodeQL command to analyze the repository
    result = subprocess.run(["codeql", "database", "analyze", database_name, "--format=sarif-latest", "--output=results.sarif"], capture_output=True, text=True)
    if result.returncode == 0:
        print("CodeQL analysis completed successfully.")
    else:
        print("CodeQL analysis failed. Error message:")
        print(result.stderr)

#  Written by Copilot
def parse_sarif_file() -> None:
    """Parses the SARIF file and extracts the vulnerabilities contained in the results array.
    :return:
    """
    with open("results.sarif") as f:
        sarif_data = json.load(f)
    
    data = sarif_data["runs"][0]
    results = data["results"]

    # Check if results exist and is not empty
    if results:
        with open("output.json", "w") as f:
            json.dump(results, f, indent=4)
    else:
        print("No vulnerabilities found in SARIF file.")

def analyze_json_results():
    ls_locations = []
    with open("output.json") as f:
        results = json.load(f)
    for result in results:
        # Access dictionary elements
        vulnerability = result["message"]["text"]
        locations = result["locations"]
        for location in locations:
            # Access location details
            file_path = location["physicalLocation"]["artifactLocation"]["uri"]
            line = location["physicalLocation"]["region"]["startLine"]
            ls_locations.append({"file_path": file_path, "line": line, "message": vulnerability})
            return ls_locations
           

def get_code_at_line(file_path: str, line_number: int) -> str:
    """Reads the file and retrieves the code at a specific line number.
    :param file_path: The path to the file.
    :param line_number: The line number.
    :return: The code at the specified line.
    """
    with open(file_path) as f:
        lines = f.readlines()
        if line_number <= len(lines):
            code = lines[line_number - 1].strip()
            return code
        else:
            print("Line number exceeds the total number of lines in the file.")
    
    return ""
def search_git_history(keyword: str) -> str:
    """Searches the git history for a specific keyword using the 'git log -S' command.
    :param keyword: The keyword to search for.
    :return: The output of the git log command.
    """
    result = subprocess.run(["git", "log", "-S", keyword], capture_output=True, text=True)
    if result.returncode == 0:
         # Extract the sha, author, and time from the git log output
        git_log_output = result.stdout
        lines = git_log_output.split("\n")
        for line in lines:
            if line.startswith("commit"):
                sha = line.split()[1]
            elif line.startswith("Author"):
                author = line.split(":")[1].split(" <")[0].strip()
                email = line.split("<")[1].split(">")[0].strip()
            elif line.startswith("Date"):
                date = line.split(":")[1].strip()
        return {"sha": sha, "author": author, "email":email, "date": date}
    
    else:
        print("Failed to search git history. Error message:")
        print(result.stderr)
        return ""

   
if __name__ == "__main__":

    authors = []
    analyze_codeql_db("database")
    parse_sarif_file()
    vulnerable_locations = analyze_json_results()
    for location in vulnerable_locations:
        code_snippet = get_code_at_line(location["file_path"], location["line"])
        author = search_git_history(code_snippet)
        author["file_path"] = location["file_path"]
        author["line"] = location["line"]
        author["message"] = location["message"]
        authors.append(author)
    with open("authors.json", "w") as f:
        json.dump(authors, f, indent=4)

