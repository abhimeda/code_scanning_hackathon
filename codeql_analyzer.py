import json
import subprocess
from app import app


def analyze_codeql_db(database_name: str, analyze_file: str):
    """Runs the CodeQL analyzer on behalf of the user and retrieves the outputted
    sarif file.
    :param name:
    :return:
    """
    # Run the CodeQL command to analyze the repository
    result = subprocess.run(["codeql", "database", "analyze", database_name,
                            "--format=sarif-latest", f"--output={analyze_file}"], capture_output=True, text=True)
    if result.returncode == 0:
        print("CodeQL analysis completed successfully")
    else:
        print("CodeQL analysis failed. Error message:")
        print(result.stderr)


def parse_sarif_file(analyze_file: str):
    """Parses the SARIF file and extracts the vulnerabilities contained in the results array.
    :return:
    """
    with open(analyze_file) as f:
        sarif_data = json.load(f)
        results = sarif_data["runs"][0]["results"]
        if results:
            return results
        else:
            print("No vulnerabilities found in SARIF file.")


def analyze_json_results(results):
    ls_locations = []
    for result in results:
        # Access dictionary elements
        vulnerability = result["message"]["text"]
        locations = result["locations"]
        for location in locations:
            # Access location details
            file_path = location["physicalLocation"]["artifactLocation"]["uri"]
            line = location["physicalLocation"]["region"]["startLine"]
            ls_locations.append(
                {"file_path": file_path, "line": line, "message": vulnerability})
    return ls_locations


def get_code_at_line(file_path: str, line_number: int):
    """Reads the file and retrieves the code at a specific line number.
    :param file_path: The path to the file.
    :param line_number: The line number.
    :return: The code at the specified line.
    """
    with open(file_path) as f:
        lines = f.readlines()
        if line_number <= len(lines):
            code = {
                "single": lines[line_number - 1].strip(),
                "preview": lines[max(0, line_number - 4):min(len(lines), line_number + 3)]
            }
            return code
        else:
            print("Line number exceeds the total number of lines in the file.")


def search_git_history(file_path: str, keyword: str):
    """Searches the git history for a specific keyword using the 'git log -S' command.
    :param keyword: The keyword to search for.
    :return: The output of the git log command.
    """
    result = subprocess.run(
        ["git", "log", "-S", keyword, "--", file_path], capture_output=True, text=True)
    if result.returncode == 0:
        # Extract the sha, author, and time from the git log output
        git_log_output = result.stdout
        lines = git_log_output.split("\n")
        x = []
        for line in lines:
            if line.startswith("commit"):
                sha = line.removeprefix("commit").strip()
                x.append(sha)
            elif line.startswith("Author"):
                author = line.split(":")[1].split(" <")[0].strip()
                email = line.split("<")[1].split(">")[0].strip()
                x.append(author)
                x.append(email)
            elif line.startswith("Date"):
                date = line.removeprefix("Date").strip()
                x.append(date)
        return {"sha": x[0], "author": x[1], "email": x[2], "date": x[3]}

    else:
        print("Failed to search git history. Error message:")
        print(result.stderr)
        return ""


if __name__ == "__main__":

    database_name = "database"
    analyze_file = "analyze.sarif"
    output_file = "authors.json"
    output = []

    analyze_codeql_db(database_name, analyze_file)
    results = parse_sarif_file(analyze_file)
    vulnerable_locations = analyze_json_results(results)
    for location in vulnerable_locations:
        code = get_code_at_line(location["file_path"], location["line"])
        vuln = search_git_history(location["file_path"], code["single"])
        vuln["file_path"] = location["file_path"]
        vuln["line"] = location["line"]
        vuln["message"] = location["message"]
        vuln["preview"] = code["preview"]
        output.append(vuln)

    with open(output_file, "w") as f:
        json.dump(output, f, indent=4)
    app.run()
