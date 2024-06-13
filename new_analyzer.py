import json
import subprocess
from app import app


def results_from_sarif(analyze_file: str):
    with open(analyze_file) as f:
        sarif_data = json.load(f)
        results = sarif_data["runs"][0]["results"]
        if results:
            return results
        else:
            print("No vulnerabilities found in SARIF file.")


def locations_from_results(results):
    locations = []
    for result in results:
        # Access dictionary elements
        vulnerability = result["message"]["text"]
        for location in result["locations"]:
            # Access location details
            file_path = location["physicalLocation"]["artifactLocation"]["uri"]
            line = location["physicalLocation"]["region"]["startLine"]
            locations.append(
                {"file_path": file_path, "line": line, "message": vulnerability})
    return locations


def code_from_location(repo_dir: str, location: dict):
    file_path = location["file_path"]
    line_number = location["line"]
    half_num_lines = 5

    with open(f"{repo_dir}/{file_path}") as f:
        lines = f.readlines()
        if line_number <= len(lines):
            code = {
                "single": lines[line_number - 1].strip(),
                "preview": lines[max(0, line_number - half_num_lines):min(len(lines), line_number + half_num_lines + 1)],
                "preview_index": line_number - 1 - max(0, line_number - half_num_lines)
            }
            return code
        else:
            print("Line number exceeds the total number of lines in the file.")


def search_git_log(location: dict, code: dict):
    file_path = location["file_path"]
    keyword = code["single"]

    result = execute_cmd(
        ["git", "log", "-S", keyword, "--", file_path], repo_dir)

    if result.returncode == 0:
        git_log_output = result.stdout
        lines = git_log_output.split("\n")
        info = {}
        temp = {}
        for line in lines:
            if line.startswith("commit"):
                sha = line.removeprefix("commit").strip()
                temp["sha"] = sha
            elif line.startswith("Author"):
                author = line.split(":")[1].split(" <")[0].strip()
                email = line.split("<")[1].split(">")[0].strip()
                temp["author"] = author
                temp["email"] = email
            elif line.startswith("Date"):
                date = line.removeprefix("Date").strip()
                temp["date"] = date
            # check if all fields in temp are present; if so, assign info = temp
            if all(key in temp for key in ["sha", "author", "email", "date"]):
                info = temp
                temp = {}
        return info
    else:
        print("Failed to search git history. Error message:")
        print(result.stderr)
        return ""


def execute_cmd(cmd: list[str], cwd: str):
    print(f"Directory: {cwd} | Command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if result.returncode == 0:
        return result
    else:
        print(f"Command error: {result.stderr}")
        return result


history_dir = "database"
history = [
    "database-b8b8ebcf851d-2017-04-11",
    "database-da5091bf507b-2019-08-02",
    "database-d25dd807485c-2020-01-03",
    "database-5a7786812dd4-2024-01-11",
    "database-a632c89dd778-2024-06-07"
]
repo_dir = "tensorflow"
repo_branch = "master"
output_file = "output.json"
stash_file = "authors.json"

if __name__ == "__main__":
    stash = []

    execute_cmd(["git", "fetch"], repo_dir)

    for scan_file in history:
        sarif_file = f"{history_dir}/{scan_file}.sarif"
        scan_sha = scan_file.split("-")[1]

        execute_cmd(["git", "checkout", scan_sha], repo_dir)

        results = results_from_sarif(sarif_file)

        locations = locations_from_results(results)

        for location in locations:
            code = code_from_location(repo_dir, location)

            search = search_git_log(location, code)

            vuln = {
                "scan_file": scan_file,
                "sha": search["sha"],
                "author": search["author"],
                "email": search["email"],
                "date": search["date"],
                "file_path": location["file_path"],
                "line": location["line"],
                "message": location["message"],
                "preview": code["preview"],
                "preview_index": code["preview_index"],
                "new": False
            }

            # check if a vuln with the same sha, file_path, and code_line is already in the stash
            if not any(v["sha"] == vuln["sha"]
                       and v["file_path"] == vuln["file_path"]
                       and v["preview"][v["preview_index"]] == vuln["preview"][vuln["preview_index"]]
                       and v["line"] == vuln["line"]
                       for v in stash):
                vuln["new"] = True
            stash.append(vuln)

    execute_cmd(["git", "checkout", repo_branch], repo_dir)

    output = {}
    for scan_file in history:
        scan_sha = scan_file.split("-")[1]
        output[scan_file] = {
            "sha": scan_sha,
            "date": scan_file.split(f"{scan_sha}-")[1],
            "new_vulns": [v for v in stash if v["scan_file"] == scan_file and v["new"] == True],
            "old_vulns": [v for v in stash if v["scan_file"] == scan_file and v["new"] == False]
        }

    # old format, just an array of vulns
    with open(stash_file, "w") as f:
        json.dump(stash, f, indent=4)
    # new format, vulns are organized by scan file, no repeated vulns
    with open(output_file, "w") as f:
        json.dump(output, f, indent=4)

    app.run()
