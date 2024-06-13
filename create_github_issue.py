import json
import os
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def create_issue_on_github(json_payload_from_site) -> Any | None:
    """
    Creates an issue on GitHub repository using the provided JSON payload.

    Args: json_payload_from_site: A dictionary containing the JSON payload from the site.
        It should have the following keys:
        - "message": A string representing the message of the issue.
        - "preview": A list of strings representing the code preview.
        - "preview_index": An integer representing the index of the vulnerability in the code preview.
    Returns: A string representing the URL of the created issue.
    """
    header = {"Accept": "application/vnd.github+json",
              "Authorization": f"Bearer {GITHUB_TOKEN}",
              "X-GitHub-Api-Version": "2022-11-28"}
    url = "https://api.github.com/repos/abhimeda/code_scanning_hackathon/issues"

    message = json_payload_from_site["message"]
    preview = json_payload_from_site["preview"]
    preview_index = json_payload_from_site["preview_index"]

    preview_index_map = {}

    for i, code in enumerate(preview):
        preview_index_map[i] = code

    json_string = json.dumps(preview_index_map, indent=4)
    
    body = f"Vulnerability at index {preview_index} in \n" \
           f"{json_string}"
    
    json_payload = {
        "title": f"CodeQL Analysis Report - {message}",
        "body": body,
        "labels": ["CodeQL"]
    }
    
    response = requests.post(url, headers=header, json=json_payload)
    
    if response.status_code == 201:
        return response.json()["html_url"]
    else:
        return None
