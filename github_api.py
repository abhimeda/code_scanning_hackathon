import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def make_request_to_github(url: object, params: object = None) -> object:
    header = {"Accept": "application/vnd.github+json",
              "Authorization": f"Bearer {GITHUB_TOKEN}",
              "X-GitHub-Api-Version": "2022-11-28"}
    response = requests.get(url, headers=header, params=params)
    return response.json()

if __name__ == "__main__":
    url = "https://api.github.com/repos/abhimeda/code_scanning_hackathon/commits?page=0&per_page=30"
    x = make_request_to_github(url)
    print(json.dumps(x, indent=4))
