import json
import json


def main():
    sarif_file = "./output.sarif"

    with open(sarif_file, "r") as file:
        sarif_data = json.load(file)

    data = sarif_data["runs"][0]
    results = data["results"]


    # for every dictionary in results, there is a key called locations that specifies where
    # the vulnerability exists.
    
    with open("results.json", "w") as file:
        json.dump(results, file, indent=5)

if __name__ == "__main__":
    main()
