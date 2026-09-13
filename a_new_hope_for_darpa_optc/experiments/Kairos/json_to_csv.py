import json
import csv
from os import walk


def json_file(path):
    res = []
    for dir_path, dir_names, file_names in walk(path):
        if dir_path[-1] != "/":
            dir_path += "/"
        for f in file_names:
            temp_file_path = dir_path + f
            if ".json" in temp_file_path:
                res.append(temp_file_path)
    return res


def json_to_csv(res, csv_file):
    i = 1
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        for r in res:
            log_file = open(r, "r")
            for line in log_file:
                json_line = json.loads(line)
                cleaned_data = {}
                cleaned_data["hostname"] = json_line["hostname"]
                cleaned_data["id"] = json_line["id"]
                cleaned_data["objectID"] = json_line["objectID"]
                cleaned_data["actorID"] = json_line["actorID"]
                cleaned_data["timestamp"] = json_line["timestamp"]
                cleaned_data["object"] = json_line["object"]
                cleaned_data["action"] = json_line["action"]

                if i:
                    writer = csv.DictWriter(
                        f, fieldnames=cleaned_data.keys()
                    )  # Utilise les clés restantes comme en-têtes
                    writer.writeheader()  # Écrire les en-têtes
                    i = 0
                writer.writerow(cleaned_data)  # Écrire la ligne modifiée


##############################################################################################################
# folder path
dir_path = "Labels/events/effectiveness/"
res = json_file(dir_path)
print(res)
csv_file = "Labels/events/effectiveness/labels.csv"
json_to_csv(res, csv_file)
