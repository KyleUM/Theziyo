import requests
import os

url = "https://www.virustotal.com/api/v3/files"
folder_path = os.path.join('..', 'output', 'dumped')  # Path to the folder containing files
output_folder = os.path.join('..', 'output', 'results')  # Path to the folder where the results will be saved

headers = {
    "accept": "application/json",
    "x-apikey": "af2cfdb2a6777ce3e79a1db3633cd585f214bb614299bc750bb29118778b4ffa"
}

if not os.path.exists(output_folder):
    os.makedirs(output_folder)

for filename in os.listdir(folder_path):
    file_path = os.path.join(folder_path, filename)
    files = {"file": (filename, open(file_path, "rb"), "text/plain")}
    response = requests.post(url, files=files, headers=headers)
    output_path = os.path.join(output_folder, f"{filename}.txt")
    with open(output_path, "w") as f:
        f.write(response.text)
    print(f"Result saved to {output_path}")
    print(response.text)
