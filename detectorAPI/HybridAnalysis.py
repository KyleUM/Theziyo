import requests
import os
import sys

url = "https://www.hybrid-analysis.com/api/v2/file"
api_key = "g6m35fwx1029ebd2t0dojuamfd4a2e29idqk4ivt474583a1rdrjz31ye22fafc8"
file_path = os.path.join('..','output','dumped','Dump0.txt')
params = {'apikey': api_key}

with open(file_path, 'rb') as f:
    response = requests.post(url, headers=params, files={'file': f})

if response.status_code == 200:
    data = response.json()
    print(data)
else:
    print('error submitting file: ' + str(response.status_code))

