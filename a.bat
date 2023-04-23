Start client.exe
frida -l script.js client.exe -o output/output.txt
echo The frida script has finished executing.
cd detectorAPI
python VirusTotal.py
cd ..
echo The script has finished executing.