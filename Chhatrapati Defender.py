import hashlib
import requests
import json

print("""
  _____ _     _           _                         _   _ _____        __               _           
 / ____| |   | |         | |                       | | (_)  __ \      / _|             | |          
| |    | |__ | |__   __ _| |_ _ __ __ _ _ __   __ _| |_ _| |  | | ___| |_ ___ _ __   __| | ___ _ __ 
| |    | '_ \| '_ \ / _` | __| '__/ _` | '_ \ / _` | __| | |  | |/ _ \  _/ _ \ '_ \ / _` |/ _ \ '__|
| |____| | | | | | | (_| | |_| | | (_| | |_) | (_| | |_| | |__| |  __/ ||  __/ | | | (_| |  __/ |   
 \_____|_| |_|_| |_|\__,_|\__|_|  \__,_| .__/ \__,_|\__|_|_____/ \___|_| \___|_| |_|\__,_|\___|_|   
                                       | |                                                          
                                       |_|                                                          
Created By - https://github.com/Martinxploit
    """)


def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()
        file_hash = hashlib.sha256(file_data).hexdigest()
        return file_hash

def scan_on_virustotal(api_key, file_hash):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": api_key, "resource": file_hash}
    response = requests.get(url, params=params)
    json_response = response.json()
    return json_response

if __name__ == '__main__':
    api_key = input("Please enter your VirusTotal API key: ")
    file_path = input("Please enter the file path: ")

    file_hash = get_file_hash(file_path)

    scan_result = scan_on_virustotal(api_key, file_hash)

    if scan_result['response_code'] == 0:
        print("The file has not been scanned on VirusTotal yet.")
    else:
        print("Scan result:")
        positives = scan_result['positives']
        total = scan_result['total']
        print(f"{positives}/{total} antivirus engines detected the file as malicious.")
        print("Full report:")
        print(json.dumps(scan_result, indent=2))
        with open('scan_result.txt', 'w') as f:
            f.write(json.dumps(scan_result, indent=2))
            print("Scan result saved to scan_result.txt")
