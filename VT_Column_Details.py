import requests

api_key = ""

def get_detection_results(api_key, resource):
    url = f"https://www.virustotal.com/api/v3/files/{resource}/analyzes"
    headers = {"x-apikey": api_key}
    params = {"limit": 1}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        response_json = response.json()
        analysis_id = response_json["data"][0]["id"]
        analysis_url = f"https://www.virustotal.com/gui/file/{resource}/detection/{analysis_id}"
        detections = response_json["data"][0]["attributes"]["last_analysis_results"]
        return detections, analysis_url
    else:
        return None, None

resource = '' #SHA256
detections, analysis_url = get_detection_results(api_key, resource)

if detections is not None:
    print("Antivirus             Detected  Version               Result                             Update")
    print("---------             --------  -------               ------                             ------")
    for vendor, data in detections.items():
        detected = data.get("detected", False)
        version = data.get("version", "")
        result = data.get("result", "")
        update = data.get("update", "")
        print(f"{vendor:<20} {detected:<9} {version:<20} {result:<35} {update}")
    print(f"\nFull analysis report: {analysis_url}")
else:
    print("Error retrieving detection results")
