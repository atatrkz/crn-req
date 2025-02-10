import requests
import json
import time
from datetime import datetime

url = "https://obs.itu.edu.tr/api/ders-kayit/v21"

payload = json.dumps({
  "ECRN": [
    "22661",
    "22662",
    "22634",
    "22636"
  ],
  "SCRN": []
})
headers = {
  'accept': 'application/json, text/plain, */*',
  'accept-language': 'en-US,en;q=0.9,tr;q=0.8',
  'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6Iml0dVxcdHVya296YTE4IiwiZGlzcGxheV9uYW1lIjoiQXRhIFTDvHJrw7Z6Iiwic2Vzc2lvbiI6ImQxZTdhNTVkLTg4NDktNGQ2Zi1hNmVhLTNjZGVlYTU2YWM2NiIsInJvbGUiOlsibGlzYW5zIiwib2dyZW5jaSJdLCJpZGVudGl0eSI6IjE1MDE4MDAxMSIsIm5iZiI6MTczOTE3Mzk1MCwiZXhwIjoxNzM5MTk1NTQ5LCJpYXQiOjE3MzkxNzM5NTB9.QErTlsSTkBCaGQDyJkN1fWYrofKeXDzn0eLWU-l3bNI',
  'content-type': 'application/json',
  'origin': 'https://obs.itu.edu.tr',
  'priority': 'u=1, i',
  'referer': 'https://obs.itu.edu.tr/ogrenci/DersKayitIslemleri/DersKayit',
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
}

def make_request():
    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        current_time = datetime.now().strftime("%H:%M:%S")
        crn_data = json.loads(payload)["ECRN"]
        response_json = response.json()
        print(f"[{current_time}]")
        if 'ecrnResultList' in response_json:
            for result in response_json['ecrnResultList']:
                crn = result.get('crn', 'Unknown')
                status = result.get('statusCode', 'Unknown')
                result_code = result.get('resultCode', 'Unknown')
                print(f"CRN: {crn} | Status Code: {status} | Result Code: {result_code}")
        else:
            print("No CRN results found in response")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
    except json.JSONDecodeError as e:
        print(f"Error parsing response: {e}")

print("Starting CRN taker script. Press Ctrl+C to stop.")
try:
    while True:
        make_request()
        time.sleep(3.5)  # Wait for 3.5 seconds before next request
except KeyboardInterrupt:
    print("\nScript stopped by user.") 