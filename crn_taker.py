import requests
import json
import time
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# ---------------- USER CONFIG ----------------
USERNAME = "YOUR_STUDENT_NUMBER"
PASSWORD = "YOUR_OBS_PASSWORD"
# ---------------------------------------------

LOGIN_START_URL = "https://obs.itu.edu.tr/login/auth/login"

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-GB,en;q=0.9,en-US;q=0.8,tr;q=0.7",
    "Upgrade-Insecure-Requests": "1",
}

# ---------------- STEP 1 ----------------
def get_login_redirect(session: requests.Session):
    """Initial request to OBS login, extract subSessionId + redirect URL."""
    resp = session.get(LOGIN_START_URL, headers=COMMON_HEADERS, allow_redirects=False)
    print(f"Step 1: status={resp.status_code}")
    
    # Print cookies from initial request
    if session.cookies:
        print("Initial cookies:")
        for c in session.cookies:
            print(f" - {c.name} = {c.value}")

    loc = resp.headers.get("Location")
    subsession = None
    if loc:
        parsed = urlparse(loc)
        subsession = parse_qs(parsed.query).get("subSessionId", [None])[0]

    print(f"subSessionId: {subsession}")
    print(f"Redirect URL: {loc}")
    return subsession, loc

# ---------------- STEP 2 ----------------
def scrape_hidden_fields(html: str, name: str) -> str:
    """Helper to extract hidden form fields like __VIEWSTATE."""
    m = re.search(r'id="%s" value="([^"]*)"' % name, html)
    return m.group(1) if m else ""

def do_login(session: requests.Session, login_url: str, username: str, password: str):
    """GET login page -> scrape hidden fields -> POST credentials -> follow redirects to obs."""
    # Step 2a: GET login page
    resp = session.get(login_url, headers=COMMON_HEADERS)
    html = resp.text
    print(f"Step 2a: GET login page status={resp.status_code}")
    
    # Print cookies after GET
    if session.cookies:
        print("Cookies after GET login page:")
        for c in session.cookies:
            print(f" - {c.name} = {c.value}")

    viewstate = scrape_hidden_fields(html, "__VIEWSTATE")
    viewstategen = scrape_hidden_fields(html, "__VIEWSTATEGENERATOR")
    eventval = scrape_hidden_fields(html, "__EVENTVALIDATION")
    
    print(f"VIEWSTATE length: {len(viewstate)}")
    print(f"VIEWSTATEGENERATOR: {viewstategen}")
    print(f"EVENTVALIDATION length: {len(eventval)}")

    # Step 2b: POST credentials
    payload = {
        "__EVENTTARGET": "",
        "__EVENTARGUMENT": "",
        "__VIEWSTATE": viewstate,
        "__VIEWSTATEGENERATOR": viewstategen,
        "__EVENTVALIDATION": eventval,
        "ctl00$ContentPlaceHolder1$hfAppName": "Öğrenci Bilgi Sistemi",
        "ctl00$ContentPlaceHolder1$hfToken": "",
        "ctl00$ContentPlaceHolder1$hfVerifier": "",
        "ctl00$ContentPlaceHolder1$hfCode": "",
        "ctl00$ContentPlaceHolder1$hfState": "",
        "ctl00$ContentPlaceHolder1$tbUserName": username,
        "ctl00$ContentPlaceHolder1$tbPassword": password,
        "ctl00$ContentPlaceHolder1$btnLogin": "Giriş / Login",
    }

    headers = {
        **COMMON_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://girisv3.itu.edu.tr",
        "Referer": login_url,
        "Cache-Control": "max-age=0",
        "Priority": "u=0, i",
        "Sec-Ch-Ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Microsoft Edge";v="140"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
    }

    # Important: allow redirects this time
    resp2 = session.post(login_url, headers=headers, data=payload, allow_redirects=True)
    print(f"Step 2b: POST login final status={resp2.status_code}")
    print(f"Final URL after redirects: {resp2.url}")

    # Print all cookies after login
    print("\nAll cookies after full login:")
    if session.cookies:
        for c in session.cookies:
            print(f" - {c.name} = {c.value} (domain={c.domain}, path={c.path})")
    else:
        print("No cookies stored.")
    
    # Check if we successfully reached OBS and have the required cookies
    has_ogrenci = any(c.name == "OgrenciCookie" for c in session.cookies)
    has_login = any(c.name == "LoginCookie" for c in session.cookies)
    
    if "obs.itu.edu.tr" in resp2.url and has_ogrenci and has_login:
        print("✅ Successfully redirected to OBS with required cookies!")
        return resp2, True
    else:
        print("❌ Login might have failed:")
        print(f"  - Redirected to OBS: {'obs.itu.edu.tr' in resp2.url}")
        print(f"  - Has OgrenciCookie: {has_ogrenci}")
        print(f"  - Has LoginCookie: {has_login}")
    
    return resp2, False

def get_jwt_token(session: requests.Session):
    """Get JWT bearer token using the auth endpoint."""
    url = "https://obs.itu.edu.tr/ogrenci/auth/jwt"
    
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-GB,en;q=0.9,en-US;q=0.8,tr;q=0.7",
        "accepts": "application/json",
        "authorization": "Bearer",
        "priority": "u=1, i",
        "referer": "https://obs.itu.edu.tr/ogrenci/",
        "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Microsoft Edge";v="140"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": COMMON_HEADERS["User-Agent"],
    }
    
    try:
        response = session.get(url, headers=headers)
        print(f"JWT request status: {response.status_code}")
        
        if response.status_code == 200:
            # The response should contain the JWT token
            token = response.text.strip().strip('"')  # Remove quotes if present
            if token and len(token) > 50:  # Basic validation
                print(f"✅ JWT token obtained: {token[:50]}...")
                return token
            else:
                print(f"⚠️  Unexpected JWT response: {response.text}")
        else:
            print(f"❌ JWT request failed: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Error getting JWT token: {e}")
    
    return None

# ---------------- API REQUEST FUNCTIONS ----------------
def make_crn_request(session: requests.Session, bearer_token: str):
    """Make the CRN registration request with proper authentication."""
    url = "https://obs.itu.edu.tr/api/ders-kayit/v21"
    payload = {
        "ECRN": ["YOUR_CRN_1", "YOUR_CRN_2", "YOUR_CRN_3", "YOUR_CRN_4"],
        "SCRN": []
    }
    
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-US,en;q=0.9,tr;q=0.8",
        "authorization": f"Bearer {bearer_token}",
        "content-type": "application/json",
        "origin": "https://obs.itu.edu.tr",
        "referer": "https://obs.itu.edu.tr/ogrenci/DersKayitIslemleri/DersKayit",
        "user-agent": COMMON_HEADERS["User-Agent"],
    }

    try:
        response = session.post(url, headers=headers, json=payload)
        current_time = datetime.now().strftime("%H:%M:%S")
        
        print(f"[{current_time}] Status: {response.status_code}")
        
        if response.status_code == 200:
            response_json = response.json()
            if "ecrnResultList" in response_json:
                for result in response_json["ecrnResultList"]:
                    crn = result.get("crn", "Unknown")
                    status = result.get("statusCode", "Unknown")
                    result_code = result.get("resultCode", "Unknown")
                    print(f"CRN: {crn} | Status Code: {status} | Result Code: {result_code}")
            else:
                print("No CRN results found")
                print(f"Response: {response.text}")
        else:
            print(f"API request failed with status {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"Error making CRN request: {e}")



# ---------------- MAIN ----------------
if __name__ == "__main__":
    print("Starting improved login sequence...")
    
    # Use session with cookie persistence
    s = requests.Session()
    
    # Get initial redirect
    subsession, loc = get_login_redirect(s)
    if not loc:
        print("❌ No redirect URL, exiting.")
        exit(1)

    input("\n⏸️  Press Enter to continue to login...")

    # Perform login
    login_resp, login_success = do_login(s, loc, USERNAME, PASSWORD)
    
    if not login_success:
        print("❌ Login failed. Cannot proceed.")
        exit(1)

    print("\n🔑 Attempting to get JWT bearer token...")
    bearer_token = get_jwt_token(s)
    
    if not bearer_token:
        print("❌ Failed to obtain JWT bearer token.")
        print("This could mean:")
        print("1. Login cookies are not properly set")
        print("2. Session has expired")
        print("3. The JWT endpoint has changed")
        exit(1)
    
    # Verify login by testing the token
    print("✅ JWT token obtained successfully!")
    input("\n⏸️  Press Enter to start CRN monitoring loop...")
    
    try:
        print("Starting CRN monitoring (Ctrl+C to stop)...")
        while True:
            make_crn_request(s, bearer_token)
            time.sleep(3.5)
    except KeyboardInterrupt:
        print("\n⏹️  Stopped by user.")