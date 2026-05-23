"""
SWU Check-in Script
Automated check-in for SWU students using the school's API.
Handles CAS OAuth login with DES encryption and CAPTCHA solving.
"""
import os
import random
import re
import sys
import time
import json
import urllib.parse
import requests

from des import str_enc


# ---- helper: CAPTCHA solving ----

def solve_captcha(session, timeout=10):
    """
    Download CAPTCHA image from idm.swu.edu.cn and solve it.
    Uses ddddocr for recognition. Falls back to manual input in local testing.
    """
    captcha_url = "https://idm.swu.edu.cn/am/validate.code?id=" + str(random.randint(0, 999999))
    resp = session.get(captcha_url, timeout=timeout)
    if resp.status_code != 200:
        print(f"[WARN] CAPTCHA download failed, status={resp.status_code}")
        return None

    try:
        import ddddocr
        ocr = ddddocr.DdddOcr()
        result = ocr.classification(resp.content)
        code = str(result).strip()
        if len(code) >= 4:
            print(f"[OCR] CAPTCHA solved: {code}")
            return code[:4]
        else:
            print(f"[WARN] OCR returned short result: {code}")
            return None
    except ImportError:
        # ddddocr not available, save and report
        with open("/tmp/swu_captcha.png", "wb") as f:
            f.write(resp.content)
        print("[ERROR] ddddocr not installed. CAPTCHA saved to /tmp/swu_captcha.png")
        return None
    except Exception as e:
        print(f"[WARN] OCR failed: {e}")
        return None


# ---- helper: ticket transformation (from old get_info.py) ----

def transform_ticket(ticket):
    """Transform CAS ticket into the format expected by the token exchange."""
    ST = urllib.parse.unquote(ticket)
    ticket_parts = urllib.parse.unquote(ST).split("-")
    str1 = ""
    str2 = ""
    for ch in ticket_parts[1]:
        str1 += str((int(ch) + 5) % 10)
    for ch in ticket_parts[2]:
        if "0" <= ch <= "9":
            str2 += str((int(ch) + 5) % 10)
        elif "A" <= ch <= "Z":
            if ord(ch) + 10 > ord("Z"):
                str2 += chr(ord(ch) + 10 - 26)
            else:
                str2 += chr(ord(ch) + 10)
        else:
            if ord(ch) + 15 > ord("z"):
                str2 += chr(ord(ch) + 15 - 26)
            else:
                str2 += chr(ord(ch) + 15)
    return str1, str2


# ---- core auth flow ----

def get_token(username: str, password: str, timeout: int = 15):
    """
    Complete login flow:
    1. Start CAS OAuth flow, follow redirects to idm login page
    2. Extract random key and hidden form fields
    3. Solve CAPTCHA
    4. DES-encrypt credentials
    5. Submit login form
    6. Follow redirect chain to get auth token
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    })

    # Step 1: Start CAS OAuth flow.
    # Step through redirects manually: of.swu.edu.cn → uaaap.swu.edu.cn → idm.swu.edu.cn
    cas_url = (
        "https://of.swu.edu.cn/cas/oauth/login/SWU_CAS2_FEDERAL"
        "?service=https%3A%2F%2Fof.swu.edu.cn%2Fgateway%2Ffighter-middle%2Fapi%2F"
        "integrate%2Fuaap%2Fcas%2Fresolve-cas-return%3Fnext%3Dhttps%253A%252F%252F"
        "of.swu.edu.cn%252F%2523%252FcasLogin%253Ffrom%253D%25252FappCenter"
    )
    print("[LOGIN] Step 1: GET CAS OAuth URL...")
    try:
        resp = session.get(cas_url, allow_redirects=False, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] CAS initial request failed: {e}")
        return None

    if resp.status_code not in (301, 302, 303, 307, 308):
        print(f"[ERROR] Expected redirect, got status {resp.status_code}")
        return None

    uaaap_url = resp.headers.get("Location", "")
    print(f"[LOGIN] Step 1 → {uaaap_url[:100]}...")

    # Extract state from uaaap URL
    parsed = urllib.parse.urlparse(uaaap_url)
    qs = urllib.parse.parse_qs(parsed.query)
    state = qs.get("state", [None])[0]
    if state:
        print(f"[LOGIN] State: {state}")

    # Step 2: Follow uaaap redirect
    print("[LOGIN] Step 2: GET uaaap...")
    try:
        resp = session.get(uaaap_url, allow_redirects=False, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] uaaap request failed: {e}")
        return None

    print(f"[LOGIN] Step 2 status: {resp.status_code}")

    # uaaap may redirect to idm (302) or show a page
    idm_url = None
    if resp.status_code in (301, 302, 303, 307, 308):
        idm_url = resp.headers.get("Location", "")
        print(f"[LOGIN] Step 2 → redirect to: {idm_url[:100]}...")
    else:
        # uaaap returned a page - might be JavaScript redirect or error
        print(f"[LOGIN] Step 2 no redirect, checking page content...")
        html_snippet = resp.text[:500]
        print(f"[LOGIN] Page start: {html_snippet[:200]}...")
        # Try to find redirect URL in HTML
        redirect_match = re.search(r'(?:location\.href|window\.location)\s*=\s*["\']([^"\']+)["\']', resp.text)
        if redirect_match:
            idm_url = redirect_match.group(1)
            print(f"[LOGIN] Found JS redirect: {idm_url[:100]}...")
        else:
            # Build idm URL manually
            print("[LOGIN] Building idm URL manually...")
            idm_url = "https://idm.swu.edu.cn/am/UI/Login?service=initService"

    # Step 3: GET idm login page
    if idm_url:
        print("[LOGIN] Step 3: GET idm login page...")
        try:
            resp = session.get(idm_url, allow_redirects=True, timeout=timeout)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] idm request failed: {e}")
            return None
        print(f"[LOGIN] Step 3 landed at: {resp.url[:120]}...")
    else:
        print("[ERROR] No idm URL found")
        return None

    login_html = resp.text
    print(f"[LOGIN] Page length: {len(login_html)} bytes")

    # Step 2: Parse the login page for hidden form fields and random value
    # Extract random value
    random_match = re.search(r'id="random"\s+(?:name="random"\s+)?value="([^"]*)"', login_html)
    if not random_match:
        random_match = re.search(r'name="random"\s+(?:id="random"\s+)?value="([^"]*)"', login_html)
    random_val = random_match.group(1) if random_match else ""
    print(f"[LOGIN] Random key: {random_val[:20]}..." if random_val else "[LOGIN] No random key found")

    # Extract hidden form fields from the Login form
    goto = ""
    goto_match = re.search(r'name="goto"\s+value="([^"]*)"', login_html)
    if goto_match:
        goto = goto_match.group(1)

    goto_on_fail = ""
    gof_match = re.search(r'name="gotoOnFail"\s+value="([^"]*)"', login_html)
    if gof_match:
        goto_on_fail = gof_match.group(1)

    sun_params = ""
    sp_match = re.search(r'name="SunQueryParamsString"\s+value="([^"]*)"', login_html)
    if sp_match:
        sun_params = sp_match.group(1)

    encoded_val = "false"
    enc_match = re.search(r'name="encoded"\s+value="([^"]*)"', login_html)
    if enc_match:
        encoded_val = enc_match.group(1)

    print(f"[LOGIN] goto={goto[:80]}..." if len(goto) > 80 else f"[LOGIN] goto={goto}")

    # Step 3: Solve CAPTCHA
    captcha_code = solve_captcha(session, timeout)
    if not captcha_code:
        print("[ERROR] Failed to solve CAPTCHA. Cannot proceed.")
        return None

    # Step 4: DES-encrypt username and password with the random key
    encrypted_username = str_enc(username, random_val, "", "")
    encrypted_password = str_enc(password, random_val, "", "")
    print(f"[LOGIN] Credentials encrypted (username hex len={len(encrypted_username)})")

    # Step 5: Submit login form
    login_data = {
        "IDToken1": encrypted_username,
        "IDToken2": encrypted_password,
        "IDToken3": "",
        "goto": goto,
        "gotoOnFail": goto_on_fail,
        "SunQueryParamsString": sun_params,
        "encoded": encoded_val,
        "gx_charset": "UTF-8",
        "validateCode": captcha_code,
    }

    print("[LOGIN] Submitting login form...")
    try:
        resp = session.post(
            "https://idm.swu.edu.cn/am/UI/Login",
            data=login_data,
            allow_redirects=True,
            timeout=timeout,
        )
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Login POST failed: {e}")
        return None

    # Check if login succeeded or failed
    post_url = resp.url
    print(f"[LOGIN] After login POST, landed at: {post_url[:120]}...")

    # If we're still on the login page, login failed
    if "UI/Login" in post_url and "idm.swu.edu.cn" in post_url:
        # Check for error message
        if "验证码" in resp.text and "错误" in resp.text:
            print("[ERROR] Login failed: incorrect CAPTCHA")
        elif "密码" in resp.text or "password" in resp.text.lower():
            print("[ERROR] Login failed: incorrect credentials")
        else:
            print("[ERROR] Login failed: still on login page")
        return None

    # Step 6: Follow the redirect chain to get the token.
    # After successful login, the chain should be:
    # idm → uaaap (with code) → of.swu.edu.cn/cas/oauth/callback (with ticket/ST)
    # → final token exchange

    # Try to extract CAS ticket from the redirect URL
    ticket = None
    if "ticket=" in post_url:
        ticket = post_url.split("ticket=")[1].split("&")[0]
        print(f"[LOGIN] Got CAS ticket: {ticket[:30]}...")

    # If no direct ticket, try the old transformation path
    if not ticket:
        # Check if we got an authorization code from uaaap
        auth_code = None
        for hist in resp.history:
            if "code=" in hist.url:
                auth_code = hist.url.split("code=")[1].split("&")[0]
                print(f"[LOGIN] Got auth code from uaaap: {auth_code[:30]}...")
                break
        if not auth_code:
            print(f"[ERROR] No ticket or code found after login. URL: {post_url[:200]}")
            return None

    # Exchange for fighter-auth-token
    # First, try to get the ST token
    token = None

    if ticket:
        try:
            str1, str2 = transform_ticket(ticket)
            CD = f"CD-{str1}-{str2}-wiie://777.643.675.751:3537/rph"
            if state:
                callback_url = (
                    f"https://of.swu.edu.cn/cas/oauth/callback/SWU_CAS2_FEDERAL"
                    f"?code={urllib.parse.quote(CD)}@@hxbeat&state={state}"
                )
            else:
                callback_url = (
                    f"https://of.swu.edu.cn/cas/oauth/callback/SWU_CAS2_FEDERAL"
                    f"?code={urllib.parse.quote(CD)}@@hxbeat"
                )
            print(f"[LOGIN] Calling CAS callback...")
            resp = session.get(callback_url, allow_redirects=True, timeout=timeout)

            if "ticket=" in resp.url:
                ST = resp.url.split("ticket=")[1].split("&")[0]
                print(f"[LOGIN] Got ST token: {ST[:30]}...")
                token_resp = requests.get(
                    f"https://of.swu.edu.cn/gateway/fighter-middle/api/integrate/"
                    f"uaap/cas/exchange-token?token={ST}&remember=true",
                    timeout=timeout,
                )
                token_data = token_resp.json()
                if "data" in token_data:
                    token = token_data["data"]
                    print(f"[LOGIN] Got fighter-auth-token: {token[:20]}...")
        except Exception as e:
            print(f"[ERROR] Token exchange failed: {e}")
            return None

    if not token:
        print("[ERROR] Could not obtain auth token")
        return None

    return token


# ---- check-in API calls (adapted from old check_in.py) ----

def get_student_id(token, timeout=10):
    url = "https://of.swu.edu.cn/gateway/fighter-middle/api/auth/user?appType=fighter-portal"
    headers = {"fighter-auth-token": token}
    resp = requests.get(url, headers=headers, timeout=timeout)
    return resp.json()["data"]["subject"]["username"]


def get_dormitory(token, timeout=10):
    url = "https://of.swu.edu.cn/gateway/fighter-baida/api/cqlc/getDormitory"
    headers = {
        "fighter-auth-token": token,
        "Content-Type": "application/json;charset=UTF-8",
    }
    resp = requests.post(url, headers=headers, data=json.dumps({}), timeout=timeout)
    return resp.json()


def get_transition_today(token, timeout=10):
    url = "https://of.swu.edu.cn/gateway/fighter-baida/api/cqtj/getTransitionByToday"
    headers = {"fighter-auth-token": token}
    data = {"pageNum": 1, "pageSize": 1}
    resp = requests.post(url, headers=headers, json=data, timeout=timeout)
    records = resp.json()["data"]["records"]
    return records[0] if records else None


def vacation_enable(token, timeout=10):
    headers = {"fighter-auth-token": token}
    url = "https://of.swu.edu.cn/gateway/fighter-baida/api/flow-ext/start-process-instance-by-key"
    params = {"processDefinitionKey": "XSQJXJ"}
    resp = requests.post(headers=headers, params=params, json={}, url=url, timeout=timeout)
    code = resp.json()["code"]
    return code == 200 or code == 1100


def checkin_post(token, timeout=10):
    try:
        transition_today = get_transition_today(token)
        if transition_today is None:
            return None
        form_id = transition_today["formId"]
        record_id = transition_today["id"]
        headers = {
            "fighter-auth-token": token,
            "Content-Type": "application/json;charset=UTF-8",
        }
        url = "https://of.swu.edu.cn/gateway/fighter-baida/api/form-instance/save"
        params = {"formId": form_id, "isSubmitProcess": False}
        dormitory = get_dormitory(token, timeout)["data"]["columnList"]

        payload = {
            "id": record_id,
            "formId": form_id,
            "tsrq": time.strftime("%Y-%m-%d"),
            "xh": get_student_id(token),
            "qdsj": ["21:00", "23:30"],
            "qsqddd": dormitory[1]["value"],
            "qdbj": dormitory[2]["value"],
            "qddz": {
                "latitude": dormitory[0]["latitude"],
                "longitude": dormitory[0]["longitude"],
                "address": dormitory[1]["value"],
                "netType": "wifi",
                "operatorType": "unknown",
                "imei": "imei",
                "time": int(time.time() * 1000),
                "provider": "lbs",
                "isFromMock": False,
                "isGpsEnabled": True,
                "isWifiEnabled": True,
                "isMobileEnabled": False,
                "isOffset": True,
                "cityAdCode": "023",
                "districtAdCode": "500109",
                "isArea": True,
                "tip": "当前在签到范围内",
            },
        }
        resp = requests.post(
            url, headers=headers, params=params, data=json.dumps(payload), timeout=timeout
        )
        return resp.json()["data"]
    except requests.exceptions.Timeout:
        return 4
    except requests.exceptions.ConnectionError:
        return 4


# ---- main entry ----

def check_in(username: str, password: str, timeout: int = 15):
    """
    Main check-in function.
    Returns:
        0 - No check-in task today
        1 - Check-in successful
        2 - Already checked in today
        3 - Account/password verification failed
        4 - Network error or timeout
        5 - On leave
    """
    print(f"[CHECKIN] Starting check-in process...")

    # Step 1: Login and get token
    token = get_token(username, password, timeout)
    if not token:
        return 3

    # Step 2: Check if on leave
    if vacation_enable(token, timeout):
        return 5

    # Step 3: Check if there's a check-in task today
    transition_today = get_transition_today(token, timeout)
    if not transition_today:
        return 0

    # Step 4: Check if already checked in
    if transition_today.get("qdzt") == "已签到":
        return 2

    # Step 5: Submit check-in
    post_result = checkin_post(token, timeout)
    if post_result == 4:
        return 4

    return 1


if __name__ == "__main__":
    print("=" * 50)
    print("  SWU Check-in Script")
    print("=" * 50)

    user = os.getenv("SWU_USERNAME", "").strip()
    pwd = os.getenv("SWU_PASSWORD", "").strip()

    if not user or not pwd:
        print("ERROR: Missing credentials.")
        print("Set environment variables: SWU_USERNAME and SWU_PASSWORD")
        sys.exit(1)

    print(f"Username: {user}")
    print("Starting...")
    print()

    result = check_in(user, pwd)

    messages = {
        0: "今日暂无签到任务。",
        1: "签到成功！",
        2: "今日已签到，无需重复操作。",
        3: "账号或密码验证失败，请检查后重试。",
        4: "连接错误或请求超时，请稍后重试。",
        5: "请假中，请检查是否有打卡任务。",
    }

    print()
    print(f"Result: {messages.get(result, f'Unknown ({result})')}")
    print("=" * 50)

    # Exit with result code so GitHub Actions can report status
    sys.exit(result if result != 1 else 0)
