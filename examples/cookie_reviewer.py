import requests

def evaluate_cookie(cookie):
    """Evaluates a single cookie against OWASP best practices and returns a score and warnings."""
    score = 100
    warnings = []

    # Secure flag check
    if not cookie.secure:
        warnings.append("Cookie is missing the Secure flag.")
        score -= 25

    # HttpOnly flag check
    if not cookie.has_nonstandard_attr("HttpOnly"):
        warnings.append("Cookie is missing the HttpOnly flag.")
        score -= 25

    # SameSite attribute check
    same_site = cookie.get_nonstandard_attr("SameSite")
    if same_site is None:
        warnings.append("Cookie is missing the SameSite attribute.")
        score -= 20
    elif same_site.lower() not in ["strict", "lax"]:
        warnings.append(f"Cookie has an insecure SameSite value: {same_site}")
        score -= 10

    # Expiration check (Persistent cookies with long lifetimes)
    if cookie.expires:
        warnings.append(f"Cookie has a persistent expiration: {cookie.expires}")
        score -= 10

    # Domain scope check (not foolproof, but a basic indicator)
    if cookie.domain and cookie.domain.startswith("."):
        warnings.append(f"Cookie is set for a wildcard domain: {cookie.domain}")
        score -= 10

    return score, warnings

def get_cookies(url):
    session = requests.Session()
    response = session.get(url)

    cookies = response.cookies

    overall_score = 0
    results = []

    if not cookies:
        print("No cookies found.")
        return

    for cookie in cookies:
        score, warnings = evaluate_cookie(cookie)
        overall_score += score
        results.append({
            "name": cookie.name,
            "secure": cookie.secure,
            "http_only": cookie.has_nonstandard_attr("HttpOnly"),
            "same_site": cookie.get_nonstandard_attr("SameSite"),
            "expires": cookie.expires,
            "domain": cookie.domain,
            "score": score,
            "warnings": warnings
        })

    avg_score = overall_score / len(cookies)
    print(f"\nOverall Security Score: {avg_score:.2f}/100\n")

    for result in results:
        print(f"Cookie: {result['name']}")
        print(f" - Score: {result['score']}/100")
        for warning in result['warnings']:
            print(f"   ⚠ {warning}")
        print("-" * 40)

if __name__ == "__main__":
    target_url = "https://google.com"
    get_cookies(target_url)