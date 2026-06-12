import re
from urllib.parse import urlparse

SHORTENERS = [
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee"
]

def analyze_url(url):
    """Analyzes a URL for potential phishing indicators."""
    
    # Ensure URL has a scheme for proper parsing
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
        
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    
    risk_score = 0
    flags = []

    # 1. Check for IP Address in Domain
    # Phishers often use IP addresses instead of domain names to obscure the destination.
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        risk_score += 3
        flags.append("Warning: IP address used instead of a standard domain name.")

    # 2. Check for the '@' Symbol
    # Browsers ignore everything before the '@', making it easy to disguise the true destination.
    if '@' in url:
        risk_score += 2
        flags.append("Warning: '@' symbol found in URL. This is often used to hide the true domain.")

    # 3. Check for URL Shorteners
    # Shorteners hide the final destination of the link.
    if any(shortener in domain for shortener in SHORTENERS):
        risk_score += 2
        flags.append("Warning: URL shortener detected. The true destination is hidden.")

    # 4. Check URL Length
    # Extremely long URLs can be used to hide suspicious parameters.
    if len(url) > 75:
        risk_score += 1
        flags.append("Notice: URL is unusually long (>75 characters).")

    # 5. Check for Multiple Subdomains
    # e.g., login.paypal.com.secure-update.net (The real domain here is secure-update.net)
    # Count the dots in the domain name. > 3 dots is highly suspicious.
    dot_count = domain.count('.')
    if dot_count >= 3 and not re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        risk_score += 2
        flags.append(f"Warning: Multiple subdomains detected ({dot_count} dots). This often mimics legitimate sites.")

    # 6. Check for Hyphens in Domain
    # Phishers use hyphens to create domains that look like legitimate ones (e.g., www.amazon-update.com).
    if '-' in domain:
        risk_score += 1
        flags.append("Notice: Hyphen '-' found in the domain name.")

    # 7. Check for HTTP instead of HTTPS
    if parsed_url.scheme == 'http':
        risk_score += 1
        flags.append("Notice: URL uses HTTP instead of secure HTTPS.")

    # Determine Risk Level
    if risk_score == 0:
        risk_level = "Low/Safe"
    elif 1 <= risk_score <= 3:
        risk_level = "Moderate"
    else:
        risk_level = "High/Phishing Risk"

    return risk_level, risk_score, flags

if __name__ == "__main__":
    print("--- Basic URL Phishing Detector ---")
    print("Type 'exit' to quit.\n")
    
    while True:
        test_url = input("Enter a URL to analyze: ")
        
        if test_url.lower() == 'exit':
            break
            
        if not test_url.strip():
            continue
            
        level, score, detected_flags = analyze_url(test_url)
        
        print("\n--- Analysis Results ---")
        print(f"URL: {test_url}")
        print(f"Risk Level: {level}")
        print(f"Risk Score: {score}")
        
        if detected_flags:
            print("\nDetected Flags:")
            for flag in detected_flags:
                print(f"- {flag}")
        else:
            print("\nNo suspicious patterns detected.")
        print("-" * 25 + "\n")