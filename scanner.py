import requests

TEST_ORIGIN = "https://evil.example"

def scan_cors(url):
    headers = {
        "Origin": TEST_ORIGIN
    }

    findings = []

    try:
        response = requests.get(url, headers=headers, timeout=5)

        aca_origin = response.headers.get("Access-Control-Allow-Origin")
        aca_creds = response.headers.get("Access-Control-Allow-Credentials")

        print(f"\nScanning {url}")
        print("-" * 45)

        if aca_origin:
            print(f"Access-Control-Allow-Origin: {aca_origin}")

            if aca_origin == "*":
                findings.append("Wildcard ACAO detected (*)")

            if aca_origin == TEST_ORIGIN:
                findings.append("Reflected Origin detected (high risk)")

        else:
            print("No ACAO header present")

        if aca_creds == "true":
            print("Access-Control-Allow-Credentials: true")
            if aca_origin in ["*", TEST_ORIGIN]:
                findings.append("Credentials allowed with insecure ACAO")

        return findings

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return []

def write_report(findings):
    with open("report.txt", "w") as report:
        report.write("CORS Misconfiguration Scan Report\n")
        report.write("=" * 35 + "\n\n")

        if not findings:
            report.write("No obvious CORS misconfigurations detected.\n")
        else:
            for finding in findings:
                report.write(f"- {finding}\n")

if __name__ == "__main__":
    target = input("Enter target URL (e.g. https://example.com): ")
    results = scan_cors(target)
    write_report(results)
    print("\nScan complete. Results written to report.txt")

