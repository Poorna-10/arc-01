from utils import print_banner
from password_checker import PasswordChecker
from email_checker import check_email_breach
from hash_identifier import SecurityChecker

def main():
    print_banner()
    checker = PasswordChecker()
    security_checker = SecurityChecker()

    # Preset sample inputs to avoid input() in non-interactive environments
    print("\n[+] Checking sample password strength...")
    password = "P@ssw0rd123!"
    result = checker.check_strength(password)

    if result['is_strong']:
        print("Strong password!")
    else:
        print("\nIssues found:")
        for issue in result['issues']:
            print(f"- {issue}")

        print("\nSuggestions:")
        for suggestion in result['suggestions']:
            print(f"- {suggestion}")

        print(f"\nEntropy Score: {result['entropy_score']}/100")

    if result['wordlist_check']['found']:
        print(f"\nWARNING: Password found in wordlist: {result['wordlist_check']['wordlist']}")

    print("\n[+] Checking sample email for breach...")
    sample_email = "example@example.com"
    check_email_breach(sample_email)

    print("\n[+] Identifying hash type...")
    sample_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    security_checker.identify_hash(sample_hash)

    print("\n[✓] Script completed successfully.")

if __name__ == "__main__":
    main()
