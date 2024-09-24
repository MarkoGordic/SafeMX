from colorama import Fore, Style, init

def parse_spf_record(spf_record):
    spf_parts = spf_record.split()

    version_detected = False
    ip_detected = False
    include_detected = False
    all_detected = False
    redirect_detected = False

    if any(c.isupper() for c in spf_record):
        print(f"{Fore.RED}[!] Warning: SPF record contains uppercase characters, which is invalid.{Style.RESET_ALL}")
    
    for part in spf_parts:
        if part.startswith("v="):
            version_detected = True
            print(f"    {Style.BRIGHT}{Fore.CYAN}Version Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] This indicates the SPF version being used. 'v=spf1' is required for a valid SPF record.")
        elif part.startswith("ip4:") or part.startswith("ip6:"):
            ip_detected = True
            print(f"    {Style.BRIGHT}{Fore.GREEN}IP Address Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] This IP address is authorized to send emails on behalf of the domain.")
        elif part.startswith("include:") or part.startswith("+include:"):
            include_detected = True
            domain = part.split(":", 1)[1]
            print(f"    {Style.BRIGHT}{Fore.YELLOW}Include Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] The domain '{domain}' is authorized to send emails on behalf of this domain. SPF checks for {domain} will also be performed.")
        elif part.startswith("redirect="):
            redirect_detected = True
            redirect_domain = part.split("=", 1)[1]
            print(f"    {Style.BRIGHT}{Fore.YELLOW}Redirect Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] This redirects SPF checks to the domain '{redirect_domain}', as if its SPF record is being used here.")
        elif part in ["-all", "~all", "?all", "+all"]:
            all_detected = True
            if part == "-all":
                all_type = "Hard Fail (-all)"
                explanation = "Any server not explicitly allowed will be rejected."
            elif part == "~all":
                all_type = "Soft Fail (~all)"
                explanation = "Emails from unauthorized servers will be marked as suspicious."
            elif part == "?all":
                all_type = "Neutral (?all)"
                explanation = "No definitive action will be taken for non-matching servers."
            elif part == "+all":
                all_type = "Accept All (+all)"
                explanation = "[!] Warning: This allows emails from any server and is usually a misconfiguration."
            print(f"    {Style.BRIGHT}{Fore.MAGENTA}{all_type} Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] {explanation}")
        else:
            print(f"    {Style.BRIGHT}{Fore.BLUE}Other Mechanism Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] This is another SPF mechanism, such as 'mx' or 'a', which authorizes servers based on DNS records.")

    if not version_detected:
        print(f"{Fore.RED}[!] Warning: SPF version not detected. This SPF record may be invalid without 'v=spf1'.")
    
    if not ip_detected and not include_detected:
        print(f"{Fore.RED}[!] Warning: No IP or Include mechanisms detected. Your SPF record may not properly authorize any servers.")

    if not all_detected and not redirect_detected:
        print(f"{Fore.YELLOW}[!] Notice: No 'all' or 'redirect=' mechanism detected. It's recommended to end SPF records with one of these to define the behavior for non-matching senders.")

    print(f"{Style.BRIGHT}{Fore.CYAN}SPF Record Analysis Complete.{Style.RESET_ALL}")
