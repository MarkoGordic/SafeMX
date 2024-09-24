from colorama import Fore, Style, init
from explanations import spf_tag_explanations, dmarc_tag_explanations, dkim_tag_explanations

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
            print(f"        [i] {spf_tag_explanations['v']}")
        elif part.startswith("ip4:") or part.startswith("ip6:"):
            ip_detected = True
            print(f"    {Style.BRIGHT}{Fore.GREEN}IP Address Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] {spf_tag_explanations[part.split(':')[0]]}")
        elif part.startswith("include:") or part.startswith("+include:"):
            include_detected = True
            domain = part.split(":", 1)[1]
            print(f"    {Style.BRIGHT}{Fore.YELLOW}Include Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] {spf_tag_explanations['include']}")
        elif part.startswith("redirect="):
            redirect_detected = True
            redirect_domain = part.split("=", 1)[1]
            print(f"    {Style.BRIGHT}{Fore.YELLOW}Redirect Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] {spf_tag_explanations['redirect']}")
        elif part in ["-all", "~all", "?all", "+all"]:
            all_detected = True
            all_type = spf_tag_explanations['all'].get(part, f"Unknown 'all' type: {part}")
            print(f"    {Style.BRIGHT}{Fore.MAGENTA}{all_type} Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] {spf_tag_explanations['all'][part]}")
        else:
            print(f"    {Style.BRIGHT}{Fore.BLUE}Other Mechanism Detected:{Style.RESET_ALL} {part}")
            print(f"        [i] {spf_tag_explanations.get(part.split(':')[0], 'Unknown mechanism')}")

    if not version_detected:
        print(f"{Fore.RED}[!] Warning: SPF version not detected. This SPF record may be invalid without 'v=spf1'.")
    
    if not ip_detected and not include_detected:
        print(f"{Fore.RED}[!] Warning: No IP or Include mechanisms detected. Your SPF record may not properly authorize any servers.")

    if not all_detected and not redirect_detected:
        print(f"{Fore.YELLOW}[!] Notice: No 'all' or 'redirect=' mechanism detected. It's recommended to end SPF records with one of these to define the behavior for non-matching senders.")

    print(f"{Style.BRIGHT}{Fore.CYAN}SPF Record Analysis Complete.{Style.RESET_ALL}\n")

def parse_dmarc_record(dmarc_record):
    dmarc_parts = dmarc_record.split(';')

    for part in dmarc_parts:
        key_value = part.strip().split('=')
        if len(key_value) == 2:
            key, value = key_value[0].strip(), key_value[1].strip()

            if key == 'v':
                print(f"    {Style.BRIGHT}{Fore.CYAN}Version Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {dmarc_tag_explanations['v']}")
            
            elif key == 'p':
                policy_explanation = dmarc_tag_explanations['p'].get(value, f"Unknown policy: {value}")
                print(f"    {Style.BRIGHT}{Fore.GREEN}Policy Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {policy_explanation}")
            
            elif key == 'adkim':
                alignment_explanation = dmarc_tag_explanations['adkim'].get(value, f"Unknown alignment: {value}")
                print(f"    {Style.BRIGHT}{Fore.YELLOW}DKIM Alignment Mode Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {alignment_explanation}")
            
            elif key == 'aspf':
                alignment_explanation = dmarc_tag_explanations['aspf'].get(value, f"Unknown alignment: {value}")
                print(f"    {Style.BRIGHT}{Fore.YELLOW}SPF Alignment Mode Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {alignment_explanation}")
            
            elif key == 'sp':
                sp_explanation = dmarc_tag_explanations['sp'].get(value, f"Unknown subdomain policy: {value}")
                print(f"    {Style.BRIGHT}{Fore.GREEN}Subdomain Policy Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {sp_explanation}")
            
            elif key == 'fo':
                fo_explanation = dmarc_tag_explanations['fo'].get(value, f"Unknown forensic reporting option: {value}")
                print(f"    {Style.BRIGHT}{Fore.MAGENTA}Forensic Options Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {fo_explanation}")
            
            elif key == 'ruf':
                print(f"    {Style.BRIGHT}{Fore.BLUE}Forensic Reports URI Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {dmarc_tag_explanations['ruf']}")
            
            elif key == 'rua':
                print(f"    {Style.BRIGHT}{Fore.BLUE}Aggregate Reports URI Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {dmarc_tag_explanations['rua']}")
            
            elif key == 'rf':
                rf_explanation = dmarc_tag_explanations['rf'].get(value, f"Unknown report format: {value}")
                print(f"    {Style.BRIGHT}{Fore.BLUE}Reporting Format Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {rf_explanation}")
            
            elif key == 'pct':
                print(f"    {Style.BRIGHT}{Fore.MAGENTA}Percentage Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] {dmarc_tag_explanations['pct']} {value}% of emails will be subject to DMARC filtering.")
            
            elif key == 'ri':
                print(f"    {Style.BRIGHT}{Fore.MAGENTA}Reporting Interval Detected:{Style.RESET_ALL} {key}={value}")
                print(f"    [i] Reporting interval is {value} seconds (default is 86400 seconds = 1 day).")
    
    print(f"{Style.BRIGHT}{Fore.CYAN}DMARC Record Analysis Complete.{Style.RESET_ALL}\n")

def parse_dkim_record(dkim_record):
    dkim_parts = dkim_record.split(';')
    for part in dkim_parts:
        key_value = part.strip().split('=')
        if len(key_value) == 2:
            key, value = key_value[0].strip(), key_value[1].strip()

            if key == 'v':
                print(f"    {Style.BRIGHT}{Fore.CYAN}Version Detected:{Style.RESET_ALL} {key}={value}")
                print(f"        [i] {dkim_tag_explanations['v']}")
            elif key == 'p':
                print(f"    {Style.BRIGHT}{Fore.GREEN}Public Key Detected:{Style.RESET_ALL} {key}={value}")
                print(f"        [i] {dkim_tag_explanations['p']}")
            else:
                print(f"    {Style.BRIGHT}{Fore.BLUE}Other Mechanism Detected:{Style.RESET_ALL} {key}={value}")
                print(f"        [i] Unknown or unhandled DKIM mechanism.")

    print(f"{Style.BRIGHT}{Fore.CYAN}DKIM Record Analysis Complete.{Style.RESET_ALL}\n")
