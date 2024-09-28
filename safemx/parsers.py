from colorama import Fore, Style, init
from safemx.explanations import spf_tag_explanations, dmarc_tag_explanations, dkim_tag_explanations

def parse_spf_record(spf_record, output_format='console'):
    spf_parts = spf_record.split()
    spf_data = {
        'record': spf_record,
        'version': None,
        'mechanisms': [],
        'warnings': [],
        'notes': []
    }

    version_detected = False
    ip_detected = False
    include_detected = False
    all_detected = False
    redirect_detected = False

    if any(c.isupper() for c in spf_record):
        warning_msg = "SPF record contains uppercase characters, which is invalid."
        spf_data['warnings'].append(warning_msg)
        if output_format == 'console':
            print(f"{Fore.RED}[!] {warning_msg}{Style.RESET_ALL}")

    for part in spf_parts:
        if part.startswith("v="):
            version_detected = True
            spf_data['version'] = part
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.CYAN}Version Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations['v']}")
        elif part.startswith("ip4:") or part.startswith("ip6:"):
            ip_detected = True
            spf_data['mechanisms'].append({'type': 'ip', 'value': part})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.GREEN}IP Address Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations[part.split(':')[0]]}")
        elif part.startswith("include:") or part.startswith("+include:"):
            include_detected = True
            domain = part.split(":", 1)[1]
            spf_data['mechanisms'].append({'type': 'include', 'value': part, 'domain': domain})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.YELLOW}Include Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations['include']}")
        elif part.startswith("redirect="):
            redirect_detected = True
            redirect_domain = part.split("=", 1)[1]
            spf_data['mechanisms'].append({'type': 'redirect', 'value': part, 'domain': redirect_domain})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.YELLOW}Redirect Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations['redirect']}")
        elif part in ["-all", "~all", "?all", "+all"]:
            all_detected = True
            spf_data['mechanisms'].append({'type': 'all', 'value': part})
            if output_format == 'console':
                all_type = spf_tag_explanations['all'].get(part, f"Unknown 'all' type: {part}")
                print(f"    {Style.BRIGHT}{Fore.MAGENTA}{all_type} Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations['all'][part]}")
        else:
            spf_data['mechanisms'].append({'type': 'other', 'value': part})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.BLUE}Other Mechanism Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations.get(part.split(':')[0], 'Unknown mechanism')}")

    if not version_detected:
        warning_msg = "SPF version not detected. This SPF record may be invalid without 'v=spf1'."
        spf_data['warnings'].append(warning_msg)
        if output_format == 'console':
            print(f"{Fore.RED}[!] {warning_msg}{Style.RESET_ALL}")
    
    if not ip_detected and not include_detected:
        warning_msg = "No IP or Include mechanisms detected. Your SPF record may not properly authorize any servers."
        spf_data['warnings'].append(warning_msg)
        if output_format == 'console':
            print(f"{Fore.RED}[!] {warning_msg}{Style.RESET_ALL}")

    if not all_detected and not redirect_detected:
        note_msg = "No 'all' or 'redirect=' mechanism detected. It's recommended to end SPF records with one of these."
        spf_data['notes'].append(note_msg)
        if output_format == 'console':
            print(f"{Fore.YELLOW}[!] {note_msg}{Style.RESET_ALL}")

    if output_format == 'console':
        print(f"{Style.BRIGHT}{Fore.CYAN}SPF Record Analysis Complete.{Style.RESET_ALL}")
    
    return spf_data

def parse_dmarc_record(dmarc_record, output_format='console'):
    dmarc_parts = dmarc_record.split(';')
    dmarc_data = {
        'record': dmarc_record,
        'fields': {},
        'warnings': [],
        'notes': []
    }

    for part in dmarc_parts:
        key_value = part.strip().split('=')
        if len(key_value) == 2:
            key, value = key_value[0].strip(), key_value[1].strip()
            dmarc_data['fields'][key] = value

            if output_format == 'console':
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

    if output_format == 'console':
        print(f"{Style.BRIGHT}{Fore.CYAN}DMARC Record Analysis Complete.{Style.RESET_ALL}")
    
    return dmarc_data

def parse_dkim_record(dkim_record, output_format='console'):
    dkim_parts = dkim_record.split(';')
    dkim_data = {
        'record': dkim_record,
        'fields': {},
        'warnings': [],
        'notes': []
    }

    for part in dkim_parts:
        key_value = part.strip().split('=')
        if len(key_value) == 2:
            key, value = key_value[0].strip(), key_value[1].strip()
            dkim_data['fields'][key] = value

            if output_format == 'console':
                if key == 'v':
                    print(f"    {Style.BRIGHT}{Fore.CYAN}Version Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"        [i] {dkim_tag_explanations['v']}")
                elif key == 'p':
                    print(f"    {Style.BRIGHT}{Fore.GREEN}Public Key Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"        [i] {dkim_tag_explanations['p']}")
                else:
                    print(f"    {Style.BRIGHT}{Fore.BLUE}Other Mechanism Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"        [i] Unknown or unhandled DKIM mechanism.")

    if output_format == 'console':
        print(f"{Style.BRIGHT}{Fore.CYAN}DKIM Record Analysis Complete.{Style.RESET_ALL}")
    
    return dkim_data
