from colorama import Fore, Style, init
from safemx.explanations import spf_tag_explanations, dmarc_tag_explanations, dkim_tag_explanations

def parse_spf_record(spf_record, output_format='console'):
    spf_parts = spf_record.split()
    spf_data = {
        'record': spf_record,
        'version': None,
        'mechanisms': [],
        'modifiers': [],
        'notes': []
    }

    ip_detected = False
    include_detected = False
    all_detected = False
    redirect_detected = False
    exp_detected = False
    a_detected = False
    mx_detected = False
    ptr_detected = False
    exists_detected = False

    if any(c.isupper() for c in spf_record):
        note_msg = "SPF record contains uppercase characters, which is invalid."
        spf_data['notes'].append(note_msg)
        if output_format == 'console':
            print(f"{Fore.RED}[!] {note_msg}{Style.RESET_ALL}")

    for part in spf_parts:
        if part.startswith("v="):
            spf_data['version'] = part
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.CYAN}Version Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations.get('v', 'No explanation available.')}")
        elif part.startswith("ip4:") or part.startswith("ip6:"):
            ip_detected = True
            spf_data['mechanisms'].append({'type': 'ip', 'value': part})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.GREEN}IP Address Detected:{Style.RESET_ALL} {part}")
                tag = part.split(':')[0]
                explanation = spf_tag_explanations.get(tag, 'No explanation available.')
                print(f"        [i] {explanation}")
        elif part == "a" or part.startswith("a:") or part.startswith("a/"):
            a_detected = True
            mechanism = {'type': 'a', 'value': part}
            if ":" in part:
                domain = part.split(":")[1].split("/")[0]
                mechanism['domain'] = domain
                if "/" in part:
                    prefix_length = part.split("/")[1]
                    mechanism['prefix_length'] = prefix_length
                    if output_format == 'console':
                        print(f"    {Style.BRIGHT}{Fore.BLUE}'a' Mechanism with Domain and Prefix Detected:{Style.RESET_ALL} {part}")
                        print(f"        Domain: {domain}, Prefix Length: {prefix_length}")
                else:
                    if output_format == 'console':
                        print(f"    {Style.BRIGHT}{Fore.BLUE}'a' Mechanism with Domain Detected:{Style.RESET_ALL} {part}")
                        print(f"        Domain: {domain}")
            elif "/" in part:
                prefix_length = part.split("/")[1]
                mechanism['prefix_length'] = prefix_length
                if output_format == 'console':
                    print(f"    {Style.BRIGHT}{Fore.BLUE}'a' Mechanism with Prefix Detected:{Style.RESET_ALL} {part}")
                    print(f"        Prefix Length: {prefix_length}")
            spf_data['mechanisms'].append(mechanism)
        elif part.startswith("mx"):
            mx_detected = True
            spf_data['mechanisms'].append({'type': 'mx', 'value': part})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.BLUE}'mx' Mechanism Detected:{Style.RESET_ALL} {part}")
        elif part.startswith("ptr"):
            ptr_detected = True
            spf_data['mechanisms'].append({'type': 'ptr', 'value': part})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.BLUE}'ptr' Mechanism Detected:{Style.RESET_ALL} {part}")
        elif part.startswith("exists:"):
            exists_detected = True
            spf_data['mechanisms'].append({'type': 'exists', 'value': part})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.BLUE}'exists' Mechanism Detected:{Style.RESET_ALL} {part}")
        elif part.startswith("include:") or part.startswith("+include:"):
            include_detected = True
            domain = part.split(":", 1)[1]
            spf_data['mechanisms'].append({'type': 'include', 'value': part, 'domain': domain})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.YELLOW}Include Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations.get('include', 'No explanation available.')}")
        elif part.startswith("redirect="):
            redirect_detected = True
            redirect_domain = part.split("=", 1)[1]
            spf_data['modifiers'].append({'type': 'redirect', 'value': part, 'domain': redirect_domain})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.YELLOW}Redirect Modifier Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations.get('redirect', 'No explanation available.')}")
        elif part.startswith("exp="):
            exp_detected = True
            exp_domain = part.split("=", 1)[1]
            spf_data['modifiers'].append({'type': 'exp', 'value': part, 'domain': exp_domain})
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.YELLOW}Explanation Modifier Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {spf_tag_explanations.get('exp', 'No explanation available.')}")
        elif part in ["-all", "~all", "?all", "+all"]:
            all_detected = True
            spf_data['mechanisms'].append({'type': 'all', 'value': part})
            if output_format == 'console':
                all_type = spf_tag_explanations.get('all', {}).get(part, f"Unknown 'all' type: {part}")
                explanation = spf_tag_explanations.get('all', {}).get(part, 'No explanation available.')
                print(f"    {Style.BRIGHT}{Fore.MAGENTA}{all_type} Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {explanation}")
        else:
            spf_data['mechanisms'].append({'type': 'other', 'value': part})
            if output_format == 'console':
                explanation = spf_tag_explanations.get(part.split(':')[0], 'Unknown mechanism')
                print(f"    {Style.BRIGHT}{Fore.BLUE}Other Mechanism Detected:{Style.RESET_ALL} {part}")
                print(f"        [i] {explanation}")

    if not ip_detected:
        spf_data['mechanisms'].append({'type': 'ip', 'value': None})
        if output_format == 'console':
            print(f"{Fore.RED}[!] Missing IP mechanism (ip4: or ip6:). Add an IP address mechanism.{Style.RESET_ALL}")

    if not a_detected:
        spf_data['mechanisms'].append({'type': 'a', 'value': None})
        if output_format == 'console':
            print(f"{Fore.RED}[!] Missing 'a' mechanism. Consider adding it for better SPF coverage.{Style.RESET_ALL}")

    if not mx_detected:
        spf_data['mechanisms'].append({'type': 'mx', 'value': None})
        if output_format == 'console':
            print(f"{Fore.RED}[!] Missing 'mx' mechanism. Consider adding it for better SPF coverage.{Style.RESET_ALL}")

    if not ptr_detected:
        spf_data['mechanisms'].append({'type': 'ptr', 'value': None})
        if output_format == 'console':
            print(f"{Fore.RED}[!] Missing 'ptr' mechanism. Consider adding it if necessary.{Style.RESET_ALL}")

    if not exists_detected:
        spf_data['mechanisms'].append({'type': 'exists', 'value': None})
        if output_format == 'console':
            print(f"{Fore.RED}[!] Missing 'exists' mechanism. Consider adding it if necessary.{Style.RESET_ALL}")

    if not include_detected:
        spf_data['mechanisms'].append({'type': 'include', 'value': None})
        if output_format == 'console':
            print(f"{Fore.RED}[!] Missing 'include' mechanism. Consider adding it if necessary.{Style.RESET_ALL}")

    if not all_detected and not redirect_detected:
        spf_data['mechanisms'].append({'type': 'all', 'value': None})
        if output_format == 'console':
            print(f"{Fore.YELLOW}[!] Missing 'all' or 'redirect=' mechanism. Add one to complete the SPF record.{Style.RESET_ALL}")

    if not redirect_detected:
        spf_data['modifiers'].append({'type': 'redirect', 'value': None})
        if output_format == 'console':
            print(f"{Fore.YELLOW}[!] Missing 'redirect=' modifier. Consider adding it if necessary.{Style.RESET_ALL}")

    if not exp_detected:
        spf_data['modifiers'].append({'type': 'exp', 'value': None})
        if output_format == 'console':
            print(f"{Fore.YELLOW}[!] Missing 'exp=' modifier. Consider adding it if necessary.{Style.RESET_ALL}")

    if output_format == 'console':
        print(f"{Style.BRIGHT}{Fore.CYAN}SPF Record Analysis Complete.{Style.RESET_ALL}")

    return spf_data

def parse_dmarc_record(dmarc_record, output_format='console'):
    dmarc_parts = dmarc_record.split(';')
    dmarc_data = {
        'record': dmarc_record,
        'fields': {},
        'notes': []
    }

    fields = ['v', 'p', 'adkim', 'aspf', 'sp', 'fo', 'ruf', 'rua', 'rf', 'pct', 'ri']

    for part in dmarc_parts:
        key_value = part.strip().split('=')
        if len(key_value) == 2:
            key, value = key_value[0].strip(), key_value[1].strip()
            dmarc_data['fields'][key] = value

            if output_format == 'console':
                if key == 'v':
                    print(f"    {Style.BRIGHT}{Fore.CYAN}Version Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {dmarc_tag_explanations.get('v', 'No explanation available.')}")
                elif key == 'p':
                    policy_explanation = dmarc_tag_explanations.get('p', {}).get(value, f"Unknown policy: {value}")
                    print(f"    {Style.BRIGHT}{Fore.GREEN}Policy Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {policy_explanation}")
                elif key == 'adkim':
                    alignment_explanation = dmarc_tag_explanations.get('adkim', {}).get(value, f"Unknown alignment: {value}")
                    print(f"    {Style.BRIGHT}{Fore.YELLOW}DKIM Alignment Mode Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {alignment_explanation}")
                elif key == 'aspf':
                    alignment_explanation = dmarc_tag_explanations.get('aspf', {}).get(value, f"Unknown alignment: {value}")
                    print(f"    {Style.BRIGHT}{Fore.YELLOW}SPF Alignment Mode Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {alignment_explanation}")
                elif key == 'sp':
                    sp_explanation = dmarc_tag_explanations.get('sp', {}).get(value, f"Unknown subdomain policy: {value}")
                    print(f"    {Style.BRIGHT}{Fore.GREEN}Subdomain Policy Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {sp_explanation}")
                elif key == 'fo':
                    fo_explanation = dmarc_tag_explanations.get('fo', {}).get(value, f"Unknown forensic reporting option: {value}")
                    print(f"    {Style.BRIGHT}{Fore.MAGENTA}Forensic Options Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {fo_explanation}")
                elif key == 'ruf':
                    print(f"    {Style.BRIGHT}{Fore.BLUE}Forensic Reports URI Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {dmarc_tag_explanations.get('ruf', 'No explanation available.')}")
                elif key == 'rua':
                    print(f"    {Style.BRIGHT}{Fore.BLUE}Aggregate Reports URI Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {dmarc_tag_explanations.get('rua', 'No explanation available.')}")
                elif key == 'rf':
                    rf_explanation = dmarc_tag_explanations.get('rf', {}).get(value, f"Unknown report format: {value}")
                    print(f"    {Style.BRIGHT}{Fore.BLUE}Reporting Format Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {rf_explanation}")
                elif key == 'pct':
                    print(f"    {Style.BRIGHT}{Fore.MAGENTA}Percentage Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] {dmarc_tag_explanations.get('pct', 'No explanation available.')} {value}% of emails will be subject to DMARC filtering.")
                elif key == 'ri':
                    print(f"    {Style.BRIGHT}{Fore.MAGENTA}Reporting Interval Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"    [i] Reporting interval is {value} seconds (default is 86400 seconds = 1 day).")

    for field in fields:
        if field not in dmarc_data['fields']:
            dmarc_data['fields'][field] = None
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.RED}Missing Field Detected:{Style.RESET_ALL} {field}=None")

    if output_format == 'console':
        print(f"{Style.BRIGHT}{Fore.CYAN}DMARC Record Analysis Complete.{Style.RESET_ALL}")

    return dmarc_data

def parse_dkim_record(dkim_record, output_format='console'):
    dkim_parts = dkim_record.split(';')
    dkim_data = {
        'record': dkim_record,
        'fields': {},
    }

    fields = ['v', 'p', 'k', 's']

    for part in dkim_parts:
        key_value = part.strip().split('=')
        if len(key_value) == 2:
            key, value = key_value[0].strip(), key_value[1].strip()
            dkim_data['fields'][key] = value

            if output_format == 'console':
                if key == 'v':
                    print(f"    {Style.BRIGHT}{Fore.CYAN}Version Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"        [i] {dkim_tag_explanations.get('v', 'Unknown version')}")
                elif key == 'p':
                    print(f"    {Style.BRIGHT}{Fore.GREEN}Public Key Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"        [i] {dkim_tag_explanations.get('p', 'Unknown public key')}")
                else:
                    print(f"    {Style.BRIGHT}{Fore.BLUE}Other Mechanism Detected:{Style.RESET_ALL} {key}={value}")
                    print(f"        [i] {dkim_tag_explanations.get(key, 'Unknown DKIM mechanism')}")

    for field in fields:
        if field not in dkim_data['fields']:
            dkim_data['fields'][field] = None
            if output_format == 'console':
                print(f"    {Style.BRIGHT}{Fore.RED}Missing Field Detected:{Style.RESET_ALL} {field}=None")

    if output_format == 'console':
        print(f"{Style.BRIGHT}{Fore.CYAN}DKIM Record Analysis Complete.{Style.RESET_ALL}")

    return dkim_data
