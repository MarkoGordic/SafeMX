import dns.resolver
from colorama import Fore, Style
from safemx.parsers import parse_spf_record, parse_dmarc_record, parse_dkim_record

def check_spf(domain, output_format='console'):
    spf_data = {}
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            record = str(rdata).strip('"')

            if 'v=spf1' in record:
                if output_format == 'console':
                    print(f"{Fore.GREEN}[+] SPF record for {domain} found!{Style.RESET_ALL}")
                    print(f"    spf: {record}\n")

                spf_data = parse_spf_record(record, output_format)
                return spf_data
        if output_format == 'console':
            print(f"{Fore.RED}[!] No SPF record found for {domain}{Style.RESET_ALL}! Careful! Attackers can send emails on behalf of this domain.")
        else:
            spf_data['error'] = f"No SPF record found for {domain}"
            spf_data['error_code'] = "NO_SPF"
    except dns.resolver.NoAnswer:
        if output_format == 'console':
            print(f"{Fore.RED}[!] No SPF record found for {domain}{Style.RESET_ALL}")
        else:
            spf_data['error'] = f"No SPF record found for {domain}"
            spf_data['error_code'] = "NO_SPF"
    except dns.resolver.NXDOMAIN:
        if output_format == 'console':
            print(f"{Fore.RED}[!] Domain {domain} does not exist.{Style.RESET_ALL}")
        else:
            spf_data['error'] = f"Domain {domain} does not exist."
            spf_data['error_code'] = "NXDOMAIN"
    except Exception as e:
        if output_format == 'console':
            print(f"{Fore.RED}[!] An error occurred while retrieving SPF: {e}{Style.RESET_ALL}")
        else:
            spf_data['error'] = f"An error occurred while retrieving SPF: {e}"
            spf_data['error_code'] = "UNKNOWN"
    return spf_data

def check_dmarc(domain, output_format='console'):
    dmarc_data = {}
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            record = str(rdata).strip('"')
            if 'v=DMARC1' in record:
                if output_format == 'console':
                    print(f"{Style.BRIGHT}{Fore.GREEN}[+] DMARC record for {domain} found!{Style.RESET_ALL}")
                    print(f"    dmarc: {record}\n")

                dmarc_data = parse_dmarc_record(record, output_format)
                return dmarc_data
        if output_format == 'console':
            print(f"{Style.BRIGHT}{Fore.RED}[!] No DMARC record found for {domain}{Style.RESET_ALL}")
        else:
            dmarc_data['error'] = f"No DMARC record found for {domain}"
            dmarc_data['error_code'] = "NO_DMARC"
    except dns.resolver.NoAnswer:
        if output_format == 'console':
            print(f"{Style.BRIGHT}{Fore.RED}[!] No DMARC record found for {domain}{Style.RESET_ALL}")
        else:
            dmarc_data['error'] = f"No DMARC record found for {domain}"
            dmarc_data['error_code'] = "NO_DMARC"
    except dns.resolver.NXDOMAIN:
        if output_format == 'console':
            print(f"{Style.BRIGHT}{Fore.RED}[!] Domain {domain} does not exist.{Style.RESET_ALL}")
        else:
            dmarc_data['error'] = f"Domain {domain} does not exist."
            dmarc_data['error_code'] = "NXDOMAIN"
    except Exception as e:
        if output_format == 'console':
            print(f"{Style.BRIGHT}{Fore.RED}[!] An error occurred while retrieving DMARC: {e}{Style.RESET_ALL}")
        else:
            dmarc_data['error'] = f"An error occurred while retrieving DMARC: {e}"
            dmarc_data['error_code'] = "UNKNOWN"
    return dmarc_data

def check_dkim(domain, selector, output_format='console'):
    dkim_data = {}
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            record = str(rdata).strip('"')
            if 'v=DKIM1' in record:
                if output_format == 'console':
                    print(f"{Style.BRIGHT}{Fore.GREEN}[+] DKIM record for {domain} found with selector '{selector}'!{Style.RESET_ALL}")
                    print(f"    dkim: {record}\n")

                dkim_data = parse_dkim_record(record, output_format)
                return dkim_data
        if output_format == 'console':
            print(f"{Style.BRIGHT}{Fore.RED}[!] No DKIM record found for {domain} with selector '{selector}'{Style.RESET_ALL}")
        else:
            dkim_data['error'] = f"No DKIM record found for {domain} with selector '{selector}'"
            dkim_data['error_code'] = "NO_DKIM"
    except dns.resolver.NoAnswer:
        if output_format == 'console':
            print(f"{Style.BRIGHT}{Fore.RED}[!] No DKIM record found for {domain} with selector '{selector}'{Style.RESET_ALL}")
        else:
            dkim_data['error'] = f"No DKIM record found for {domain} with selector '{selector}'"
            dkim_data['error_code'] = "NO_DKIM"
    except dns.resolver.NXDOMAIN:
        if output_format == 'console':
            print(f"{Style.BRIGHT}{Fore.RED}[!] Domain {domain} does not exist.{Style.RESET_ALL}")
        else:
            dkim_data['error'] = f"Domain {domain} does not exist."
            dkim_data['error_code'] = "NXDOMAIN"
    except Exception as e:
        if output_format == 'console':
            print(f"{Style.BRIGHT}{Fore.RED}[!] An error occurred while retrieving DKIM: {e}{Style.RESET_ALL}")
        else:
            dkim_data['error'] = f"An error occurred while retrieving DKIM: {e}"
            dkim_data['error_code'] = "UNKNOWN"
    return dkim_data
