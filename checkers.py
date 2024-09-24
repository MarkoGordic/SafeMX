import dns.resolver
from colorama import Fore, Style
from parsers import parse_spf_record

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            record = str(rdata).strip('"')

            if 'v=spf1' in record:
                print(f"{Fore.GREEN}[+] SPF record for {domain} found!{Style.RESET_ALL}")
                print(f"    spf: {record}\n")

                parse_spf_record(str(record))
                return
        print(f"{Fore.RED}[!] No SPF record found for {domain}{Style.RESET_ALL}! Careful! Attackers can send emails on behalf of this domain.")
    except dns.resolver.NoAnswer:
        print(f"{Fore.RED}[!] No SPF record found for {domain}{Style.RESET_ALL}")
    except dns.resolver.NXDOMAIN:
        print(f"{Fore.RED}[!] Domain {domain} does not exist.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred while retrieving SPF: {e}{Style.RESET_ALL}")

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            if 'v=DMARC1' in str(rdata):
                print(f"DMARC record for {domain}: {rdata}")
                return
        print(f"No DMARC record found for {domain}")
    except dns.resolver.NoAnswer:
        print(f"No DMARC record found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist.")
    except Exception as e:
        print(f"An error occurred while retrieving DMARC: {e}")

def check_dkim(domain, selector):
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            print(f"DKIM record for {domain} with selector {selector}: {rdata}")
            return
        print(f"No DKIM record found for {domain}")
    except dns.resolver.NoAnswer:
        print(f"No DKIM record found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist.")
    except Exception as e:
        print(f"An error occurred while retrieving DKIM: {e}")
