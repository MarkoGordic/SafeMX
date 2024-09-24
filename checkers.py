import dns.resolver

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in str(rdata):
                print(f"SPF record for {domain}: {rdata}")
                return
        print(f"No SPF record found for {domain}")
    except dns.resolver.NoAnswer:
        print(f"No SPF record found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist.")
    except Exception as e:
        print(f"An error occurred while retrieving SPF: {e}")

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
