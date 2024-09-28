spf_tag_explanations = {
    'v': 'This indicates the SPF version being used. "v=spf1" is required for a valid SPF record.',
    'ip4': 'This IP address is authorized to send emails on behalf of the domain.',
    'ip6': 'This IP address is authorized to send emails on behalf of the domain.',
    'include': 'The domain included is authorized to send emails on behalf of this domain. SPF checks for the included domain will also be performed.',
    'redirect': 'This redirects SPF checks to another domain, as if its SPF record is being used here.',
    'exp': 'This allows for a custom explanation if the SPF check fails, providing further information.',
    'all': {
        '-all': 'Any server not explicitly allowed will be rejected.',
        '~all': 'Emails from unauthorized servers will be marked as suspicious.',
        '?all': 'No definitive action will be taken for non-matching servers.',
        '+all': '[!] Warning: This allows emails from any server and is usually a misconfiguration.'
    },
    'a': 'Authorizes the domain\'s A or AAAA records to send emails on behalf of this domain.',
    'mx': 'Authorizes the domain\'s MX servers to send emails on behalf of this domain.',
    'ptr': 'Matches if the client IP has a PTR record pointing to a domain name ending in the specified domain.',
    'exists': 'Matches if a DNS lookup on the specified domain returns a result.'
}

dmarc_tag_explanations = {
    'v': 'The DMARC version should always be "DMARC1". A missing or incorrect version causes the record to be ignored.',
    'p': {
        'none': 'No action taken for emails that fail DMARC checks.',
        'quarantine': 'Emails that fail DMARC checks are treated as suspicious (usually moved to spam).',
        'reject': 'Emails that fail DMARC checks are outright rejected.'
    },
    'adkim': {
        'r': 'Relaxed alignment for DKIM. Allows common organizational domains.',
        's': 'Strict alignment for DKIM. Requires exact matching of domains.'
    },
    'aspf': {
        'r': 'Relaxed alignment for SPF. Allows common organizational domains.',
        's': 'Strict alignment for SPF. Requires exact matching of domains.'
    },
    'sp': {
        'none': 'No action taken for subdomains.',
        'quarantine': 'Subdomain emails that fail DMARC checks are treated as suspicious.',
        'reject': 'Subdomain emails that fail DMARC checks are outright rejected.'
    },
    'fo': {
        '0': 'Forensic reports generated if both SPF and DKIM fail.',
        '1': 'Forensic reports generated if any mechanism fails.',
        'd': 'Forensic reports generated if DKIM fails.',
        's': 'Forensic reports generated if SPF fails.'
    },
    'ruf': 'The URI where forensic reports are sent.',
    'rua': 'The URI where aggregate XML reports are sent.',
    'rf': {
        'afrf': 'Format for forensic reports (default).',
        'iodef': 'Incident Object Description Exchange Format for reports.'
    },
    'pct': 'The percentage of messages that should be subjected to the DMARC policy.',
    'ri': 'The reporting interval for aggregate reports (default: 86400 seconds = 1 day).'
}

dkim_tag_explanations = {
    'v': 'This indicates the DKIM version being used. "v=DKIM1" is required for a valid DKIM record.',
    'p': 'The public key used for verifying emails signed with the corresponding private key. It ensures the authenticity of the email.',
    'selector': 'The DKIM selector, which is used to differentiate between multiple keys that may exist for the same domain.',
    'ttl': 'Time to live (TTL) indicates how long this record is valid before it needs to be refreshed.'
}