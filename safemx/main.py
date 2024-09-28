import argparse
import sys
from safemx.checkers import check_spf, check_dmarc, check_dkim
from colorama import Fore, Style, init
import json

init(autoreset=True)

def display_banner():
    banner = r"""
  ________     __       _______   _______  ___      ___  ___  ___  
 /"       )   /""\     /"     "| /"     "||"  \    /"  ||"  \/"  | 
(:   \___/   /    \   (: ______)(: ______) \   \  //   | \   \  /  
 \___  \    /' /\  \   \/    |   \/    |   /\\  \/.    |  \\  \/   
  __/  \\  //  __'  \  // ___)   // ___)_ |: \.        |  /\.  \   
 /" \   :)/   /  \\  \(:  (     (:      "||.  \    /:  | /  \   \  
(_______/(___/    \___)\__/      \_______)|___|\__/|___||___/\___| 
                                                                   
    """
    print(Fore.MAGENTA + banner + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(
        description="Check domain's SPF, DMARC, and DKIM records.",
        usage='main.py [-h] [-spf] [-dmarc] [-dkim] [-selector SELECTOR] [--output OUTPUT] domain'
    )

    parser.add_argument('domain', help="The domain to check")
    parser.add_argument('-spf', action='store_true', help="Check SPF record")
    parser.add_argument('-dmarc', action='store_true', help="Check DMARC record")
    parser.add_argument('-dkim', action='store_true', help="Check DKIM record")
    parser.add_argument('-selector', type=str, help="DKIM selector for DKIM check")
    parser.add_argument('--output', choices=['console', 'json'], default='console', help='Output format')
    parser.add_argument('--outfile', type=str, help="Output file for JSON results", default='output.json')

    args = parser.parse_args()

    display_banner()

    if not any([args.spf, args.dmarc, args.dkim]):
        print("No check option provided, use -spf, -dmarc, or -dkim flags.")
        parser.print_help()
        sys.exit(1)

    output_data = {}

    if args.spf:
        spf_data = check_spf(args.domain, args.output)
        if args.output == 'json':
            output_data['spf'] = spf_data

    if args.dmarc:
        dmarc_data = check_dmarc(args.domain, args.output)
        if args.output == 'json':
            output_data['dmarc'] = dmarc_data

    if args.dkim:
        if args.selector is None:
            print(f"{Style.BRIGHT}{Fore.YELLOW}[!] No DKIM selector provided. Proceeding with default selector 'default'{Style.RESET_ALL}")
            args.selector = 'default'
        dkim_data = check_dkim(args.domain, args.selector, args.output)
        if args.output == 'json':
            output_data['dkim'] = dkim_data

    if args.output == 'json':
        with open(args.outfile, 'w') as json_file:
            json.dump(output_data, json_file, indent=4)
        print(f"JSON output written to {args.outfile}")

if __name__ == "__main__":
    main()
