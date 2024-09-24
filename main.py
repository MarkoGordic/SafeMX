import argparse
import sys
from checkers import check_spf, check_dmarc, check_dkim

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f"Error: {message}\n")
        self.print_help()
        sys.exit(2)

def main():
    parser = CustomArgumentParser(
        description="Check domain's SPF, DMARC, and DKIM records."
    )
    
    parser.add_argument('domain', type=str, help="The domain to check")
    parser.add_argument('-spf', action='store_true', help="Check SPF record")
    parser.add_argument('-dmarc', action='store_true', help="Check DMARC record")
    parser.add_argument('-dkim', action='store_true', help="Check DKIM record")
    parser.add_argument('-selector', type=str, help="DKIM selector for DKIM check (required if using -dkim)", default="default")
    
    args = parser.parse_args()
    
    if not any([args.spf, args.dmarc, args.dkim]):
        print("No check option provided, use -spf, -dmarc, or -dkim flags.")
        parser.print_help()
        sys.exit(1)
    
    if args.spf:
        check_spf(args.domain)
    
    if args.dmarc:
        check_dmarc(args.domain)
    
    if args.dkim:
        check_dkim(args.domain, args.selector)

if __name__ == "__main__":
    main()
