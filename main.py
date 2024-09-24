import argparse
import sys
from checkers import check_spf, check_dmarc, check_dkim
from colorama import Fore, Style, init

init(autoreset=True)

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f"Error: {message}\n")
        self.print_help()
        sys.exit(2)

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
        description=Fore.GREEN + "Check domain's SPF, DMARC, and DKIM records." + Style.RESET_ALL,
        usage=Fore.YELLOW + 'main.py [-h] [-spf] [-dmarc] [-dkim] [-selector SELECTOR] domain' + Style.RESET_ALL
    )
    
    parser.add_argument('domain', help=Fore.CYAN + "The domain to check" + Style.RESET_ALL)
    parser.add_argument('-spf', action='store_true', help=Fore.MAGENTA + "Check SPF record" + Style.RESET_ALL)
    parser.add_argument('-dmarc', action='store_true', help=Fore.MAGENTA + "Check DMARC record" + Style.RESET_ALL)
    parser.add_argument('-dkim', action='store_true', help=Fore.MAGENTA + "Check DKIM record" + Style.RESET_ALL)
    parser.add_argument('-selector', type=str, help=Fore.CYAN + "DKIM selector for D" + Style.RESET_ALL)
    
    args = parser.parse_args()
    
    display_banner()

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
