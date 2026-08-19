import dns.resolver
import dns.reversename


resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '8.8.4.4']


def get_a_records(domain):
    try:
        answers = resolver.resolve(domain, 'A')
        for answer in answers:
            print(f"  A Record: {answer}")
    except dns.resolver.NoAnswer:
        print("  A Record: No records found")
    except dns.resolver.NXDOMAIN:
        print("  Domain does not exist")
    except Exception as e:
        print(f"  A Record: Error - {e}")

def get_aaaa_records(domain):
    try:
        answers = resolver.resolve(domain, 'AAAA')
        for answer in answers:
            print(f"  AAAA Record: {answer}")
    except dns.resolver.NoAnswer:
        print("  AAAA Record: No records found")
    except dns.resolver.NXDOMAIN:
        print("  Domain does not exist")
    except Exception as e:
        print(f"  AAAA Record: Error - {e}")

def get_mx_records(domain):
    try:
        answers = resolver.resolve(domain, 'MX')
        for answer in answers:
            print(f"  MX Record: {answer}")
    except dns.resolver.NoAnswer:
        print("  MX Record: No records found")
    except dns.resolver.NXDOMAIN:
        print("  Domain does not exist")
    except Exception as e:
        print(f"  MX Record: Error - {e}")

def get_ns_records(domain):
    try:
        answers = resolver.resolve(domain, 'NS')
        for answer in answers:
            print(f"  NS Record: {answer}")
    except dns.resolver.NoAnswer:
        print("  NS Record: No records found")
    except dns.resolver.NXDOMAIN:
        print("  Domain does not exist")
    except Exception as e:
        print(f"  NS Record: Error - {e}")

def get_txt_records(domain):
    try:
        answers = resolver.resolve(domain, 'TXT')
        for answer in answers:
            print(f"  TXT Record: {answer}")
    except dns.resolver.NoAnswer:
        print("  TXT Record: No records found")
    except dns.resolver.NXDOMAIN:
        print("  Domain does not exist")
    except Exception as e:
        print(f"  TXT Record: Error - {e}")

def get_cname_records(domain):
    try:
        answers = resolver.resolve(domain, 'CNAME')
        for answer in answers:
            print(f"  CNAME Record: {answer}")
    except dns.resolver.NoAnswer:
        print("  CNAME Record: No records found")
    except dns.resolver.NXDOMAIN:
        print("  Domain does not exist")
    except Exception as e:
        print(f"  CNAME Record: Error - {e}")

def reverse_lookup(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, 'PTR')
        for answer in answers:
            print(f"  PTR Record: {answer}")
    except Exception as e:
        print(f"  Reverse DNS: Error - {e}")


print()
print("DNS LOOKUP TOOL")
print()
print("1. Domain lookup")
print("2. Reverse lookup (IP to hostname)")
choice = input("Pick (1 or 2): ")

if choice == "1":
    domain = input("Enter domain: ")
    print(f"\nDNS Lookup for {domain}")
    get_a_records(domain)
    get_aaaa_records(domain)
    get_mx_records(domain)
    get_ns_records(domain)
    get_txt_records(domain)
    get_cname_records(domain)
elif choice == "2":
    ip = input("Enter IP address: ")
    print(f"\nReverse DNS for {ip}")
    reverse_lookup(ip)
else:
    print("Invalid choice")
