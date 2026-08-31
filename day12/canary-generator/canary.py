import json
import uuid
import os
from datetime import datetime

TOKENS_FILE = "tokens.json"
OUTPUT_DIR = "artifacts"
BASE_URL = "http://127.0.0.1:5000/c"   # local canary server (server.py)

# MITRE Engage deception techniques per token type
MITRE_ENGAGE = {
    "envfile":    "EAC0011 Lures / EAC0005 Decoy Credentials",
    "aws":        "EAC0005 Decoy Credentials",
    "kubeconfig": "EAC0005 Decoy Credentials",
    "webbug":     "EAC0011 Lures (beacon)",
    "docx":       "EAC0021 Decoy Content",
    "sshkey":     "EAC0005 Decoy Credentials",
}


# ---------- Registry ----------

def load_tokens():
    if os.path.exists(TOKENS_FILE):
        try:
            with open(TOKENS_FILE, 'r') as f:
                content = f.read().strip()
                return json.loads(content) if content else []
        except json.JSONDecodeError:
            return []
    return []


def save_tokens(tokens):
    with open(TOKENS_FILE, 'w') as f:
        json.dump(tokens, f, indent=2)


def create_token(token_type, memo):
    token_id = str(uuid.uuid4())[:8]
    return {
        "id": token_id,
        "type": token_type,
        "memo": memo,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "trigger_url": f"{BASE_URL}/{token_id}",
        "mitre_engage": MITRE_ENGAGE.get(token_type, "EAC0005 Decoy Credentials"),
        "triggered": False,
        "triggers": []
    }


# ---------- Artifact generators ----------

def gen_envfile(token):
    return f"""# Application configuration
NODE_ENV=production
PORT=8080
DATABASE_URL=postgres://appuser:Xk92mLp4@db.internal:5432/maindb
REDIS_URL=redis://cache.internal:6379
AWS_ACCESS_KEY_ID=AKIAJQ7EXAMPLEFAKE00
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIfake0KEYfakeEXAMPLEKEY0000
STRIPE_KEY=sk_test_fake0000000000000000000000
INTERNAL_METRICS_ENDPOINT={token['trigger_url']}
JWT_SECRET=fake0jwt0secret0value0000000000000
"""


def gen_aws_creds(token):
    return f"""[default]
aws_access_key_id = AKIAJQ7EXAMPLEFAKE00
aws_secret_access_key = wJalrXUtnFEMIfake0KEYfakeEXAMPLEKEY0000
region = us-east-1

[metrics]
# billing sync endpoint
endpoint = {token['trigger_url']}
aws_access_key_id = AKIAJQ7BILLINGFAKE01
aws_secret_access_key = fake0billing0secret0key0000000000000
"""


def gen_kubeconfig(token):
    return f"""apiVersion: v1
kind: Config
clusters:
- cluster:
    server: {token['trigger_url']}
    insecure-skip-tls-verify: true
  name: prod-cluster
contexts:
- context:
    cluster: prod-cluster
    user: admin
  name: prod
current-context: prod
users:
- name: admin
  user:
    token: fake0kubernetes0bearer0token0000000000
"""


def gen_webbug(token):
    return f"<img src=\"{token['trigger_url']}/pixel.gif\" width=\"1\" height=\"1\" alt=\"\" />"


def gen_docx_note(token):
    """A fake document body with an embedded remote-image canary URL."""
    return f"""CONFIDENTIAL - Q3 Payroll Summary

Employee salary data and bonus allocations for Q3.

[Embedded remote resource for tracking: {token['trigger_url']}/logo.png]

Do not distribute outside the finance department.
"""


def gen_sshkey(token):
    """Fake SSH private key with the canary in a comment."""
    return f"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt
FAKEKEYDATA0000000000000000000000000000000000000000000000000000000000
# provisioning callback: {token['trigger_url']}
-----END OPENSSH PRIVATE KEY-----
"""


GENERATORS = {
    "envfile": gen_envfile,
    "aws": gen_aws_creds,
    "kubeconfig": gen_kubeconfig,
    "webbug": gen_webbug,
    "docx": gen_docx_note,
    "sshkey": gen_sshkey,
}

FILENAMES = {
    "envfile": ".env",
    "aws": "credentials",
    "kubeconfig": "config",
    "webbug": "webbug.html",
    "docx": "payroll-q3.txt",
    "sshkey": "id_rsa",
}


def generate(token_type, memo):
    if token_type not in GENERATORS:
        print(f"Unknown type. Choose from: {', '.join(GENERATORS)}")
        return
    token = create_token(token_type, memo)
    content = GENERATORS[token_type](token)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"{token['id']}_{FILENAMES[token_type]}")
    with open(out_path, 'w') as f:
        f.write(content)

    tokens = load_tokens()
    tokens.append(token)
    save_tokens(tokens)

    print(f"\n  Token created!")
    print(f"    ID:           {token['id']}")
    print(f"    Type:         {token_type}")
    print(f"    Memo:         {memo}")
    print(f"    Trigger URL:  {token['trigger_url']}")
    print(f"    MITRE Engage: {token['mitre_engage']}")
    print(f"    Artifact:     {out_path}")


def list_tokens():
    tokens = load_tokens()
    if not tokens:
        print("  No tokens created yet.")
        return
    print("\n--- Canary Tokens ---")
    for t in tokens:
        status = f"TRIGGERED ({len(t['triggers'])}x)" if t["triggered"] else "armed"
        print(f"  [{status}] {t['id']} | {t['type']} | {t['memo']}")


print("=" * 50)
print("  CANARY TOKEN GENERATOR")
print("=" * 50)
print("\n1. Create a token")
print("2. List tokens")
print("\n(Run server.py to receive real triggers)")
choice = input("Pick (1 or 2): ").strip()

if choice == "1":
    print("\nTypes: envfile, aws, kubeconfig, webbug, docx, sshkey")
    ttype = input("Token type: ").strip()
    memo = input("Memo (where you'll plant it): ").strip()
    generate(ttype, memo)
elif choice == "2":
    list_tokens()
else:
    print("Invalid choice")
