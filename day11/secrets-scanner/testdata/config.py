# Sample config file with planted secrets for testing

# --- Fake-but-pattern-matching secrets (SHOULD be flagged) ---
# NOTE: these are NOT real credentials, only shaped like them for testing
AWS_ACCESS_KEY = "AKIAEXAMPLE0KEY00FAKE"
GITHUB_TOKEN = "ghp_faketokenAAAAAAAAAAAAAAAAAAAAAAAAA0"
STRIPE_KEY = "sk_test_faketokenAAAAAAAAAAAAAAAA"
GOOGLE_API = "AIzaFakeKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
db_password = "S3cr3tP@ssw0rd123"
API_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

# A random high-entropy token (caught by entropy, not pattern)
SESSION_SECRET = "xQ9mK2pL7vB4nR8wT3zY6cH1jF5gD0sA"

# --- Placeholders (should NOT be flagged) ---
EXAMPLE_KEY = "YOUR_API_KEY_HERE"
TEST_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxx"
placeholder = "changeme"

# --- Normal code (should NOT be flagged) ---
def connect_to_database(host, port):
    return f"Connecting to {host}:{port}"

MAX_RETRIES = 5
DEBUG_MODE = True
