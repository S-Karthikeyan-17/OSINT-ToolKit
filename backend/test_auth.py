import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Read the key from .env
AUTHORIZATION_KEY = os.environ.get("RECON_ALLOWED_KEY")
print("🔑 Loaded AUTHORIZATION_KEY =", AUTHORIZATION_KEY)

@app.route("/")
def home():
    return "Auth Test Backend Running!"

# Route to test auth key
@app.route("/verify-key")
def verify_key():
    auth_key = request.args.get("auth")
    if auth_key == AUTHORIZATION_KEY:
        return jsonify({"authorized": True, "message": "Valid key!"})
    else:
        return jsonify({"authorized": False, "message": "Invalid key!"}), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
