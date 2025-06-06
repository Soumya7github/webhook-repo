import os
import hmac
import hashlib
from datetime import datetime
from flask import Flask, request, abort, jsonify, render_template
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

MONGO_URI      = os.getenv("MONGO_URI", "mongodb://localhost:27017/github_events")
DATABASE_NAME  = os.getenv("DATABASE_NAME", "github_events")
COLLECTION_NAME= os.getenv("COLLECTION_NAME", "events")
SECRET_TOKEN   = os.getenv("SECRET_TOKEN", "")

# Initialize MongoDB client & collection
client     = MongoClient(MONGO_URI)
db         = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]

def verify_signature(payload_bytes: bytes, signature_header: str) -> bool:
    """
    Verifies GitHub HMAC-SHA1 signature. If SECRET_TOKEN is blank or signature is missing, skip.
    """
    if not SECRET_TOKEN or not signature_header:
        return True

    try:
        sha_name, signature = signature_header.split("=")
    except ValueError:
        return False

    if sha_name != "sha1":
        return False

    mac = hmac.new(SECRET_TOKEN.encode(), msg=payload_bytes, digestmod=hashlib.sha1)
    return hmac.compare_digest(mac.hexdigest(), signature)

# def format_timestamp(iso_ts: str) -> str:
#     """
#     Convert ISO8601 UTC timestamp into "1st April 2021 - 09:30 PM UTC" style (with ordinal suffix).
#     """
#     # e.g. iso_ts = "2021-04-01T21:30:00Z"
#     dt = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ")
#     day = dt.day
#     if 11 <= day <= 13:
#         suffix = "th"
#     else:
#         suffix = {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
#     return dt.strftime(f"%-d{suffix} %B %Y - %I:%M %p UTC")

from datetime import datetime, timezone

def format_timestamp(iso_ts: str) -> str:
    """
    Convert an ISO8601 timestamp (with either 'Z' or '+HH:MM' offset)
    into a string like "5th June 2025 - 01:15 AM UTC".
    """

    # 1) Normalize the timestamp so fromisoformat can parse it:
    #    - If it ends with 'Z', replace with '+00:00'
    if iso_ts.endswith("Z"):
        ts_fixed = iso_ts.replace("Z", "+00:00")
    else:
        ts_fixed = iso_ts   # e.g. "2025-06-05T01:15:53+05:30"

    # 2) Parse into a timezone-aware datetime
    dt = datetime.fromisoformat(ts_fixed)

    # 3) Convert to UTC
    dt_utc = dt.astimezone(timezone.utc)

    # 4) Build the day with ordinal suffix manually
    day = dt_utc.day
    if 11 <= day <= 13:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")

    # 5) Use only standard strftime specifiers (no %-d) for the rest
    #    We want: "5th June 2025 - 01:15 AM UTC"
    #    Construct the "June 2025 - 01:15 AM UTC" part with strftime:
    rest = dt_utc.strftime("%B %Y - %I:%M %p UTC")

    # 6) Combine into final string
    return f"{day}{suffix} {rest}"



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/events", methods=["GET"])
def get_events():
    """
    Return latest 50 formatted strings from MongoDB.
    """
    docs = collection.find().sort("inserted_at", -1).limit(50)
    results = [doc["formatted"] for doc in docs]
    return jsonify(results), 200

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    """
    1) Verify signature (if SECRET_TOKEN is set).
    2) Determine GitHub event type; handle only `push` and `pull_request (opened/merged)`.
    3) Format a string, insert into MongoDB. Otherwise return {"status":"ignored"}.
    """
    signature = request.headers.get("X-Hub-Signature")
    if not verify_signature(request.data, signature):
        abort(403, "Invalid signature")

    event_type = request.headers.get("X-GitHub-Event", "")
    payload    = request.get_json(silent=True)

    # If payload is not JSON or missing, abort
    if payload is None:
        return jsonify({"status": "no-json-payload"}), 400

    # Prepare to insert
    doc = {
        "inserted_at": datetime.utcnow(),
        "formatted": ""
    }

    # Handle PUSH
    if event_type == "push":
        try:
            author    = payload["pusher"]["name"]
            ref       = payload["ref"]                # e.g. "refs/heads/main"
            to_branch = ref.split("/")[-1]            # "main"
            ts        = payload["head_commit"]["timestamp"]  # e.g. "2021-04-01T21:30:00Z"
        except KeyError:
            # If GitHub payload changed or keys missing, log and ignore
            app.logger.warning("Missing key in push payload: %s", payload)
            return jsonify({"status": "ignored-key-error"}), 200

        try:
            formatted_string = f"\"{author}\" pushed to \"{to_branch}\" on {format_timestamp(ts)}"
            doc["formatted"] = formatted_string
        except Exception as e:
            app.logger.error("Failed to format push timestamp: %s → %s", ts, e)
            return jsonify({"status": "error-formatting"}), 200

    # Handle PULL REQUEST
    elif event_type == "pull_request":
        action = payload.get("action", "")
        pr     = payload.get("pull_request", {})

        # If action is "opened"
        if action == "opened":
            try:
                author      = pr["user"]["login"]
                from_branch = pr["head"]["ref"]
                to_branch   = pr["base"]["ref"]
                ts          = pr["created_at"]        # e.g. "2021-04-01T09:00:00Z"
            except KeyError:
                app.logger.warning("Missing key in pull_request-opened: %s", payload)
                return jsonify({"status": "ignored-key-error"}), 200

            try:
                formatted_string = (
                    f"\"{author}\" submitted a pull request from \"{from_branch}\" "
                    f"to \"{to_branch}\" on {format_timestamp(ts)}"
                )
                doc["formatted"] = formatted_string
            except Exception as e:
                app.logger.error("Failed to format pull_request-opened timestamp: %s → %s", ts, e)
                return jsonify({"status": "error-formatting"}), 200

        # If action is "closed" AND merged == True
        elif action == "closed" and pr.get("merged", False):
            try:
                author      = pr["user"]["login"]
                from_branch = pr["head"]["ref"]
                to_branch   = pr["base"]["ref"]
                ts          = pr["merged_at"]         # e.g. "2021-04-02T12:00:00Z"
            except KeyError:
                app.logger.warning("Missing key in pull_request-closed: %s", payload)
                return jsonify({"status": "ignored-key-error"}), 200

            try:
                formatted_string = (
                    f"\"{author}\" merged branch \"{from_branch}\" to \"{to_branch}\" "
                    f"on {format_timestamp(ts)}"
                )
                doc["formatted"] = formatted_string
            except Exception as e:
                app.logger.error("Failed to format pull_request-merged timestamp: %s → %s", ts, e)
                return jsonify({"status": "error-formatting"}), 200

        else:
            # Ignore any other pull_request actions (reopened, labeled, closed-not-merged, etc.)
            return jsonify({"status": "ignored-pull-action"}), 200

    else:
        # Ignore any other event types (e.g. "ping", "issues", etc.)
        return jsonify({"status": "ignored-event"}), 200

    # At this point `doc["formatted"]` is guaranteed to be non-empty
    collection.insert_one(doc)
    return jsonify({"status": "stored"}), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
