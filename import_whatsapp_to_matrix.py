#!/usr/bin/env python3
"""
Import a WhatsApp chat export into a Matrix Synapse room using the
Application Service API.

Usage:
    # 1. Generate the appservice YAML template
    python import_whatsapp_to_matrix.py --generate-config

    # 2. Dry-run to verify parsing
    python import_whatsapp_to_matrix.py --dry-run

    # 3. Real import
    python import_whatsapp_to_matrix.py

Environment variables:
    MATRIX_AS_TOKEN   - Application service access token (required for real run)
    HOMESERVER_URL    - Matrix homeserver URL (default: http://localhost:8008)
    OWNER_MXID        - Your Matrix user ID (e.g. @user:example.com)
    SERVER_NAME       - Matrix server name (e.g. example.com)
    GHOST_LOCALPART   - Localpart for the ghost user (default: hogan_laundry)
    TIMEZONE          - Timezone for timestamps (default: Asia/Makassar)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
CHAT_FILE = SCRIPT_DIR / "_chat.txt"
PROGRESS_FILE = SCRIPT_DIR / "import_progress.json"

# WhatsApp chat line pattern: [DD/MM/YYYY, HH:MM:SS] Sender: Message
# Lines may start with Unicode LTR mark \u200e
LINE_RE = re.compile(
    r"^\u200e?\[(\d{2}/\d{2}/\d{4}),\s(\d{2}:\d{2}:\d{2})\]\s"
    r"(~?[^:]+?):\s(.*)"
)

# Attachment tag, possibly preceded by Unicode LTR mark
ATTACH_RE = re.compile(r"\u200e?<attached:\s*(.+?)>")

# WhatsApp formatting → HTML
FORMAT_RULES = [
    # *bold*
    (re.compile(r"(?<!\w)\*([^\*]+?)\*(?!\w)"), r"<strong>\1</strong>"),
    # _italic_
    (re.compile(r"(?<!\w)_([^_]+?)_(?!\w)"), r"<em>\1</em>"),
    # ~strikethrough~
    (re.compile(r"(?<!\w)~([^~]+?)~(?!\w)"), r"<del>\1</del>"),
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Import WhatsApp chat export into Matrix via appservice API"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Parse and display messages without sending to Matrix"
    )
    parser.add_argument(
        "--generate-config", action="store_true",
        help="Print appservice YAML and playbook instructions, then exit"
    )
    parser.add_argument(
        "--homeserver-url",
        default=os.environ.get("HOMESERVER_URL", "http://localhost:8008"),
        help="Matrix homeserver URL"
    )
    parser.add_argument(
        "--as-token",
        default=os.environ.get("MATRIX_AS_TOKEN"),
        help="Appservice access token (prefer MATRIX_AS_TOKEN env var)"
    )
    parser.add_argument(
        "--owner-mxid",
        default=os.environ.get("OWNER_MXID"),
        help="Your Matrix user ID, e.g. @malo:example.com"
    )
    parser.add_argument(
        "--server-name",
        default=os.environ.get("SERVER_NAME"),
        help="Matrix server name, e.g. example.com"
    )
    parser.add_argument(
        "--ghost-localpart",
        default=os.environ.get("GHOST_LOCALPART", "hogan_laundry"),
        help="Localpart for the ghost user (default: hogan_laundry)"
    )
    parser.add_argument(
        "--timezone",
        default=os.environ.get("TIMEZONE", "Asia/Makassar"),
        help="Timezone for chat timestamps (default: Asia/Makassar)"
    )
    parser.add_argument(
        "--room-id",
        default=os.environ.get("MATRIX_ROOM_ID"),
        help="Existing room ID to import into (skip room creation)"
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Timezone handling (no pytz dependency)
# ---------------------------------------------------------------------------

TIMEZONE_OFFSETS = {
    "Asia/Makassar": timedelta(hours=8),   # WITA (Bali)
    "Asia/Jakarta": timedelta(hours=7),     # WIB
    "Asia/Jayapura": timedelta(hours=9),    # WIT
    "UTC": timedelta(hours=0),
    "Europe/Paris": timedelta(hours=1),
    "Europe/London": timedelta(hours=0),
    "America/New_York": timedelta(hours=-5),
    "America/Los_Angeles": timedelta(hours=-8),
}


def get_tz_offset(tz_name: str) -> timedelta:
    if tz_name in TIMEZONE_OFFSETS:
        return TIMEZONE_OFFSETS[tz_name]
    print(f"Warning: Unknown timezone '{tz_name}', defaulting to Asia/Makassar (UTC+8)")
    return timedelta(hours=8)


# ---------------------------------------------------------------------------
# Chat parsing
# ---------------------------------------------------------------------------

def parse_chat(chat_path: Path, tz_offset: timedelta) -> list[dict]:
    """Parse the WhatsApp _chat.txt file into a list of message dicts."""
    messages = []
    current = None

    tz = timezone(tz_offset)

    with open(chat_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")

            m = LINE_RE.match(line)
            if m:
                # Save previous message
                if current:
                    messages.append(current)

                date_str, time_str, sender, body = m.groups()
                # Strip leading LTR marks from body
                body = body.lstrip("\u200e")

                # Parse timestamp
                dt = datetime.strptime(
                    f"{date_str} {time_str}", "%d/%m/%Y %H:%M:%S"
                )
                dt = dt.replace(tzinfo=tz)
                ts_ms = int(dt.timestamp() * 1000)

                # Check for attachment
                attach_match = ATTACH_RE.search(body)
                attachment = None
                text_body = body
                if attach_match:
                    attachment = attach_match.group(1)
                    # Remove attachment tag from text
                    text_body = ATTACH_RE.sub("", body).strip()
                    text_body = text_body.lstrip("\u200e").strip()

                current = {
                    "sender": sender.strip(),
                    "timestamp_ms": ts_ms,
                    "timestamp_dt": dt.isoformat(),
                    "body": text_body,
                    "attachment": attachment,
                }
            elif current:
                # Continuation line — append to previous message body
                current["body"] += "\n" + line

    # Don't forget the last message
    if current:
        messages.append(current)

    # Skip the first system message about encryption
    if messages and "end-to-end encrypted" in messages[0].get("body", ""):
        messages = messages[1:]

    return messages


def format_to_html(text: str) -> str | None:
    """Convert WhatsApp formatting to HTML. Returns None if no formatting."""
    html = text
    changed = False
    for pattern, replacement in FORMAT_RULES:
        new_html = pattern.sub(replacement, html)
        if new_html != html:
            changed = True
            html = new_html

    if not changed:
        return None

    # Convert newlines to <br> for HTML
    html = html.replace("\n", "<br>\n")
    return html


# ---------------------------------------------------------------------------
# Matrix API helpers
# ---------------------------------------------------------------------------

class MatrixAPI:
    def __init__(self, homeserver_url: str, as_token: str):
        self.base = homeserver_url.rstrip("/")
        self.as_token = as_token
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {as_token}"
        self.txn_counter = int(time.time() * 1000)

    def _url(self, path: str) -> str:
        return f"{self.base}/_matrix/client/v3{path}"

    def _request(self, method: str, path: str, params: dict = None,
                 json_body: dict = None, data=None, headers=None,
                 max_retries: int = 5) -> requests.Response:
        url = self._url(path)
        for attempt in range(max_retries):
            try:
                resp = self.session.request(
                    method, url, params=params, json=json_body,
                    data=data, headers=headers, timeout=30
                )
                if resp.status_code == 429:
                    retry_ms = resp.json().get("retry_after_ms", 2000 * (attempt + 1))
                    print(f"  Rate limited, waiting {retry_ms}ms...")
                    time.sleep(retry_ms / 1000)
                    continue
                if resp.status_code >= 500:
                    wait = min(2 ** attempt, 30)
                    print(f"  Server error {resp.status_code}, retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                return resp
            except requests.exceptions.RequestException as e:
                wait = min(2 ** attempt, 30)
                print(f"  Request error: {e}, retrying in {wait}s...")
                time.sleep(wait)

        # Final attempt without retry
        return self.session.request(
            method, url, params=params, json=json_body,
            data=data, headers=headers, timeout=30
        )

    def _next_txn(self) -> str:
        self.txn_counter += 1
        return str(self.txn_counter)

    def register_ghost(self, localpart: str) -> None:
        """Register an appservice ghost user (idempotent)."""
        resp = self._request("POST", "/register", json_body={
            "type": "m.login.application_service",
            "username": localpart,
        })
        if resp.status_code in (200, 409):
            print(f"  Ghost user @{localpart} registered (or already exists)")
        else:
            print(f"  Warning: register ghost returned {resp.status_code}: {resp.text}")

    def set_displayname(self, user_id: str, name: str) -> None:
        resp = self._request(
            "PUT", f"/profile/{user_id}/displayname",
            params={"user_id": user_id},
            json_body={"displayname": name}
        )
        if resp.status_code == 200:
            print(f"  Set display name for {user_id} → {name}")
        else:
            print(f"  Warning: set displayname returned {resp.status_code}: {resp.text}")

    def create_room(self, creator_user_id: str, name: str,
                    invite: list[str] = None) -> str:
        """Create a room as the given user. Returns room_id."""
        body = {
            "name": name,
            "visibility": "private",
            "preset": "private_chat",
            "is_direct": True,
            "creation_content": {
                "m.federate": False,
            },
        }
        if invite:
            body["invite"] = invite

        resp = self._request(
            "POST", "/createRoom",
            params={"user_id": creator_user_id},
            json_body=body
        )
        resp.raise_for_status()
        room_id = resp.json()["room_id"]
        print(f"  Created room: {room_id}")
        return room_id

    def join_room(self, room_id: str, user_id: str) -> None:
        resp = self._request(
            "POST", f"/join/{room_id}",
            params={"user_id": user_id},
        )
        if resp.status_code == 200:
            print(f"  {user_id} joined {room_id}")
        else:
            print(f"  Warning: join returned {resp.status_code}: {resp.text}")

    def set_direct_room(self, owner_mxid: str, ghost_mxid: str,
                        room_id: str) -> None:
        """Update m.direct account data so Element shows the room as a DM."""
        encoded_owner = urllib.parse.quote(owner_mxid)
        path = f"/user/{encoded_owner}/account_data/m.direct"

        # Fetch current m.direct mappings (impersonate the owner)
        resp = self._request("GET", path, params={"user_id": owner_mxid})
        if resp.status_code == 200:
            direct = resp.json()
        elif resp.status_code == 404:
            direct = {}
        else:
            print(f"  Warning: GET m.direct returned {resp.status_code}: {resp.text}")
            direct = {}

        # Append room_id under the ghost user's key (avoid duplicates)
        rooms = direct.get(ghost_mxid, [])
        if room_id not in rooms:
            rooms.append(room_id)
        direct[ghost_mxid] = rooms

        # Save updated mappings
        resp = self._request("PUT", path, params={"user_id": owner_mxid},
                             json_body=direct)
        if resp.status_code == 200:
            print(f"  Set m.direct for {owner_mxid}: {ghost_mxid} → {room_id}")
        else:
            print(f"  Warning: PUT m.direct returned {resp.status_code}: {resp.text}")

    def upload_file(self, file_path: Path, user_id: str) -> str:
        """Upload a file and return the mxc:// URI."""
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        file_data = file_path.read_bytes()

        resp = self._request(
            "POST", "/upload",
            params={
                "filename": file_path.name,
                "user_id": user_id,
            },
            data=file_data,
            headers={"Content-Type": content_type},
        )
        # upload endpoint is on /_matrix/media/v3/upload, let's use the right one
        # Actually, let's use the correct media endpoint
        url = f"{self.base}/_matrix/media/v3/upload"
        resp = self.session.post(
            url,
            params={
                "filename": file_path.name,
                "user_id": user_id,
            },
            data=file_data,
            headers={
                "Content-Type": content_type,
                "Authorization": f"Bearer {self.as_token}",
            },
            timeout=60,
        )
        resp.raise_for_status()
        mxc_uri = resp.json()["content_uri"]
        print(f"  Uploaded {file_path.name} → {mxc_uri}")
        return mxc_uri

    def send_message(self, room_id: str, user_id: str, ts_ms: int,
                     content: dict) -> str:
        """Send a message event with a specific timestamp. Returns event_id."""
        txn_id = self._next_txn()
        # Create a deterministic txn_id for idempotency
        txn_hash = hashlib.sha256(
            f"{room_id}:{user_id}:{ts_ms}:{json.dumps(content, sort_keys=True)}".encode()
        ).hexdigest()[:16]

        resp = self._request(
            "PUT",
            f"/rooms/{room_id}/send/m.room.message/{txn_hash}",
            params={
                "user_id": user_id,
                "ts": str(ts_ms),
            },
            json_body=content,
        )
        resp.raise_for_status()
        return resp.json()["event_id"]


# ---------------------------------------------------------------------------
# Appservice config generation
# ---------------------------------------------------------------------------

def generate_appservice_config(server_name: str, ghost_localpart: str):
    import secrets
    as_token = secrets.token_hex(32)
    hs_token = secrets.token_hex(32)

    escaped_server = server_name.replace(".", "\\\\.")
    yaml_content = f"""# Application Service registration for WhatsApp import
# Place this file on your server and register it with Synapse

id: whatsapp-import
url: ''
as_token: {as_token}
hs_token: {hs_token}
sender_localpart: _whatsapp_import
namespaces:
  users:
    - exclusive: false
      regex: '@malo:{escaped_server}'
    - exclusive: true
      regex: '@{ghost_localpart}:{escaped_server}'
  rooms: []
  aliases: []
rate_limited: false
"""

    print("=" * 60)
    print("APPSERVICE REGISTRATION YAML")
    print("=" * 60)
    print(yaml_content)
    print("=" * 60)
    print()
    print("SETUP INSTRUCTIONS (matrix-docker-ansible-deploy playbook)")
    print("=" * 60)
    print()
    print("1. Save the YAML above to a file on your server, e.g.:")
    print("     /matrix/synapse/config/appservice-whatsapp-import.yaml")
    print()
    print("2. In your playbook's inventory/host_vars/matrix.DOMAIN/vars.yml, add:")
    print()
    print("   matrix_synapse_configuration_extension_yaml: |")
    print("     app_service_config_files:")
    print("       - /data/appservice-whatsapp-import.yaml")
    print()
    print("   Or if you already have app_service_config_files, append to the list.")
    print()
    print("   Alternatively, if your playbook version supports it:")
    print("   matrix_synapse_app_service_config_files_auto: []")
    print("   matrix_synapse_app_service_config_files_custom:")
    print("     - /matrix/synapse/config/appservice-whatsapp-import.yaml")
    print()
    print("3. Re-run the playbook:")
    print("     just run-tags setup-synapse,start")
    print()
    print("4. Set the environment variable and run this script:")
    print(f"     export MATRIX_AS_TOKEN='{as_token}'")
    print(f"     export HOMESERVER_URL='https://matrix.YOURDOMAIN.com'")
    print(f"     export OWNER_MXID='@malo:{server_name}'")
    print(f"     export SERVER_NAME='{server_name}'")
    print()
    print(f"   Then:  python import_whatsapp_to_matrix.py --dry-run")
    print(f"   Then:  python import_whatsapp_to_matrix.py")
    print()


# ---------------------------------------------------------------------------
# Progress tracking
# ---------------------------------------------------------------------------

def load_progress() -> dict:
    if PROGRESS_FILE.exists():
        return json.loads(PROGRESS_FILE.read_text())
    return {"sent_indices": [], "room_id": None}


def save_progress(progress: dict):
    PROGRESS_FILE.write_text(json.dumps(progress, indent=2))


# ---------------------------------------------------------------------------
# Main import logic
# ---------------------------------------------------------------------------

def build_sender_map(owner_mxid: str, server_name: str,
                     ghost_localpart: str) -> dict[str, str]:
    """Map WhatsApp sender names to Matrix user IDs.

    Both senders use ghost accounts since the appservice can only act
    as users within its registered namespace.
    """
    return {
        "Malo Camaret": owner_mxid,
        "~Hogan Laundry": f"@{ghost_localpart}:{server_name}",
    }


def get_image_info(file_path: Path) -> dict:
    """Get image dimensions and size for m.image content."""
    info = {
        "size": file_path.stat().st_size,
        "mimetype": mimetypes.guess_type(str(file_path))[0] or "image/jpeg",
    }
    if HAS_PIL:
        try:
            with Image.open(file_path) as img:
                info["w"], info["h"] = img.size
        except Exception:
            pass
    return info


def do_dry_run(messages: list[dict], sender_map: dict[str, str]):
    """Print parsed messages without sending to Matrix."""
    print(f"\nParsed {len(messages)} messages:\n")
    for i, msg in enumerate(messages):
        mxid = sender_map.get(msg["sender"], f"?{msg['sender']}")
        ts = msg["timestamp_dt"]
        body = msg["body"]
        attach = msg["attachment"]

        # Truncate long bodies for display
        if len(body) > 120:
            body_display = body[:120] + "..."
        else:
            body_display = body

        print(f"[{i:3d}] {ts}  {mxid}")
        if body:
            # Show first line + indication of more
            lines = body_display.split("\n")
            print(f"      text: {lines[0]}")
            if len(lines) > 1:
                print(f"            (+ {len(body.split(chr(10))) - 1} more lines)")
        if attach:
            file_exists = (SCRIPT_DIR / attach).exists()
            status = "OK" if file_exists else "MISSING"
            print(f"      attachment: {attach} [{status}]")

        html = format_to_html(msg["body"])
        if html:
            print(f"      (has HTML formatting)")
        print()

    # Summary
    senders = set(m["sender"] for m in messages)
    attachments = [m for m in messages if m["attachment"]]
    print(f"Summary: {len(messages)} messages, {len(senders)} senders, "
          f"{len(attachments)} attachments")
    print(f"Senders: {', '.join(senders)}")
    for m in attachments:
        fname = m["attachment"]
        exists = (SCRIPT_DIR / fname).exists()
        print(f"  Attachment: {fname} — {'found' if exists else 'NOT FOUND'}")


def do_import(messages: list[dict], sender_map: dict[str, str],
              args, ghost_mxid: str, ghost_localpart: str):
    """Send all messages to Matrix."""
    if not HAS_REQUESTS:
        sys.exit("Missing dependency: requests\n  pip install requests")
    if not HAS_PIL:
        print("Warning: Pillow not installed — image dimensions won't be included.")
        print("  pip install Pillow")
    if not args.as_token:
        sys.exit("Error: MATRIX_AS_TOKEN is required for import.\n"
                 "Set it via --as-token or the MATRIX_AS_TOKEN env var.\n"
                 "Run with --generate-config to create the appservice registration.")

    api = MatrixAPI(args.homeserver_url, args.as_token)
    progress = load_progress()

    # Step 1: Register ghost user
    print("\n[1/4] Registering ghost user...")
    api.register_ghost(ghost_localpart)
    api.set_displayname(ghost_mxid, "Hogan Laundry")

    # Step 2: Create or reuse room
    room_id = args.room_id or progress.get("room_id")
    if room_id:
        print(f"\n[2/4] Using existing room: {room_id}")
    else:
        print("\n[2/4] Creating room...")
        # Ghost creates the room and invites the owner, since the
        # appservice can only act as users in its own namespace.
        room_id = api.create_room(
            creator_user_id=args.owner_mxid,
            name="Hogan Laundry (WhatsApp Import)",
            invite=[ghost_mxid],
        )
        api.join_room(room_id, ghost_mxid)
        progress["room_id"] = room_id
        save_progress(progress)

    # Always set m.direct so re-runs fix the DM flag too
    api.set_direct_room(args.owner_mxid, ghost_mxid, room_id)

    # Step 3: Send messages
    print(f"\n[3/4] Sending {len(messages)} messages...")
    sent_set = set(progress.get("sent_indices", []))
    event_count = 0

    for i, msg in enumerate(messages):
        if i in sent_set:
            continue

        mxid = sender_map.get(msg["sender"])
        if not mxid:
            print(f"  Warning: unknown sender '{msg['sender']}', skipping")
            continue

        ts_ms = msg["timestamp_ms"]

        # Send text if present
        if msg["body"]:
            content = {
                "msgtype": "m.text",
                "body": msg["body"],
            }
            html = format_to_html(msg["body"])
            if html:
                content["format"] = "org.matrix.custom.html"
                content["formatted_body"] = html

            event_id = api.send_message(room_id, mxid, ts_ms, content)
            event_count += 1
            print(f"  [{i}] text from {msg['sender'][:20]} → {event_id}")

        # Send attachment if present
        if msg["attachment"]:
            file_path = SCRIPT_DIR / msg["attachment"]
            if not file_path.exists():
                print(f"  [{i}] Warning: attachment {msg['attachment']} not found, skipping")
            else:
                mxc_uri = api.upload_file(file_path, mxid)
                img_info = get_image_info(file_path)

                content = {
                    "msgtype": "m.image",
                    "body": msg["attachment"],
                    "url": mxc_uri,
                    "info": img_info,
                }
                event_id = api.send_message(room_id, mxid, ts_ms, content)
                event_count += 1
                print(f"  [{i}] image from {msg['sender'][:20]} → {event_id}")

        sent_set.add(i)
        progress["sent_indices"] = sorted(sent_set)
        save_progress(progress)

    # Step 4: Done
    print(f"\n[4/4] Import complete!")
    print(f"  Room: {room_id}")
    print(f"  Events sent: {event_count}")
    print(f"  Progress saved to: {PROGRESS_FILE}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    if args.generate_config:
        server_name = args.server_name
        if not server_name:
            server_name = input("Enter your Matrix server name (e.g. example.com): ").strip()
        generate_appservice_config(server_name, args.ghost_localpart)
        return

    # Validate required args for non-dry-run
    if not args.dry_run:
        missing = []
        if not args.owner_mxid:
            missing.append("OWNER_MXID (--owner-mxid)")
        if not args.server_name:
            missing.append("SERVER_NAME (--server-name)")
        if missing:
            sys.exit(f"Error: missing required config: {', '.join(missing)}\n"
                     f"Set via CLI args or environment variables.")

    # Parse chat
    print(f"Parsing {CHAT_FILE}...")
    tz_offset = get_tz_offset(args.timezone)
    messages = parse_chat(CHAT_FILE, tz_offset)
    print(f"Found {len(messages)} messages")

    # Build sender map
    server_name = args.server_name or "example.com"
    owner_mxid = args.owner_mxid or f"@malo:{server_name}"
    ghost_localpart = args.ghost_localpart
    ghost_mxid = f"@{ghost_localpart}:{server_name}"

    sender_map = build_sender_map(owner_mxid, server_name, ghost_localpart)

    if args.dry_run:
        do_dry_run(messages, sender_map)
    else:
        do_import(messages, sender_map, args, ghost_mxid, ghost_localpart)


if __name__ == "__main__":
    main()
