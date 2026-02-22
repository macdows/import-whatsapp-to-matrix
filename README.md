# WhatsApp to Matrix Importer

Import a WhatsApp chat export into a Matrix room using the Application Service (AS) API. Messages are sent with their original timestamps and sender identities preserved via a ghost user.

## Features

- **End-to-end encrypted** by default (Megolm via matrix-nio's crypto engine)
- Parses WhatsApp's `_chat.txt` export format (timestamps, senders, multiline messages)
- Converts WhatsApp formatting (\*bold\*, \_italic\_, \~strikethrough\~) to HTML
- Uploads image attachments as `m.image` events (encrypted client-side when E2EE is on)
- Sets the room as a direct message in Element/clients
- Resumable: tracks progress in `import_progress.json` so interrupted imports can continue
- Idempotent message sending via deterministic transaction IDs
- Built-in rate-limit and retry handling

## Prerequisites

- Python 3.10+
- A Matrix homeserver running [Synapse](https://github.com/element-hq/synapse)
- An application service registered with the homeserver
- `libolm` 3.x (required for E2EE)

```bash
# System dependency (for E2EE)
brew install libolm          # macOS
# apt install libolm-dev     # Debian/Ubuntu

# Python dependencies
pip install requests Pillow "matrix-nio[e2e]"
```

`Pillow` is optional (only needed for image dimension metadata). `matrix-nio[e2e]` is optional if you use `--no-encryption`.

## Quick start

### 1. Prepare the chat export

Export the WhatsApp chat (with media). The folder should contain:

- `_chat.txt` — the chat transcript
- Any attached media files referenced in the transcript (e.g. `IMG-20240101-WA0001.jpg`)

By default the script looks for these files in its own directory. To target a different folder, use `--chat-dir`:

```bash
python import_whatsapp_to_matrix.py --chat-dir "/path/to/WhatsApp Chat - Someone" --dry-run
```

### 2. Generate the appservice registration

```bash
python import_whatsapp_to_matrix.py --generate-config --server-name example.com
```

This prints a YAML registration file and setup instructions for your homeserver. Save the YAML to your server and register it with Synapse.

### 3. Set environment variables

```bash
export MATRIX_AS_TOKEN='<as_token from the generated YAML>'
export HOMESERVER_URL='https://matrix.example.com'
export OWNER_MXID='@user:example.com'
export SERVER_NAME='example.com'
```

### 4. Dry run

Verify that the chat parses correctly without sending anything:

```bash
python import_whatsapp_to_matrix.py --dry-run
```

### 5. Import

```bash
python import_whatsapp_to_matrix.py
```

The script will:

1. Register the ghost user (`@whatsapp_ghost:example.com`)
2. Create an encrypted private DM room (or reuse an existing one)
3. Set up E2EE (login crypto devices, share Megolm sessions)
4. Send all messages encrypted with original timestamps
5. Export Megolm session keys to `megolm_keys.txt`

After import, import the keys into Element: **Settings > Security & Privacy > Import E2E room keys** (passphrase: `import-whatsapp`).

To skip encryption: `python import_whatsapp_to_matrix.py --no-encryption`

## Configuration

All options can be set via CLI flags or environment variables:

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--homeserver-url` | `HOMESERVER_URL` | `http://localhost:8008` | Matrix homeserver URL |
| `--as-token` | `MATRIX_AS_TOKEN` | — | Appservice access token (required) |
| `--owner-mxid` | `OWNER_MXID` | — | Your Matrix user ID (required) |
| `--server-name` | `SERVER_NAME` | — | Matrix server name (required) |
| `--ghost-localpart` | `GHOST_LOCALPART` | `whatsapp_ghost` | Localpart for the ghost user |
| `--timezone` | `TIMEZONE` | `Europe/London` | Timezone for chat timestamps |
| `--room-id` | `MATRIX_ROOM_ID` | — | Import into an existing room |
| `--chat-dir` | `CHAT_DIR` | Script directory | Path to WhatsApp chat export folder |
| `--owner-name` | `OWNER_NAME` | Auto-detected | WhatsApp display name of the room owner |
| `--ghost-name` | `GHOST_NAME` | Auto-detected | WhatsApp display name of the other party |
| `--no-encryption` | — | — | Send plaintext instead of E2EE |
| `--dry-run` | — | — | Parse only, don't send |
| `--fresh` | — | — | Delete progress and start a fresh import |
| `--generate-config` | — | — | Print appservice YAML and exit |

## Resuming an interrupted import

Progress is saved to `import_progress.json` after each message. Re-running the script will skip already-sent messages and continue where it left off.

To start fresh, re-run with `--fresh` to delete the progress file and create a new room.

## End-to-end encryption

By default, messages are **end-to-end encrypted** using Megolm (the same algorithm Matrix/Element uses). The script uses matrix-nio's crypto engine to encrypt message content client-side, then sends the encrypted payloads through the appservice API with original timestamps.

**How it works:**

1. Two temporary crypto devices are created (one per sender) and logged in via appservice auth
2. Device keys are uploaded and Megolm group sessions are established
3. Each message is encrypted with the sender's Megolm session before being sent
4. Attachments are encrypted client-side (AES-CTR) and uploaded as `application/octet-stream`
5. Session keys are exported to `megolm_keys.txt` for import into Element

**Runtime artifacts** (created in the chat directory):

- `.e2ee_store/` — nio crypto state (Olm accounts, Megolm sessions)
- `nio_credentials.json` — device IDs and access tokens for the crypto devices
- `megolm_keys.txt` — exported Megolm session keys

**Re-runs** reuse the existing crypto state. To fully reset E2EE state, delete `.e2ee_store/` and `nio_credentials.json`.

Use `--no-encryption` to send plaintext messages instead (no `libolm` or `matrix-nio` needed).

## Adapting for other chats

Sender names are auto-detected when the chat has exactly two participants. For chats with more senders, specify `--owner-name` and `--ghost-name` explicitly. Adjust `--ghost-localpart` to set the Matrix localpart for the ghost user.
