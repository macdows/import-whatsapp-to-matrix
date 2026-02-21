# WhatsApp to Matrix Importer

Import a WhatsApp chat export into a Matrix room using the Application Service (AS) API. Messages are sent with their original timestamps and sender identities preserved via a ghost user.

## Features

- Parses WhatsApp's `_chat.txt` export format (timestamps, senders, multiline messages)
- Converts WhatsApp formatting (\*bold\*, \_italic\_, \~strikethrough\~) to HTML
- Uploads image attachments as `m.image` events
- Sets the room as a direct message in Element/clients
- Resumable: tracks progress in `import_progress.json` so interrupted imports can continue
- Idempotent message sending via deterministic transaction IDs
- Built-in rate-limit and retry handling

## Prerequisites

- Python 3.10+
- A Matrix homeserver running [Synapse](https://github.com/element-hq/synapse)
- An application service registered with the homeserver

```
pip install requests Pillow
```

(`Pillow` is optional — only needed for image dimension metadata.)

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
export OWNER_MXID='@malo:example.com'
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

1. Register the ghost user (`@hogan_laundry:example.com`)
2. Create a private DM room (or reuse an existing one)
3. Send all messages with original timestamps
4. Save progress after each message

## Configuration

All options can be set via CLI flags or environment variables:

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--homeserver-url` | `HOMESERVER_URL` | `http://localhost:8008` | Matrix homeserver URL |
| `--as-token` | `MATRIX_AS_TOKEN` | — | Appservice access token (required) |
| `--owner-mxid` | `OWNER_MXID` | — | Your Matrix user ID (required) |
| `--server-name` | `SERVER_NAME` | — | Matrix server name (required) |
| `--ghost-localpart` | `GHOST_LOCALPART` | `hogan_laundry` | Localpart for the ghost user |
| `--timezone` | `TIMEZONE` | `Asia/Makassar` | Timezone for chat timestamps |
| `--room-id` | `MATRIX_ROOM_ID` | — | Import into an existing room |
| `--chat-dir` | `CHAT_DIR` | Script directory | Path to WhatsApp chat export folder |
| `--dry-run` | — | — | Parse only, don't send |
| `--generate-config` | — | — | Print appservice YAML and exit |

## Resuming an interrupted import

Progress is saved to `import_progress.json` after each message. Re-running the script will skip already-sent messages and continue where it left off.

To start fresh, delete `import_progress.json`.

## Note on encryption

Imported messages are **not end-to-end encrypted**, even if you normally use an encrypted Matrix room. The appservice API sends events server-side, bypassing client-side encryption. The created room has federation disabled but is otherwise a standard unencrypted room. Keep this in mind if your homeserver is shared or managed by a third party.

## Adapting for other chats

The sender map is hardcoded in `build_sender_map()`. To import a different chat, update the sender names and ghost localpart to match your export.
