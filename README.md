# RelayProxy

Routes C2 HTTP traffic through an Azure Relay Hybrid Connection so the backend server is never directly exposed. The dropper talks to `*.servicebus.windows.net`; the C2 IP is never seen.

```
Dropper ──HTTPS──▶ <namespace>.servicebus.windows.net/<connection>/...
                            (Azure Relay)
                                │
                      WSS control channel
                                │
                         RelayProxy.exe ──HTTPS──▶ C2 server
```

## Quick Start

```
RelayProxy.exe -namespace <ns>.servicebus.windows.net -connection api -key "<sas_key>" -target <c2_host>
```

| Argument | Description |
|----------|-------------|
| `-namespace` | Relay namespace FQDN |
| `-connection` | Hybrid Connection name (becomes the URL path prefix) |
| `-key` | SAS primary key |
| `-target` | Backend C2 hostname |

## Azure Setup

1. **Create a Relay Namespace** — Portal → Create a resource → Relay. The namespace name is globally unique and becomes `<name>.servicebus.windows.net`.
2. **Create a Hybrid Connection** — inside the namespace, add one (e.g. `api`). Leave *Requires Client Authorization* **unchecked**.
3. **Get the SAS Key** — namespace → Shared access policies → `RootManageSharedAccessKey` → copy Primary key. Or create a scoped policy with **Listen + Send**.

## Build

Requires .NET 8 SDK. Run `release.bat` to produce self-contained single-file executables (no runtime needed on target):

```
release.bat
```

Outputs:
- `publish\win-x64\RelayProxy.exe`
- `publish\linux-x64\RelayProxy`

Or run from source: `dotnet run`

## PoshC2 Configuration

Set `PayloadCommsHost` to:

```
https://<namespace>.servicebus.windows.net
```

Beacon URLs from `resources/urls.txt` route through automatically — the Hybrid Connection name prefix is stripped by RelayProxy before forwarding.

## Protocol Notes

- `"body"` field in the response JSON is **required** — relay returns 500 if absent
- `content-length` should be in `responseHeaders` — without it WinINet falls back to a 5 MB buffer
- Response body must be a **single binary frame** (`endOfMessage=true`) — fragmented frames cause chunking issues
- `requestId` must include the `_V` suffix from the control message
- Rendezvous WS CLOSE must follow the body — relay only delivers the response after receiving CLOSE

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `401` on control channel | Wrong SAS key or key name |
| `404` on control channel | Hybrid Connection name wrong or not created |
| Rendezvous errors | Transient — auto-retries per request |
| Dropper gets 500 | Check `requestId` and `body` field in response JSON |

## Security Notes

- Rotate SAS keys after engagements
- Azure Relay logs sender IPs in Azure Monitor
- Namespace and connection names appear in TLS SNI — choose names that blend with the target environment
