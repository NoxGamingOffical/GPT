# Nox Remote AI

Windows desktop remote-assistance prototype. **Not yet a functioning ChatGPT-to-PC remote control application.**

## Free update hosting

GitHub Pages target: https://noxgamingoffical.github.io/GPT/

The launcher configuration must use:

```json
{ "updateBaseUrl": "https://noxgamingoffical.github.io/GPT/" }
```

To enable Pages: **Settings → Pages → Deploy from a branch → main → /docs → Save**.

**Not yet live:** the launcher requires a signed `manifest.json`, a Base64 RSA-PSS-SHA256 `manifest.sig`, and a SHA256-verified `NoxRemoteAI.zip`. No release is uploaded yet. The launcher will intentionally refuse to start until these are published and verified. Do not upload private signing keys, access tokens, or personal data.

GitHub Pages only hosts static update files, not a live authenticated remote-control server. Never expose an unauthenticated remote-control endpoint.
