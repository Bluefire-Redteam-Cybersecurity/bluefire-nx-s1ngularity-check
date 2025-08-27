# 🔍 Bluefire Nx "s1ngularity" Supply Chain Scanner

![npm (scoped)](https://img.shields.io/npm/v/@bluefire-redteam/nx-s1ngularity-check)
![license](https://img.shields.io/github/license/bluefire-redteam/nx-s1ngularity-check)
![build](https://img.shields.io/github/actions/workflow/status/bluefire-redteam/nx-s1ngularity-check/ci.yml?branch=main)

**Free, open-source scanner from [Bluefire Redteam](https://bluefireredteam.com)**  
Detect if your systems or projects were impacted by the August 2025 Nx *s1ngularity* supply-chain compromise.  

---

## 🚨 What Happened?
On **Aug 26–27, 2025**, multiple malicious versions of the **Nx build system packages** were published to npm.  
They contained a **postinstall malware (`telemetry.js`)** that:
- Stole **GitHub tokens, npm tokens, SSH keys, `.env` secrets, crypto wallets**
- Abused local **AI CLI tools (Claude, Gemini, Q)** to aid reconnaissance
- Exfiltrated stolen data into **public GitHub repos** named `s1ngularity-repository`, `-0`, `-1`
- Modified `~/.bashrc` & `~/.zshrc` to cause forced shutdowns  

👉 Millions of developers may have been exposed.

---

## ✅ What This Tool Does
`@bluefire-redteam/nx-s1ngularity-check` scans your environment for **all known indicators of compromise (IoCs):**

- **Malicious versions** of Nx / @nx packages in:
  - `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - `npm ls` output
- **Host IoCs:**
  - `sudo shutdown -h 0` in `~/.bashrc` / `~/.zshrc`
  - `/tmp/inventory.txt` or `/tmp/inventory.txt.bak`
- **Node_modules payload check:**
  - Detects `telemetry.js` with malicious markers inside installed Nx packages
- **Exfil files:**
  - Finds `results.b64` (locally or `/tmp`)  
  - Auto-decodes up to 3x Base64 → previews decoded JSON
- **GitHub repos:**
  - Flags attacker-created repos (`s1ngularity-repository`) in your account/org  
  - Requires `GH_TOKEN` or `GITHUB_TOKEN` for API access

---

## 🚀 Quick Start

Run directly with `npx` (no install needed):

```bash
npx @bluefire-redteam/nx-s1ngularity-check
```

> ⚠️ Use the scoped name `@bluefire-redteam/nx-s1ngularity-check`.  
> Do **not** use the unscoped `bluefire-nx-check` package — that is unrelated and will show a “vibe-coded” message.

---

## 🖥️ Example Output

```bash
=== Bluefire Nx s1ngularity Comprehensive Scanner ===

❌ Host IoCs detected (.bashrc/.zshrc/tmp)

--- JSON ---
{
  "summary": {
    "affectedFound": false,
    "iocFound": true,
    "nodeModulesFound": false,
    "resultsB64Found": false,
    "ghFound": false,
    "severity": "high"
  }
}
```

---

## 🛡️ What To Do If Compromised
1. **Remove malicious Nx versions:**
   ```bash
   rm -rf node_modules
   npm cache clean --force
   npm install nx@latest
   ```
2. **Clean persistence:**
   - Remove `sudo shutdown -h 0` lines from `~/.bashrc` / `~/.zshrc`
   - Delete `/tmp/inventory.txt*`
3. **Check GitHub repos:**  
   - Delete suspicious `s1ngularity-repository*` repos if present
4. **Rotate ALL credentials:**  
   - GitHub tokens, npm tokens, SSH keys, API keys, environment secrets
   - Move cryptocurrency funds to new wallets immediately
5. **Audit CI/CD pipelines & logs** for suspicious activity

---

## 🏢 About Bluefire Redteam
Bluefire Redteam is a global leader in **offensive security, AI red teaming, and supply chain defense**.  
We built this tool to help the community **detect, contain, and respond** to the Nx compromise.

👉 Need help with **incident response or supply chain hardening?**  
Contact us: [bluefireredteam.com](https://bluefireredteam.com)

---

## 📜 License
MIT – free to use and share. Please credit **Bluefire Redteam** when referencing.
