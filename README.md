# 🔍 Bluefire Redteam – Nx "s1ngularity" Supply Chain Scanner

**Free open-source tool to detect if your projects or systems were impacted by the August 2025 Nx `s1ngularity` compromise.**  
Published by [Bluefire Redteam](https://bluefire-redteam.com)

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
`bluefire-nx-check` scans your environment for **all known indicators of compromise (IoCs):**

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

Run locally (no install needed):

```bash
npx bluefire-nx-check
```

Optional GitHub/org check:

```bash
GH_TOKEN=ghp_xxx BLUEFIRE_ORGS="your-org,another-org" npx bluefire-nx-check
```

**Exit code:**  
- `0` → No issues detected  
- `1` → IoCs or malicious versions found  

---

## 🖥️ Example Output

```bash
=== Bluefire Nx s1ngularity Comprehensive Scanner ===

❌ Affected Nx versions in lockfiles/npm ls
❌ Host IoCs detected (.bashrc/.zshrc/tmp)
❌ results.b64 file detected locally

--- JSON ---
{
  "summary": {
    "affectedFound": true,
    "iocFound": true,
    "nodeModulesFound": false,
    "resultsB64Found": true,
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
Bluefire Redteam is a global company with expertise in **offensive security, AI red teaming, and supply chain defense**.  
We built this tool to help the community **detect, contain, and respond** to the Nx compromise.

👉 Need help with **incident response or supply chain hardening?**  
Contact us: [bluefire-redteam.com](https://bluefire-redteam.com)

---

## 📜 License
MIT – free to use and share. Please credit **Bluefire Redteam** when referencing.


![npm](https://img.shields.io/npm/v/bluefire-nx-check)
![license](https://img.shields.io/github/license/bluefire-redteam/bluefire-nx-check)
![build](https://img.shields.io/github/actions/workflow/status/bluefire-redteam/bluefire-nx-check/ci.yml?branch=main)

