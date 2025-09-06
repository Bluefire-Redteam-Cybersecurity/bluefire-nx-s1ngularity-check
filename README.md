# 🔍 Bluefire Redteam's Nx "s1ngularity" Supply Chain Scanner(New Update)

![npm (scoped)](https://img.shields.io/npm/v/%40bluefire-redteam%2Fnx-s1ngularity-check)

**Free, open-source scanner from [Bluefire Redteam](https://bluefire-redteam.com)**  
Detect if your systems or projects were impacted by the August 2025 Nx *s1ngularity* supply-chain compromise.  

---

## 🚨 What Happened?
On **Aug 26–27, 2025**, multiple malicious versions of the **Nx build system packages** were published to npm.  
They contained a **postinstall malware (`telemetry.js`)** that:
- Stole **GitHub tokens, npm tokens, SSH keys, `.env` secrets, crypto wallets**
- Abused local **AI CLI tools (Claude, Gemini, Q)** to aid reconnaissance
- Exfiltrated stolen data into **public GitHub repos** named:
  - `s1ngularity-repository`
  - `s1ngularity-repository-0`
  - `s1ngularity-repository-1`
  - `s1ngularity-repository-<5letters>` (Phase 2)
  - `*_bak` with description `"S1ngularity"` (Phase 3)
- Modified `~/.bashrc` & `~/.zshrc` to cause forced shutdowns  

👉 Thousands of secrets and repos were exposed across multiple phases of this attack.

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
  - Detects `telemetry.js` with malicious markers across all known prompt variants (Phase 1–3)
- **Exfil files:**
  - Finds `results.b64` (locally or `/tmp`)  
  - Auto-decodes up to 3x Base64 → previews decoded JSON
- **GitHub repos (expanded detection):**
  - Flags attacker-created repos in your account/org:
    - `s1ngularity-repository`, `-0`, `-1`  
    - `s1ngularity-repository-<5letters>`  
    - Any repo suffixed with `_bak` or with description `"S1ngularity"`  
  - Requires `GH_TOKEN` or `GITHUB_TOKEN` for API access
- **GitHub search mode (NEW in v1.0.7):**
  - Use `--search <query>` to check all public repos on GitHub for IoCs

---

## 🚀 Quick Start

Run directly with `npx` (no install needed):

```bash
npx @bluefire-redteam/nx-s1ngularity-check
```

> ⚠️ Use the scoped name `@bluefire-redteam/nx-s1ngularity-check`.  
> Do **not** use any unscoped package — that is not us!

---

## 🔍 Usage Examples

### Scan current project
```bash
npx @bluefire-redteam/nx-s1ngularity-check
```

### Scan a GitHub user’s repos
```bash
GH_TOKEN=ghp_xxx npx @bluefire-redteam/nx-s1ngularity-check --user someuser
```

### Scan a GitHub organization
```bash
GH_TOKEN=ghp_xxx npx @bluefire-redteam/nx-s1ngularity-check --org myorg
```

### Search all public GitHub repos (NEW in v1.0.7)
```bash
GH_TOKEN=ghp_xxx npx @bluefire-redteam/nx-s1ngularity-check --search s1ngularity-repository
```

---

## 🖥️ Example Output

```bash
=== Bluefire Nx s1ngularity Comprehensive Scanner ===

❌ Suspicious GitHub repos detected

--- JSON ---
{
  "summary": {
    "affectedFound": false,
    "iocFound": false,
    "nodeModulesFound": false,
    "resultsB64Found": false,
    "ghFound": true,
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
   - Delete suspicious repos flagged by the scanner
4. **Rotate ALL credentials:**  
   - GitHub tokens, npm tokens, SSH keys, API keys, environment secrets
   - Move cryptocurrency funds to new wallets immediately
5. **Audit CI/CD pipelines & logs** for suspicious activity

---

## 🏢 About Bluefire Redteam
Bluefire Redteam is a global leader in **offensive security, AI red teaming, and supply chain defense**.  
We built this tool to help the community **detect, contain, and respond** to the Nx compromise.

👉 Need help with **incident response or supply chain hardening?**  
Contact us: [bluefire-redteam.com](https://bluefire-redteam.com)

---

## 📦 Version Updates
- **v1.0.7 (latest)** — Added Phase 2/3 repo detection, expanded `telemetry.js` IoCs, new `--search` flag  
- **v1.0.6** — Added `--org` and `--user` scanning, initial GitHub integration  
- **v1.0.5 and earlier** — Initial release with local project + host scanning

---

## 📜 License
MIT – free to use and share. Please credit **Bluefire Redteam** when referencing.

