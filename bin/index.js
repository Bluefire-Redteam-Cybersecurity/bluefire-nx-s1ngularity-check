#!/usr/bin/env node
// Bluefire Redteam - Nx "s1ngularity" comprehensive scanner
// Node 18+, zero deps.

import { readFileSync, existsSync, readdirSync } from 'fs';
import { homedir } from 'os';
import { execSync } from 'child_process';
import path from 'path';
import https from 'https';

const AFFECTED = {
  "nx": ["20.9.0","20.10.0","20.11.0","20.12.0","21.5.0","21.6.0","21.7.0","21.8.0"],
  "@nrwl/nx": ["20.9.0","20.10.0","20.11.0","20.12.0","21.5.0","21.6.0","21.7.0","21.8.0"],
  "@nx/devkit": ["21.5.0","20.9.0"],
  "@nx/eslint": ["21.5.0"],
  "@nx/js": ["21.5.0","20.9.0"],
  "@nx/node": ["21.5.0","20.9.0"],
  "@nx/workspace": ["21.5.0","20.9.0"],
  "@nx/key": ["3.2.0"],
  "@nx/enterprise-cloud": ["3.2.0"]
};

// Expanded repo name heuristics (phase 1, 2, 3)
const REPO_NAMES = [
  /^s1ngularity-repository(-[01])?$/,
  /^s1ngularity-repository-[a-z0-9]{5}$/i,
  /_bak$/i
];

// IoC strings and prompt fragments (expanded to detect variant telemetry.js payloads)
const MAL_STRINGS = [
  "s1ngularity-repository",
  "sudo shutdown -h 0",
  "--dangerously-skip-permissions",
  "--trust-all-tools",
  "--yolo",
  // Phase-specific prompt fragments observed in telemetry.js variants:
  "You are an authorized penetration testing agent",
  "You are a file-search agent",
  "Search the filesystem and locate text configuration and environment-definition files",
  "Recursively search local paths on Linux/macOS",
  "produce a newline-separated inventory of full file paths",
  "write it to /tmp/inventory.txt"
];

const cwd = process.cwd();
const home = homedir();
const args = process.argv.slice(2);
const results = {
  time: new Date().toISOString(),
  cwd,
  lockFindings: [],
  nodeModulesFindings: [],
  resultsB64: [],
  iocs: {
    bashrcShutdown: false,
    zshrcShutdown: false,
    tmpInventory: false,
    tmpInventoryBak: false
  },
  github: {
    checked: false,
    userReposFlagged: [],
    orgReposFlagged: [],
    searchReposFlagged: []
  },
  summary: {
    affectedFound: false,
    iocFound: false,
    ghFound: false,
    nodeModulesFound: false,
    resultsB64Found: false,
    severity: "none"
  }
};

function readSafe(p) {
  try { return readFileSync(p, 'utf8'); } catch { return null; }
}

function searchLockfile(file, content) {
  for (const [pkg, versions] of Object.entries(AFFECTED)) {
    versions.forEach(v => {
      // handle both "pkg": "version" and yarn/pnpm lockfile forms loosely
      const rx1 = new RegExp(`"${pkg}"\\s*:\\s*"${v}"`, 'g');
      const rx2 = new RegExp(`${pkg}@${v}(\\s|$)`);
      if (rx1.test(content) || rx2.test(content)) {
        results.lockFindings.push({ file, package: pkg, version: v });
      }
    });
  }
}

function scanLocks() {
  const files = ['package-lock.json','pnpm-lock.yaml','yarn.lock'].map(f => path.join(cwd, f));
  files.forEach(f => {
    const data = readSafe(f);
    if (data) searchLockfile(f, data);
  });
  try {
    const out = execSync('npm ls nx @nrwl/nx @nx/devkit @nx/js @nx/node @nx/workspace @nx/eslint @nx/key @nx/enterprise-cloud', { stdio: ['ignore','pipe','ignore'] }).toString();
    for (const [pkg, versions] of Object.entries(AFFECTED)) {
      versions.forEach(v => {
        const rx = new RegExp(`${pkg}@${v}(\\s|$)`);
        if (rx.test(out)) results.lockFindings.push({ file: 'npm-ls', package: pkg, version: v });
      });
    }
  } catch {}
}

function scanIocs() {
  const bashrc = path.join(home, '.bashrc');
  const zshrc  = path.join(home, '.zshrc');
  const b = readSafe(bashrc) || '';
  const z = readSafe(zshrc) || '';
  if (b.includes('sudo shutdown -h 0')) results.iocs.bashrcShutdown = true;
  if (z.includes('sudo shutdown -h 0')) results.iocs.zshrcShutdown = true;
  results.iocs.tmpInventory = existsSync('/tmp/inventory.txt');
  results.iocs.tmpInventoryBak = existsSync('/tmp/inventory.txt.bak');
}

function scanNodeModules(dir) {
  const nm = path.join(dir, 'node_modules');
  if (!existsSync(nm)) return;
  const suspects = ['nx','@nrwl/nx','@nx/devkit','@nx/js','@nx/node','@nx/workspace','@nx/eslint','@nx/key','@nx/enterprise-cloud'];
  suspects.forEach(pkg => {
    const pkgPath = path.join(nm, pkg);
    if (existsSync(pkgPath)) {
      try {
        // Using readdirSync recursive option (Node 18+)
        const files = readdirSync(pkgPath, { recursive: true });
        files.forEach(f => {
          if (f.includes('telemetry.js')) {
            const full = path.join(pkgPath, f);
            const data = readSafe(full);
            if (data && MAL_STRINGS.some(s => data.includes(s))) {
              results.nodeModulesFindings.push({ file: full, marker: MAL_STRINGS.filter(s=>data.includes(s)) });
            }
          }
        });
      } catch {}
    }
  });
}

function tryDecodeBase64(content, rounds=3) {
  let buf;
  try { buf = Buffer.from(content.trim(), 'base64'); } catch { return ''; }
  for (let i=1;i<rounds;i++) {
    try { buf = Buffer.from(buf.toString('utf8').trim(), 'base64'); }
    catch { break; }
  }
  return buf.toString('utf8').slice(0,500);
}

function scanResultsB64(dir) {
  const paths = ['results.b64','/tmp/results.b64'].map(p=>path.join(dir,p));
  paths.forEach(p=>{
    if (existsSync(p)) {
      const raw = readSafe(p);
      if (raw) {
        results.resultsB64.push({ file:p, preview: tryDecodeBase64(raw) });
      }
    }
  });
}

// ---- GitHub scanning ----

function ghRequest(url, token) {
  return new Promise((resolve,reject)=>{
    const opts = {
      headers: {
        'User-Agent': 'bluefire-nx-check',
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    };
    https.get(url, opts, res=>{
      let data='';
      res.on('data', chunk=>data+=chunk);
      res.on('end', ()=>{
        try { resolve(JSON.parse(data)); }
        catch(e){ reject(e); }
      });
    }).on('error', reject);
  });
}

async function scanGitHub() {
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (!token) return;
  results.github.checked = true;

  let orgIndex = args.indexOf('--org');
  let userIndex = args.indexOf('--user');
  let searchIndex = args.indexOf('--search');

  if (orgIndex !== -1 && args[orgIndex+1]) {
    const org = args[orgIndex+1];
    const url = `https://api.github.com/orgs/${org}/repos?per_page=100`;
    const repos = await ghRequest(url, token).catch(e=>({error:e}));
    if (Array.isArray(repos)) {
      repos.forEach(r=>{
        // match by name OR by description containing s1ngularity
        const nameMatch = REPO_NAMES.some(rx=>rx.test(r.name));
        const desc = (r.description||'').toString();
        const descMatch = /s1ngularity/i.test(desc);
        if (nameMatch || descMatch) {
          results.github.orgReposFlagged.push(r.full_name);
        }
      });
    } else {
      // non-array response (error)
      // keep error visible but continue
      // console.error("GitHub API error for org:", repos);
    }
  }

  if (userIndex !== -1 && args[userIndex+1]) {
    const user = args[userIndex+1];
    const url = `https://api.github.com/users/${user}/repos?per_page=100`;
    const repos = await ghRequest(url, token).catch(e=>({error:e}));
    if (Array.isArray(repos)) {
      repos.forEach(r=>{
        const nameMatch = REPO_NAMES.some(rx=>rx.test(r.name));
        const desc = (r.description||'').toString();
        const descMatch = /s1ngularity/i.test(desc);
        if (nameMatch || descMatch) {
          results.github.userReposFlagged.push(r.full_name);
        }
      });
    } else {
      // console.error("GitHub API error for user:", repos);
    }
  }

  if (searchIndex !== -1 && args[searchIndex+1]) {
    const rawQuery = args[searchIndex+1];
    const query = encodeURIComponent(rawQuery);
    const url = `https://api.github.com/search/repositories?q=${query}&per_page=50`;
    const res = await ghRequest(url, token).catch(e=>({error:e}));
    if (res && Array.isArray(res.items)) {
      res.items.forEach(r=>{
        const nameMatch = REPO_NAMES.some(rx=>rx.test(r.name));
        const desc = (r.description||'').toString();
        const descMatch = /s1ngularity/i.test(desc);
        if (nameMatch || descMatch) {
          results.github.searchReposFlagged.push(r.full_name);
        }
      });
    } else {
      // console.error("GitHub API error for search:", res);
    }
  }
}

// ---- End GitHub scanning ----

function finalize() {
  const affectedFound = results.lockFindings.length > 0;
  const iocFound = results.iocs.bashrcShutdown || results.iocs.zshrcShutdown || results.iocs.tmpInventory || results.iocs.tmpInventoryBak;
  const nodeModulesFound = results.nodeModulesFindings.length > 0;
  const resultsB64Found = results.resultsB64.length > 0;
  const ghFound = (results.github.userReposFlagged?.length||0) > 0 ||
                  (results.github.orgReposFlagged?.length||0) > 0 ||
                  (results.github.searchReposFlagged?.length||0) > 0;

  results.summary = { affectedFound, iocFound, nodeModulesFound, resultsB64Found, ghFound, severity: (affectedFound||iocFound||nodeModulesFound||resultsB64Found||ghFound) ? 'high':'none' };

  console.log('\n=== Bluefire Nx s1ngularity Comprehensive Scanner ===\n');
  if (results.summary.severity==='none') {
    console.log('✅ No affected versions or IoCs found.');
  } else {
    if (affectedFound) console.log('❌ Affected Nx versions in lockfiles/npm ls');
    if (iocFound) console.log('❌ Host IoCs detected (.bashrc/.zshrc/tmp)');
    if (nodeModulesFound) console.log('❌ Malicious telemetry.js found in node_modules');
    if (resultsB64Found) console.log('❌ results.b64 file detected locally');
    if (ghFound) console.log('❌ Suspicious GitHub repos detected');
  }
  console.log('\n--- JSON ---');
  console.log(JSON.stringify(results,null,2));
  if (results.summary.severity!=='none') process.exit(1);
}

(async function main(){
  scanLocks();
  scanIocs();
  scanNodeModules(cwd);
  scanResultsB64(cwd);
  await scanGitHub();
  finalize();
})();
