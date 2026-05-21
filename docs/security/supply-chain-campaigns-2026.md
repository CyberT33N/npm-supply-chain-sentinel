# Supply-Chain-Lagebild 2026 fuer Node.js / npm

## Ziel und Scope
Dieses Dokument fasst die groessten oeffentlich dokumentierten, fuer Node.js/npm relevanten Supply-Chain-Vorfaelle im Zeitraum ab dem Axios-Vorfall vom `31.03.2026` bis zur AntV-/GitHub-bezogenen Welle vom `19./20.05.2026` zusammen.

Der Fokus ist defensiv:

- verifizierbare Einordnung der Kampagnen,
- technische IOCs und Persistence-Artefakte,
- Unterschiede zwischen separaten Einzelvorfaellen und derselben Wurmfamilie,
- praktische Konsequenzen fuer einen plattformuebergreifenden Node.js-Scanner.

Die maschinenlesbare Datenbasis liegt in `src/data/supply-chain-campaigns-2026.mjs`.

## Direktantworten
Ja: Der Axios-Fall ist ueber normale Websuche sehr gut auffindbar.

Die ausgewerteten Quellen sprechen fuer zwei verschiedene Cluster:

- `Axios` ist nach aktuellem oeffentlichen Stand ein separater Maintainer-Account-Takeover mit eingeschleustem `plain-crypto-js`-Dropper und klassischem RAT/C2.
- `@bitwarden/cli`, `mbt`, `@cap-js/*`, `intercom-client`, `@tanstack/*` und die spaetere `@antv`-/`echarts-for-react`-Welle gehoeren technisch zusammen und passen zur `Shai-Hulud`- bzw. `Mini Shai-Hulud`-Linie.

Wichtig fuer die Benennung:

- Das offizielle `react`-Paket taucht in den ausgewerteten belastbaren Berichten nicht als direkt kompromittiert auf.
- Das offizielle `next`- bzw. `next.js`-Paket taucht in den ausgewerteten belastbaren Berichten ebenfalls nicht als direkt kompromittiert auf.
- `GitHub` ist in diesen Wellen vor allem missbrauchte Infrastruktur: `GitHub Actions`, `OIDC trusted publishing`, `cache poisoning`, `api.github.com` fuer Dead-Drop-Exfiltration und repo-seitige Workflow-Injektion.

## Executive Summary
Die wichtigste technische Trennung ist diese:

- `Axios` arbeitet mit einer eingeschleusten Abhaengigkeit (`plain-crypto-js@4.2.1`), die via `postinstall` einen plattformabhaengigen RAT nachlaedt und zu einer klassischen C2-Domain (`sfrclak.com`) telefoniert.
- `Shai-Hulud` und `Mini Shai-Hulud` sind echte Wurmfamilien: Sie stehlen Publishing- oder CI/CD-Credentials, enumerieren weitere publizierbare Pakete, repacken diese automatisch und verbreiten sich lateral ueber Maintainer, Runner und Projekt-Workspaces weiter.

Die React-/GitHub-Relevanz in den belastbaren Quellen liegt vor allem hier:

- `@tanstack/react-router`, `@tanstack/react-start-*` und verwandte Router/Start-Pakete waren direkt betroffen.
- `echarts-for-react` wurde in der AntV-Welle als Downstream-/Ecosystem-Opfer genannt.
- `GitHub Actions` war bei TanStack der direkte Missbrauchspfad.
- `GitHub GraphQL` und private/oeffentliche GitHub-Repositories wurden in mehreren Wellen als Exfiltrations- oder Propagationskanal missbraucht.

## Chronologische Timeline
### 2026-03-31: Axios
Betroffene Artefakte:

- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js@4.2.1`

Wesentliche Merkmale:

- eingeschleuste Runtime-Abhaengigkeit statt Schadcode direkt in Axios,
- `postinstall`-Ausfuehrung,
- plattformspezifischer RAT fuer Windows, macOS und Linux,
- C2 zu `sfrclak.com:8000`,
- Selbstbereinigung im Paketverzeichnis zur Erschwerung der Forensik.

### 2026-04-22: Bitwarden CLI (`Shai-Hulud: The Third Coming`)
Betroffenes Artefakt:

- `@bitwarden/cli@2026.4.0`

Wesentliche Merkmale:

- `preinstall: node bw_setup.js`,
- Bun-Download von GitHub Releases (`bun-v1.3.13`),
- 10-MB-Payload `bw1.js`,
- GitHub-Commit-Suche als Dead-Drop (`LongLiveTheResistanceAgainstMachines`, `beautifulcastle`),
- Shell-RC-Persistenz (`~/.bashrc`, `~/.zshrc`),
- Wurmfunktion fuer weiteres npm-Repacking ueber gestohlene publish-faehige Tokens.

### 2026-04-29: SAP CAP / mbt (`Mini Shai-Hulud`)
Betroffene Artefakte:

- `mbt@1.2.48`
- `@cap-js/sqlite@2.2.2`
- `@cap-js/postgres@2.2.2`
- `@cap-js/db-service@2.10.1`

Wesentliche Merkmale:

- `preinstall: node setup.mjs`,
- Bun-Bootstrapper,
- 11.6-11.7 MB `execution.js`,
- Exfiltration in GitHub-Repositories mit Beschreibung `A Mini Shai-Hulud has Appeared`,
- IDE-/Agent-Persistenz ueber `.claude/settings.json` und `.vscode/tasks.json`,
- erste deutlich dokumentierte Ausrichtung auf AI-/IDE-Tooling.

### 2026-04-30: Intercom Node SDK
Betroffenes Artefakt:

- `intercom-client@7.0.4`

Wesentliche Merkmale:

- dieselbe `setup.mjs` -> Bun -> Payload-Kette,
- Payload-Umbenennung zu `router_runtime.js`,
- erweiterte Multi-Cloud-Sammlung fuer AWS, GCP und Azure,
- Exfiltration ueber `api.github.com` statt ueber offensichtliche externe C2-Domains,
- starke Hinweise auf Wurm-Propagation aus der SAP-Welle.

### 2026-05-11: TanStack Router/Start
Direkt betroffener Kern:

- 42 `@tanstack/*` Pakete aus dem Router/Start-Bereich,
- 84 kompromittierte Versionen,
- darunter `@tanstack/react-router`, `@tanstack/react-start`, `@tanstack/react-start-client` und verwandte React-, Solid- und Vue-Varianten.

Wesentliche Merkmale:

- Missbrauch von `pull_request_target`,
- GitHub Actions cache poisoning ueber Fork/Base-Vertrauensgrenzen,
- OIDC-Token-Extraktion aus Runner-Speicher,
- Publikation ueber legitime Trusted-Publishing-/SLSA-Provenance-Pfade,
- grossformatige Payload `router_init.js`,
- Persistenz in `.claude/`, `.vscode/`, LaunchAgent/systemd,
- Exfiltration ueber Session/Oxen (`filev2.getsession.org`) und GitHub GraphQL.

### 2026-05-19 / 2026-05-20: AntV / echarts-for-react / Dormant-Package-Welle
Oeffentlich prominent genannte betroffene Artefakte:

- `jest-canvas-mock@2.5.3`
- `size-sensor@1.0.4`
- `@antv/l7-core@2.26.10`
- viele weitere `@antv/*` Pakete,
- `echarts-for-react`,
- `timeago.js`,
- weitere spaeter identifizierte Pakete ausserhalb des `@antv`-Scopes

Wesentliche Merkmale:

- Phantom-`optionalDependencies` auf `@antv/setup` mit GitHub-Commit-Refs,
- `prepare: bun run index.js && exit 1` im optionalen Dropper,
- spaetere repackte Pakete mit Root-`index.js` (~500 KB) und `preinstall: bun run index.js`,
- Sigstore/Fulcio/Rekor-Provenance-Missbrauch bzw. signierte Schadpakete,
- erneute Fokusverlagerung auf GitHub Actions unter Linux und CI/CD-Secrets.

## Ist das alles "derselbe Wurm"?
### Nein fuer Axios
`Axios` passt nicht sauber in die Mini-Shai-Hulud-Linie.

Dafuer sprechen:

- anderer Infektionsmechanismus (`plain-crypto-js` statt Bun-/setup.mjs-Kette),
- klassischer RAT mit eigener Domain/IP,
- andere Persistenz- und Payload-Struktur,
- keine belastbaren Hinweise aus den ausgewerteten Quellen auf dieselbe GitHub-/OIDC-/Session-P2P-Architektur.

### Ja fuer Bitwarden -> SAP -> Intercom -> TanStack -> AntV
Diese Vorfaelle teilen eine klare technische Linie:

- Bun als Ausfuehrungs-/Evasion-Layer,
- obfuskierte grosse JS-Payloads,
- Credentialsammlung ueber Entwickler- und Runner-Kontexte,
- Repacking weiterer Pakete mit `preinstall`/`setup.mjs` oder verwandten Hooks,
- Missbrauch von GitHub als Trust Boundary, C2 oder Dead-Drop,
- `.claude`-/`.vscode`-Persistenz,
- fortlaufende Evolution von Payload-Namen und Exfil-Kanaelen statt kompletter Neuentwicklung.

## Technische IOCs nach Familie
### Axios
Paket- und Versions-Iocs:

- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js@4.2.1`

Netzwerk-Iocs:

- `sfrclak.com`
- `142.11.206.73`
- `http://sfrclak.com:8000/6202033`

Datei-/Pfad-Iocs:

- macOS: `/Library/Caches/com.apple.act.mond`
- Linux: `/tmp/ld.py`
- Windows: `%PROGRAMDATA%\wt`
- Windows transient: `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
- Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run -> MicrosoftUpdate`

### Shai-Hulud / Mini Shai-Hulud
Typische Paket-Hooks und Dateien:

- `preinstall: node setup.mjs`
- `preinstall: bun run index.js`
- `prepare: bun run index.js && exit 1`
- `bw_setup.js`
- `bw1.js`
- `execution.js`
- `router_runtime.js`
- `router_init.js`

Typische Projekt-/Workspace-Persistenz:

- `.claude/settings.json` mit verdraechtigen `SessionStart`-Hooks
- `.claude/setup.mjs`
- `.claude/execution.js`
- `.claude/router_runtime.js`
- `.vscode/tasks.json` mit `runOn: folderOpen` und Loader-/Payload-Pfaden
- `.vscode/setup.mjs`
- `.github/workflows/codeql_analysis.yml`
- `.github/workflows/format-check.yml`

Typische Home-/OS-Persistenz:

- `~/.local/bin/gh-token-monitor.sh`
- `~/.config/systemd/user/gh-token-monitor.service`
- `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`

Typische Text-/Payload-Marker:

- `A Mini Shai-Hulud has Appeared`
- `LongLiveTheResistanceAgainstMachines`
- `beautifulcastle`
- `__decodeScrambled`
- `__DAEMONIZED`
- `claude@users.noreply.github.com`
- `@antv/setup`
- `github:antvis/G2#1916faa365f2788b6e193514872d51a242876569`
- `github:antvis/G2#7cb42f57561c321ecb09b4552802ae0ac55b3a7a`

Netzwerk-/DNS-Iocs mit sinnvoller Blockierbarkeit:

- `filev2.getsession.org`
- `seed1.getsession.org`
- `seed2.getsession.org`
- `seed3.getsession.org`
- `api.masscan.cloud`
- `git-tanstack.com`
- `t.m-kosche.com`
- `zero.masscan.cloud`
- `audit.checkmarx.cx`

Detection-only, nicht blind global hosts-blocken:

- `api.github.com`
- `github.com`
- `registry.npmjs.org`
- `metadata.google.internal`
- `169.254.169.254`
- `169.254.170.2`

## Warum die Hosts-Datei allein nicht reicht
Eine wichtige Architekturgrenze:

- Die Hosts-Datei kann Hostnamen aufloesen oder ins Leere zeigen lassen.
- Sie kann keine Roh-IPs direkt blockieren.
- Sie ist fuer `api.github.com` als pauschale Gegenmassnahme ungeeignet, weil das legitime CI/CD- und Entwicklerpfade massiv beschaedigen wuerde.
- Bei Session/Oxen ist DNS-Blocking auf den bekannten Domains sinnvoller als starres IP-Blocking.

Deshalb trennt der Scanner bewusst:

- hosts-taugliche Domains,
- Firewall-/Proxy-taugliche IPs,
- Detection-only-Indikatoren mit hohem Kollateralschaden bei pauschalem Block.

## Repo-Ablageort und Namenskonvention
Fuer das Standalone-Repo `npm-supply-chain-sentinel` ist die Ablage so modelliert:

- `src/cli` ist die Delivery-Schicht. Dort lebt nur die ausfuehrbare CLI und die Host-/Projekt-Orchestrierung.
- `src/data` ist die kuratierte Intelligence-/Policy-Schicht. Dort liegen versionierte Kampagnen-, IOC- und Heuristikdaten.
- `docs/security` ist die dokumentarische Read-Model-Schicht fuer Incident Response, Analysten und Reviewer.

Aus DDD-Sicht ist das der sauberste Zuschnitt fuer diesen Bounded Context:

- Der eigentliche Fachkern ist nicht "Node-Scripting", sondern `Supply-Chain Threat Detection and Response Policy`.
- Die CLI ist nur ein Adapter an dieses fachliche Modell.
- Die Blocklisten und Reports sind bewusst getrennte Lesemodelle und nicht Teil des operativen Domain-Kerns.

Aus 12-Factor-Sicht bleibt das Tool dadurch klar:

- Konfiguration kommt ueber Flags und explizite Dateipfade.
- Es gibt keinen versteckten Prozesszustand.
- Generierte Artefakte bleiben explizit in `docs/security` und werden nicht mit dem Quellmodell vermischt.

## Was im Repo implementiert wurde
### Node.js-Scanner
Datei:

- `src/cli/scan-supply-chain-campaigns.mjs`

Der Scanner prueft:

- exakte kompromittierte Paketversionen in `package.json`, `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`, `bun.lock`, `bun.lockb`,
- installierte `node_modules` auf exact matches und dokumentierte Heuristiken,
- `.claude`-/`.vscode`-/`.github/workflows`-Persistenzmuster,
- feste Home-/OS-Artefakte,
- Windows-Registry fuer den Axios-Run-Key,
- standardmaessig das Projekt, in dem der Scanner selbst liegt, nicht einfach nur das aktuelle Arbeitsverzeichnis,
- optional einen echten maschinenweiten Scan ueber alle lokal erreichbaren Dateisystem-Wurzeln,
- `Worker Threads` fuer parallele Verarbeitung von Top-Level-Teilbaeumen,
- optionale Blocklist-Erzeugung,
- optionales Einspielen einer verwalteten Hosts-Sektion.

### Datenbasis
Datei:

- `src/data/supply-chain-campaigns-2026.mjs`

Diese Datei enthaelt:

- exakte Package-/Versionsregeln,
- heuristische Manifest-, Hook- und Payload-Indikatoren,
- Plattformpfade,
- Netzwerk-Iocs,
- Blocklist-Klassifizierung.

## Nutzung
Minimaler Repo-Scan:

```bash
node src/cli/scan-supply-chain-campaigns.mjs
```

Der Default ist jetzt bewusst projektgebunden:

- Das Skript bestimmt aus seinem eigenen Ablageort den Projekt-Root.
- Ohne weiteren Flag scannt es nur dieses Projekt rekursiv plus die dokumentierten festen Home-/Maschinen-Artefakte.

Mehrere Roots scannen:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --root ../repo-a --root ../repo-b
```

Maschinenweiter Scan:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide
```

Mit expliziter Worker-Zahl:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --machine-wide --workers 8
```

Wichtig:

- `--machine-wide` und `--root` sind absichtlich nicht kombinierbar.
- Im maschinenweiten Modus werden alle lokal erreichbaren Dateisystem-Wurzeln als Startpunkte benutzt.
- Innerhalb dieser Wurzeln werden Top-Level-Teilbaeume auf Worker Threads verteilt.

Blocklisten schreiben:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --write-blocklists ./docs/security/blocklists
```

Hosts-Datei aktualisieren:

```bash
node src/cli/scan-supply-chain-campaigns.mjs --apply-hosts
```

Hinweis:

- Unter Windows braucht das Aendern der Hosts-Datei in der Regel ein erhoehtes Terminal.
- Unter Linux/macOS braucht das Aendern von `/etc/hosts` entsprechende Rechte.

## Grenzen der Aussage
Eine ehrliche Grenze ist wichtig:

- Kein lokaler Scanner kann fuer einen sich aktiv entwickelnden Wurm `100%` absolute Vollstaendigkeit garantieren.
- Dieses Setup deckt die derzeit oeffentlich dokumentierten, hochrelevanten Node.js/npm-bezogenen IOCs und Verhaltensmuster aus den ausgewerteten Berichten ab.
- Fuer spaetere Copycats, neue Payload-Namen oder bisher nicht oeffentlich dokumentierte repackte Packages bleibt eine Restunsicherheit.

Deshalb kombiniert der Scanner absichtlich:

- exakte kompromittierte Versionen,
- dateibasierte IOCs,
- Hook-/Loader-/Persistence-Heuristiken,
- getrennte DNS-/Firewall-/Detection-only-Listen.

## Primarquellen und Kernberichte
Axios:

- [Axios post mortem](https://github.com/axios/axios/issues/10636)
- [StepSecurity: axios compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Malwarebytes: Axios supply chain attack chops away at npm trust](https://www.malwarebytes.com/blog/news/2026/04/axios-supply-chain-attack-chops-away-at-npm-trust)

Shai-Hulud / Mini Shai-Hulud:

- [Endor Labs: Bitwarden CLI attack](https://www.endorlabs.com/learn/shai-hulud-the-third-coming----inside-the-bitwarden-cli-2026-4-0-supply-chain-attack)
- [StepSecurity: A Mini Shai-Hulud Has Appeared](https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared)
- [StepSecurity: intercom-client hijacked](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked)
- [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [StepSecurity: Mini Shai-Hulud hits npm ecosystem](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [Snyk: TanStack npm packages compromised](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [Microsoft: AntV packages enable CI/CD credential theft](https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/)
- [Endor Labs: AntV Sigstore wave](https://www.endorlabs.com/learn/mini-shai-hulud-returns-42-malicious-npm-packages-fake-sigstore-badges-in-antv-ecosystem-attack)
- [Aikido: AntV npm supply chain attack](https://www.aikido.dev/blog/mini-shai-hulud-antv-npm-supply-chain-attack)
