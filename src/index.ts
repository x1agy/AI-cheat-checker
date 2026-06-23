import { promises as fs, readFileSync } from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';

interface SuspiciousPattern {
  name: string;
  regex: RegExp;
}

interface ScanEntry {
  path: string;
  type: 'file' | 'directory';
  mtime?: string;
  matches: string[];
}

interface RegistryEntry {
  key: string;
  name: string;
  type: string;
  data: string;
  matches: string[];
}

const suspiciousPatterns: SuspiciousPattern[] = [
  { name: 'cheat', regex: /cheat/i },
  { name: 'чит', regex: /чит/i },
  { name: 'hack', regex: /hack/i },
  { name: 'aimbot', regex: /aimbot/i },
  { name: 'esp', regex: /esp/i },
  { name: 'wallhack', regex: /wallhack/i },
  { name: 'cheatengine', regex: /cheatengine/i },
  { name: 'injector', regex: /injector/i },
  { name: 'bypass', regex: /bypass/i },
  { name: 'trainer', regex: /trainer/i },
  { name: 'bot', regex: /bot/i },
  { name: 'hacktool', regex: /hacktool/i },
  { name: 'crack', regex: /crack/i },
  { name: 'loader', regex: /loader/i },
  { name: 'hackhub', regex: /hackhub/i },
  { name: 'dll', regex: /\.dll/i },
];

function findSuspicious(text: string): string[] {
  const normalized = text.toLowerCase();
  const matches = new Set<string>();

  for (const pattern of suspiciousPatterns) {
    if (pattern.regex.test(normalized)) {
      matches.add(pattern.name);
    }
  }

  return Array.from(matches);
}

async function pathExists(location: string): Promise<boolean> {
  try {
    await fs.access(location);
    return true;
  } catch {
    return false;
  }
}

async function collectDirectoryEntries(
  root: string,
  maxItems = 12000
): Promise<ScanEntry[]> {
  const results: ScanEntry[] = [];
  const stack: string[] = [root];
  let processed = 0;

  while (stack.length > 0 && processed < maxItems) {
    const current = stack.pop();
    if (!current) break;

    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (processed >= maxItems) {
        break;
      }
      processed += 1;
      const entryPath = path.join(current, entry.name);
      const matches = findSuspicious(entryPath + ' ' + entry.name);
      const scanEntry: ScanEntry = {
        path: entryPath,
        type: entry.isDirectory() ? 'directory' : 'file',
        matches,
      };

      if (!entry.isDirectory()) {
        try {
          const stats = await fs.stat(entryPath);
          scanEntry.mtime = stats.mtime.toISOString();
        } catch {
          // ignore stat failures
        }
      }

      if (matches.length > 0) {
        results.push(scanEntry);
      }

      if (entry.isDirectory()) {
        stack.push(entryPath);
      }
    }
  }

  return results;
}

async function collectRecentPrefetch(root: string): Promise<ScanEntry[]> {
  const results: ScanEntry[] = [];

  try {
    const dirents = await fs.readdir(root, { withFileTypes: true });
    const fileRecords: ScanEntry[] = [];

    for (const dirent of dirents) {
      if (!dirent.isFile()) {
        continue;
      }
      const filePath = path.join(root, dirent.name);
      const matches = findSuspicious(filePath + ' ' + dirent.name);
      const stats = await fs.stat(filePath);
      fileRecords.push({
        path: filePath,
        type: 'file',
        mtime: stats.mtime.toISOString(),
        matches,
      });
    }

    fileRecords.sort((a, b) => {
      if (!a.mtime || !b.mtime) return 0;
      return b.mtime.localeCompare(a.mtime);
    });

    return fileRecords.slice(0, 60).filter((entry) => entry.matches.length > 0);
  } catch {
    return results;
  }
}

function parseRegistryOutput(key: string, raw: string): RegistryEntry[] {
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const entries: RegistryEntry[] = [];

  for (const line of lines) {
    if (/^HKEY_/i.test(line)) {
      continue;
    }

    const parts = line.split(/\s{2,}/).filter(Boolean);
    if (parts.length < 2) {
      continue;
    }

    let name = parts[0];
    let type = '';
    let data = '';

    if (parts.length === 2) {
      type = parts[0];
      data = parts[1];
      name = '(default)';
    } else {
      type = parts[1];
      data = parts.slice(2).join(' ');
    }

    const matches = findSuspicious(name + ' ' + data);
    entries.push({ key, name, type, data, matches });
  }

  return entries;
}

function queryRegistryKey(key: string): {
  raw: string;
  entries: RegistryEntry[];
  error?: string;
} {
  try {
    const raw = execFileSync('reg', ['query', key, '/s'], {
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
    });
    const entries = parseRegistryOutput(key, raw);
    return { raw, entries };
  } catch (error: any) {
    return { raw: '', entries: [], error: error.message || String(error) };
  }
}

function runCommand(
  command: string,
  args: string[]
): { output: string; error?: string } {
  try {
    const output = execFileSync(command, args, {
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
    });
    return { output };
  } catch (error: any) {
    const message =
      error.stdout || error.stderr || error.message || String(error);
    return { output: '', error: message };
  }
}

function parseInstallDate(systeminfo: string): string | undefined {
  const lines = systeminfo.split(/\r?\n/);
  for (const line of lines) {
    const normalized = line.trim();
    const patterns = [
      /Original Install Date:\s*(.+)$/i,
      /Дата первоначальной установки ОС:\s*(.+)$/i,
      /Install Date:\s*(.+)$/i,
      /InstallDate:\s*(.+)$/i,
    ];
    for (const pattern of patterns) {
      const match = normalized.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
    }
  }
  return undefined;
}

function buildAiPrompt(report: Record<string, unknown>): string {
  return `
  You are a game security analyst reviewing an artifact report produced by our internal cheat-scanner.

Your task:
Analyze the report for suspicious cheat client activity, injectors, loaders, hidden persistence, recent deleted cheat-related artifacts, suspicious registry entries, and likely compromise indicators.

Important scope rules:

* Do NOT react to our own tool named cheat-scanner or any of its files, folders, logs, registry traces, or execution artifacts.
* Do NOT react to normal Windows system files, Windows components, drivers, services, DLLs, scheduled tasks, or default registry entries.
* Do NOT react to known legitimate game clients, game launchers, game stores, or their cache artifacts.
* Do NOT react to known anti-cheat systems, even if they belong to other games.
* Do NOT report generic game files, game folders, shaders, logs, crash dumps, launcher cache, or normal game telemetry.
* Do NOT report MUI-cache entries by themselves. MUI-cache only shows that something was displayed/executed and is not suspicious without a clearly suspicious executable name or path.
* Do NOT report Telegram WebView, browser WebView, Discord cache, Chromium cache, Electron cache, or normal app cache artifacts unless they clearly reference a cheat, injector, loader, stealer, RAT, or suspicious executable.
* Do NOT overreact to generic words such as overlay, hook, driver, service, launcher, updater, helper, bootstrapper, crashhandler, webview, cef, runtime, redistributable, or anticheat when they belong to legitimate software.
* Do NOT treat deleted files as suspicious only because they are deleted. Deleted artifacts are suspicious only if their names, paths, timestamps, or surrounding context indicate cheat clients, injectors, loaders, bypass tools, credential stealers, or malware.

Known legitimate items to ignore unless there is strong contradictory evidence:

* Steam, Epic Games, EA App / Origin, Ubisoft Connect / Uplay, Battle.net, GOG Galaxy, Rockstar Launcher, Riot Client, Xbox App, Microsoft Store games.
* Easy Anti-Cheat, BattlEye, Vanguard, VAC, FACEIT AC, Ricochet, PunkBuster, Xigncode, GameGuard, ESEA, FiveM/RedM legitimate components.
* Telegram, Discord, browsers, WebView2, Chromium Embedded Framework, Overwolf, NVIDIA/AMD/Intel overlays, OBS, MSI Afterburner, RTSS, Logitech/Razer/Corsair software.
* Microsoft Visual C++ Redistributables, .NET, DirectX, Windows Defender, Windows Update, system32, SysWOW64, WinSxS, ProgramData Microsoft components.

Suspicious indicators to prioritize:

* Executables, DLLs, drivers, scripts, archives, or folders with cheat-related names such as cheat, hack, loader, injector, bypass, spoofer, hwid, aimbot, wallhack, esp, radar, triggerbot, silentaim, modmenu, executor, external, internal, unlocker, dumper, mapper, kdmapper, drvmap, manualmap.
* Suspicious tools used for injection or driver loading: DLL injectors, manual mappers, unsigned kernel drivers, vulnerable driver loaders, process hollowing tools.
* Persistence connected to suspicious files: Run keys, Services, Scheduled Tasks, Startup folder, WMI persistence, IFEO debugger keys, AppInit_DLLs, Shell/Userinit modifications.
* Suspicious recently deleted artifacts where the name/path strongly suggests cheat software, injector, loader, bypass, spoofer, or malware.
* Suspicious paths such as Temp, Downloads, Desktop, AppData, ProgramData, Public, Recycle Bin, random-name folders, or hidden folders containing cheat/injector-style files.
* Evidence chains: the same suspicious name appearing across Prefetch, Amcache/ShimCache, UserAssist, RecentFiles, registry, deleted files, browser downloads, archives, and execution traces.
* Compromise indicators such as stealers, RATs, suspicious PowerShell/cmd scripts, credential dumpers, unknown remote access tools, or persistence pointing to unknown executables.
* Known cheat client names, injector names, loader names, bypass tool names.
* 

Analysis rules:

* Be conservative and cold-minded.
* Do not invent findings.
* Do not force suspicion from weak artifacts.
* Do not report safe/benign artifacts just because they look technical.
* Prefer evidence chains over single weak indicators.
* If a finding is only weak or ambiguous, mark it as "low confidence" or omit it.
* If something is suspicious only because of its name but there is no execution or persistence evidence, say so clearly.
* Do not provide removal, mitigation, cleanup, bypass, or evasion advice.
* Look for specially for those cheats:
  Impulse Menu 
  Luna Menu 
  Cherax
  Stand (Stand Mod Menu)
  2Take1 Menu 
  Midnight
  Rebound
  North Menu
  Eulen 
  Sapphire Menu
  X-Force
* Don't offer additional actions
* Don't SRP launcher

Output format:

1. Concise conclusion:

   * Clear suspicious cheat activity found / likely suspicious activity / inconclusive / no strong suspicious findings.
2. Most suspicious findings:

   * List only important findings.
   * For each finding include: artifact, path/key if available, why suspicious, confidence level.
3. Recent deleted suspicious artifacts:

   * Only list deleted items that are actually suspicious.
4. Suspicious persistence:

   * Only list persistence entries pointing to suspicious files.
5. Ignore summary:

   * Briefly mention categories intentionally ignored, such as game clients, anti-cheats, Windows files, MUI-cache-only entries, Telegram/WebView/cache artifacts.
  ${JSON.stringify(
    report,
    null,
    2
  )} Respond with a summary on Russian language. НЕ ПИШИ РЕКОМЕНДАЦИИ ПО УДАЛЕНИЮ ИЛИ УСТРАНЕНИЮ, ТОЛЬКО АНАЛИЗ.`;
}

function getApiKey() {
  try {
    const configPath = path.join(__dirname, 'config.json');

    return JSON.parse(readFileSync(configPath, 'utf8')).apiKey;
  } catch (e) {
    console.error(e);
    return '';
  }
}

async function analyzeWithOllama(prompt: string): Promise<string | undefined> {
  try {
    const apiKey = getApiKey();

    const response = await fetch('https://ollama.com/api/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(apiKey && { Authorization: `Bearer ${apiKey}` }),
      },
      body: JSON.stringify({
        model: 'gpt-oss:120b',
        stream: false,
        messages: [
          {
            role: 'system',
            content:
              "You are a games security analyst. Analyze the collected artifact report below for suspicious cheat client activity, hidden persistence, recent deleted file artifacts, and any likely compromise indicators. Provide a concise conclusion and list the most suspicious findings. Ignore game clients that are known to be legitimate. Focus on potential cheat clients, injectors, and suspicious registry entries. Don't give advise on how to remove or mitigate, just provide a summary of the findings. Don't try to find to hard, your job is cold minded analysis. Don't react on cheat-scanner it's our program. Don't react on any windows system files, only focus on suspicious cheat clients and injectors. Don't react on any known game clients like steam, epic games, origin, uplay, etc. Don't react on any known game launchers like battle.net, gog galaxy, etc. Don't react on any known anti-cheat like easy anti-cheat, battleye, valve anti-cheat, etc. Don't react on any known game files or folders. Focus on the suspicious findings and provide a summary of the most important ones.",
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Ollama API error:', response.status, errorText);
      return undefined;
    }

    const data = await response.json();
    return data?.message?.content?.trim();
  } catch (error: any) {
    console.error('Ollama API error:', error?.message || error);
    return undefined;
  }
}

async function collectDirectorySummary(root: string, label: string) {
  const exists = await pathExists(root);
  const suspicious = exists ? await collectDirectoryEntries(root) : [];
  const recentItems = exists ? await collectRecentPrefetch(root) : [];

  return {
    label,
    path: root,
    exists,
    suspiciousCount: suspicious.length,
    suspiciousEntries: suspicious,
    recentItems,
  };
}

async function main() {
  if (process.platform !== 'win32') {
    console.error('This scanner is intended to run on Windows.');
  }

  const appData =
    process.env.APPDATA ||
    path.join(
      process.env.USERPROFILE || 'C:\\Users\\Default',
      'AppData',
      'Roaming'
    );
  const localAppData =
    process.env.LOCALAPPDATA ||
    path.join(
      process.env.USERPROFILE || 'C:\\Users\\Default',
      'AppData',
      'Local'
    );
  const userProfile = process.env.USERPROFILE || 'C:\\Users\\Default';
  const windowsRoot =
    process.env.SystemRoot || process.env.windir || 'C:\\Windows';

  const rootsToScan = [
    { label: 'AppData Roaming root', path: appData },
    { label: 'AppData Local root', path: localAppData },
    {
      label: 'Roaming Microsoft Windows',
      path: path.join(appData, 'Microsoft', 'Windows'),
    },
    {
      label: 'Windows Prefetch folder',
      path: path.join(windowsRoot, 'Prefetch'),
    },
    {
      label: 'Roaming Recent folder',
      path: path.join(appData, 'Microsoft', 'Windows', 'Recent'),
    },
  ];

  const pathReports = [] as Array<
    Awaited<ReturnType<typeof collectDirectorySummary>>
  >;
  for (const root of rootsToScan) {
    pathReports.push(await collectDirectorySummary(root.path, root.label));
  }

  const registryKeys = [
    'HKCU\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache',
    'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched',
    'HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store',
  ];

  const registryReports = registryKeys.map((key) => {
    const { raw, entries, error } = queryRegistryKey(key);
    return {
      key,
      error,
      totalEntries: entries.length,
      suspiciousEntries: entries.filter((entry) => entry.matches.length > 0),
      raw: error ? undefined : raw,
    };
  });

  const systeminfoResult = runCommand('systeminfo', []);
  const installDate = systeminfoResult.output
    ? parseInstallDate(systeminfoResult.output)
    : undefined;

  const report = {
    scanTime: new Date().toISOString(),
    environment: {
      platform: process.platform,
      appData,
      localAppData,
      userProfile,
      windowsRoot,
    },
    pathReports,
    registryReports,
    systeminfo: {
      installDate,
      raw: systeminfoResult.output || undefined,
      error: systeminfoResult.error,
    },
  };

  console.log('=== Cheat Scanner Report ===');
  console.log(JSON.stringify(report, null, 2));

  const aiPrompt = buildAiPrompt(report);
  const aiResponse = await analyzeWithOllama(aiPrompt);

  if (aiResponse) {
    console.log('\n=== Ollama AI Analysis ===');
    console.log(aiResponse);
  }
}

function waitForExit(): Promise<void> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      console.log('\nPress Enter to exit.');
      process.stdin.resume();
      process.stdin.once('data', () => resolve());
    } else {
      setTimeout(resolve, 2000);
    }
  });
}

main()
  .then(() => waitForExit())
  .catch((error) => {
    console.error('Unhandled error:', error);
  });
