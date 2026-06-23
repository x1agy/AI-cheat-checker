import { app, BrowserWindow, ipcMain } from 'electron';
import * as path from 'path';
import { mkdir, readFile, rm, writeFile } from 'fs/promises';
import { execSync } from 'child_process';
import { copyFileSync, existsSync } from 'fs';

let mainWindow: BrowserWindow | null = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 820,
    icon: path.join(__dirname, '../assets/logo.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  mainWindow.setMenu(null);

  mainWindow.loadFile(path.join(__dirname, '../src/index.html'));
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

const KEY_FILE = 'ollama-key.txt';
const STORAGE_DIR = 'cheat-scanner';

function getStoragePath() {
  return path.join(app.getPath('userData'), STORAGE_DIR);
}

async function readApiKey(): Promise<string | undefined> {
  try {
    const storagePath = getStoragePath();
    const filePath = path.join(storagePath, KEY_FILE);
    const contents = await readFile(filePath, 'utf8');
    return contents.trim();
  } catch {
    return undefined;
  }
}

async function saveApiKey(key: string): Promise<void> {
  const storagePath = getStoragePath();
  await mkdir(storagePath, { recursive: true });
  const filePath = path.join(storagePath, KEY_FILE);
  await writeFile(filePath, key, 'utf8');
}

ipcMain.handle('read-api-key', async () => {
  return await readApiKey();
});

ipcMain.handle('save-api-key', async (_event, key: string) => {
  await saveApiKey(key);
  return true;
});

ipcMain.handle('create-standalone-exe', async (_event, apiKey: string) => {
  try {
    const projectDir = process.cwd();
    const tempDir = path.join(projectDir, 'temp-build');
    await mkdir(tempDir, { recursive: true });

    const configFile = path.join(tempDir, 'config.json');
    await writeFile(configFile, JSON.stringify({ apiKey }), 'utf8');

    const entryFile = path.join(
      projectDir,
      app.isPackaged ? 'resources/dist' : 'dist',
      'index.js'
    );
    if (!existsSync(entryFile)) {
      throw new Error(`Entry file not found: ${entryFile}`);
    }

    const tempPackageJson = {
      name: 'cheat-scanner',
      version: '1.0.0',
      main: app.isPackaged ? '../resources/dist/index.js' : '../dist/index.js',
      bin: app.isPackaged ? '../resources/dist/index.js' : '../dist/index.js',
      pkg: {
        assets: ['config.json'],
        targets: ['node18-win-x64'],
      },
    };

    await writeFile(
      path.join(tempDir, 'package.json'),
      JSON.stringify(tempPackageJson, null, 2),
      'utf8'
    );

    execSync('npx pkg . --output cheat-scanner.exe', {
      stdio: 'inherit',
      cwd: tempDir,
    });

    const downloadsDir = app.getPath('downloads');
    await mkdir(downloadsDir, { recursive: true });

    const sourceExe = path.join(tempDir, 'cheat-scanner.exe');
    const destExe = path.join(downloadsDir, 'cheat-scanner.exe');

    copyFileSync(sourceExe, destExe);

    await rm(tempDir, { recursive: true, force: true });

    return {
      success: true,
      path: destExe,
    };
  } catch (error: any) {
    console.error('Error:', error);
    return {
      success: false,
      error: error?.message || String(error),
    };
  }
});
