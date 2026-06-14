const { app, BrowserWindow, dialog, shell } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const path = require("path");
const fs = require("fs");

const SERVER_URL = "http://127.0.0.1:8000";
const HEALTH_URL = `${SERVER_URL}/api/overview`;
const ROOT_DIR = path.resolve(__dirname, "..", "..");

let mainWindow;
let backendProcess;

function ignoreBrokenPipe(stream) {
  stream.on("error", (error) => {
    if (error.code !== "EPIPE") {
      throw error;
    }
  });
}

ignoreBrokenPipe(process.stdout);
ignoreBrokenPipe(process.stderr);

function safeLog(message, stream = process.stdout) {
  if (!stream.writable || stream.destroyed) {
    return;
  }

  try {
    stream.write(`${message}\n`);
  } catch (error) {
    if (error.code !== "EPIPE") {
      throw error;
    }
  }
}

function requestHealth(timeoutMs = 1000) {
  return new Promise((resolve) => {
    const req = http.get(HEALTH_URL, (res) => {
      res.resume();
      resolve(res.statusCode >= 200 && res.statusCode < 500);
    });

    req.on("error", () => resolve(false));
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForBackend(maxAttempts = 45) {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (await requestHealth()) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return false;
}

function pythonExecutable() {
  const venvPython = process.platform === "win32"
    ? path.join(ROOT_DIR, ".venv", "Scripts", "python.exe")
    : path.join(ROOT_DIR, ".venv", "bin", "python");

  if (fs.existsSync(venvPython)) {
    return venvPython;
  }

  return process.platform === "win32" ? "python" : "python3";
}

function systemPythonExecutable() {
  return process.platform === "win32" ? "python" : "python3";
}

function runCommand(command, args, label) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: ROOT_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    child.stdout.on("data", (chunk) => {
      safeLog(`[${label}] ${chunk.toString().trim()}`);
    });

    child.stderr.on("data", (chunk) => {
      safeLog(`[${label}] ${chunk.toString().trim()}`, process.stderr);
    });

    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${label} exited with code ${code}`));
      }
    });
  });
}

async function ensurePythonEnvironment() {
  const venvPython = process.platform === "win32"
    ? path.join(ROOT_DIR, ".venv", "Scripts", "python.exe")
    : path.join(ROOT_DIR, ".venv", "bin", "python");

  if (!fs.existsSync(venvPython)) {
    await runCommand(systemPythonExecutable(), ["-m", "venv", ".venv"], "python-setup");
  }

  try {
    await runCommand(venvPython, [
      "-c",
      "import fastapi, uvicorn, psutil, sklearn, numpy, watchdog, wmi, win32evtlog",
    ], "python-check");
  } catch {
    await runCommand(venvPython, ["-m", "pip", "install", "-r", "requirements.txt"], "python-deps");
  }
}

async function ensureBackend() {
  if (await requestHealth()) {
    return true;
  }

  await ensurePythonEnvironment();

  backendProcess = spawn(pythonExecutable(), ["-m", "backend"], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      PYTHONUNBUFFERED: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });

  backendProcess.stdout.on("data", (chunk) => {
    safeLog(`[backend] ${chunk.toString().trim()}`);
  });

  backendProcess.stderr.on("data", (chunk) => {
    safeLog(`[backend] ${chunk.toString().trim()}`, process.stderr);
  });

  backendProcess.on("exit", (code, signal) => {
    safeLog(`[backend] exited with code ${code ?? "null"} signal ${signal ?? "null"}`);
    backendProcess = null;
  });

  return waitForBackend();
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1100,
    minHeight: 720,
    backgroundColor: "#050816",
    title: "Trinetra Sentinel",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.webContents.setZoomFactor(1.0);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.loadURL(SERVER_URL);
}

function stopBackend() {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill();
  }
}

app.whenReady().then(async () => {
  const ready = await ensureBackend();

  if (!ready) {
    dialog.showErrorBox(
      "Trinetra Sentinel could not start",
      "The Python backend did not become available on http://127.0.0.1:8000. Run run_trinetra.bat once to install Python dependencies, then try npm run electron again."
    );
    app.quit();
    return;
  }

  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", stopBackend);
