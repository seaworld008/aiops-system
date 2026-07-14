import { spawn } from "node:child_process";
import { constants } from "node:os";

const [timeoutRaw, graceRaw, command, ...args] = process.argv.slice(2);
const timeoutSeconds = Number(timeoutRaw);
const graceSeconds = Number(graceRaw);

if (
  !command ||
  !Number.isInteger(timeoutSeconds) ||
  timeoutSeconds < 1 ||
  !Number.isInteger(graceSeconds) ||
  graceSeconds < 1
) {
  console.error(
    "code-map deadline runner: usage <timeout-seconds> <grace-seconds> <command> [args...]",
  );
  process.exit(2);
}

const child = spawn(command, args, {
  stdio: "inherit",
  env: process.env,
  detached: process.platform !== "win32",
});

let childExited = false;
let timedOut = false;
let forwardedSignal = "";
let killTimer;
let exitTimer;

function signalNumber(signal) {
  return constants.signals[signal] ?? 1;
}

function signalChild(signal) {
  if (!child.pid) return;
  try {
    if (process.platform !== "win32") process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch (error) {
    if (error?.code !== "ESRCH") {
      console.error(
        "code-map deadline runner: failed to forward " +
          signal +
          ": " +
          error.message,
      );
    }
  }
}

function processGroupIsAlive() {
  if (!child.pid || process.platform === "win32") return !childExited;
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    return true;
  }
}

function forcedExitCode() {
  if (timedOut) return 124;
  return 128 + signalNumber(forwardedSignal);
}

function finishForcedTermination() {
  signalChild("SIGKILL");
  if (!exitTimer) {
    exitTimer = setTimeout(() => process.exit(forcedExitCode()), 100);
  }
}

function armForcedKill() {
  if (killTimer) return;
  killTimer = setTimeout(finishForcedTermination, graceSeconds * 1000);
}

const deadline = setTimeout(() => {
  timedOut = true;
  console.error(
    "code-map deadline runner: command exceeded " +
      timeoutSeconds +
      " seconds; terminating its process group",
  );
  signalChild("SIGTERM");
  armForcedKill();
}, timeoutSeconds * 1000);

for (const signal of ["SIGHUP", "SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    if (forwardedSignal) {
      finishForcedTermination();
      return;
    }
    forwardedSignal = signal;
    signalChild(signal);
    armForcedKill();
  });
}

child.on("error", (error) => {
  clearTimeout(deadline);
  if (killTimer) clearTimeout(killTimer);
  if (exitTimer) clearTimeout(exitTimer);
  console.error("code-map deadline runner: failed to start command: " + error.message);
  process.exit(2);
});

child.on("exit", (code, signal) => {
  childExited = true;
  clearTimeout(deadline);
  if (timedOut || forwardedSignal) {
    if (!processGroupIsAlive()) {
      if (killTimer) clearTimeout(killTimer);
      process.exit(forcedExitCode());
    }
    armForcedKill();
    return;
  }
  if (killTimer) clearTimeout(killTimer);
  if (code !== null) {
    process.exit(code);
  }
  process.exit(128 + signalNumber(signal));
});
