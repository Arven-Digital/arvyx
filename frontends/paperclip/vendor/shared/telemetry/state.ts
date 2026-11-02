import { randomUUID, randomBytes } from "node:crypto";
import { constants, openSync, closeSync, fstatSync, fsyncSync, linkSync, unlinkSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { TelemetryState } from "./types.js";

export function loadOrCreateState(stateDir: string, version: string): TelemetryState {
  const filePath = path.join(stateDir, "state.json");

  const readState = (): TelemetryState => {
    const fd = openSync(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > 16384 || (stat.mode & 0o077) !== 0
        || typeof process.getuid === "function" && stat.uid !== process.getuid()) throw new Error("Telemetry state requires a private regular file");
      const raw = readFileSync(fd, "utf-8");
      const parsed = JSON.parse(raw) as TelemetryState;
      if (typeof parsed.installId === "string" && /^[a-f0-9-]{36}$/.test(parsed.installId)
        && typeof parsed.salt === "string" && /^[a-f0-9]{64}$/.test(parsed.salt)
        && typeof parsed.createdAt === "string" && typeof parsed.firstSeenVersion === "string") {
        return parsed;
      }
      throw new Error("Invalid telemetry state; offline recovery required");
    } finally { closeSync(fd); }
  };
  try { return readState(); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }

  const state: TelemetryState = {
    installId: randomUUID(),
    salt: randomBytes(32).toString("hex"),
    createdAt: new Date().toISOString(),
    firstSeenVersion: version,
  };

  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const temporary = path.join(stateDir, `.state-${randomUUID()}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { writeFileSync(fd, JSON.stringify(state, null, 2) + "\n", "utf-8"); fsyncSync(fd); }
  finally { closeSync(fd); }
  try { linkSync(temporary, filePath); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
  finally { unlinkSync(temporary); }
  return readState();
}
