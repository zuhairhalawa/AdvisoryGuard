#!/usr/bin/env node
import { run } from "./main.js";

try {
  process.exitCode = run(process.argv.slice(2), {
    stdout: process.stdout,
    stderr: process.stderr,
    env: process.env,
  });
} catch (e) {
  process.stderr.write(`advisoryguard: unexpected internal error: ${(e as Error).stack ?? String(e)}\n`);
  process.exitCode = 70;
}
