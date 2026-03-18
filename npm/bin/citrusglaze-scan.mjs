#!/usr/bin/env node

import { execSync, spawnSync } from "node:child_process";

const python = ["python3", "python"].find((cmd) => {
  try {
    execSync(`${cmd} --version`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
});

if (!python) {
  console.error(
    "Error: Python 3 is required but not found.\n" +
      "Install it from https://www.python.org/downloads/"
  );
  process.exit(1);
}

// Ensure the pip package is installed
try {
  execSync(`${python} -c "import citrusglaze_scan"`, { stdio: "ignore" });
} catch {
  console.log("Installing citrusglaze-scan...");
  try {
    execSync(`${python} -m pip install citrusglaze-scan --quiet --user`, {
      stdio: "inherit",
    });
  } catch {
    console.error(
      "Failed to install citrusglaze-scan. Try manually:\n" +
        "  pip3 install citrusglaze-scan"
    );
    process.exit(1);
  }
}

// Forward all args to the Python CLI
const args = process.argv.slice(2);
const result = spawnSync(python, ["-m", "citrusglaze_scan", ...args], {
  stdio: "inherit",
});

process.exit(result.status ?? 1);
