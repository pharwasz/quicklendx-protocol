#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const {
  buildSummary,
  hasBlockingVulnerabilities,
  normalizeThreshold,
  parseAuditReport,
} = require("./lib/audit-utils");

function main() {
  const reportPath = process.argv[2] || "audit-report.json";
  const threshold = normalizeThreshold(process.argv[3] || process.env.AUDIT_SEVERITY || "high");
  const absolutePath = path.resolve(process.cwd(), reportPath);

  // If the report is missing, attempt a couple of sensible fallbacks that
  // account for different working-directory usages in CI (root vs backend/).
  const candidatePaths = [absolutePath,
    path.resolve(process.cwd(), reportPath),
    path.resolve(process.cwd(), "..", reportPath),
    path.resolve(process.cwd(), "backend", reportPath),
  ];

  const foundPath = candidatePaths.find((p) => fs.existsSync(p));
  if (!foundPath) {
    console.error(
      `Security gate failed: audit report not found. Searched paths: ${candidatePaths.join(", ")}`
    );
    process.exit(1);
  }

  const reportFilePath = foundPath;

  const reportText = fs.readFileSync(reportFilePath, "utf8");
  const vulnerabilities = parseAuditReport(reportText);

  console.log(`Dependency audit summary: ${buildSummary(vulnerabilities)}`);
  console.log(`Blocking threshold: ${threshold}`);

  if (hasBlockingVulnerabilities(vulnerabilities, threshold)) {
    console.error(
      `Security gate failed: Found vulnerabilities at or above ${threshold}. ` +
        "Resolve issues or explicitly adjust threshold with AUDIT_SEVERITY."
    );
    process.exit(1);
  }

  console.log("Security gate passed: No blocking vulnerabilities were found.");
}

try {
  main();
} catch (error) {
  console.error(`Security gate failed: ${error.message}`);
  process.exit(1);
}
