import { readFile } from "node:fs/promises";

const acceptedAdvisories = new Set(["GHSA-QWWW-VCR4-C8H2"]);
const reportPath = process.argv[2];

if (!reportPath) {
  console.error("Usage: node scripts/check-npm-audit.mjs <npm-audit.json>");
  process.exit(2);
}

let report;
try {
  report = JSON.parse(await readFile(reportPath, "utf8"));
} catch (error) {
  console.error(`Could not read npm audit JSON: ${error.message}`);
  process.exit(2);
}

if (report.error) {
  const summary =
    typeof report.error === "string"
      ? report.error
      : report.error.summary || report.error.message || "unknown npm audit error";
  console.error(`npm audit failed: ${summary}`);
  process.exit(2);
}

if (!report.vulnerabilities || typeof report.vulnerabilities !== "object") {
  console.error("npm audit returned an unsupported report without vulnerabilities.");
  process.exit(2);
}

const vulnerabilities = report.vulnerabilities;
const acceptedPackages = new Map();
const resolving = new Set();

function advisoryId(advisory) {
  const match = String(advisory.url || "").match(/GHSA-[a-z0-9-]+/i);
  return match ? match[0].toUpperCase() : "";
}

function isAcceptedAdvisory(advisory) {
  const id = advisoryId(advisory);
  const packageName = advisory.name || advisory.dependency;
  return (
    acceptedAdvisories.has(id) &&
    packageName === "react-router" &&
    advisory.severity === "high"
  );
}

function isAcceptedPackage(packageName) {
  if (acceptedPackages.has(packageName)) {
    return acceptedPackages.get(packageName);
  }
  if (resolving.has(packageName)) {
    return false;
  }

  const vulnerability = vulnerabilities[packageName];
  if (
    !vulnerability ||
    vulnerability.severity !== "high" ||
    !Array.isArray(vulnerability.via) ||
    vulnerability.via.length === 0
  ) {
    acceptedPackages.set(packageName, false);
    return false;
  }

  resolving.add(packageName);
  const accepted = vulnerability.via.every((cause) =>
    typeof cause === "string"
      ? isAcceptedPackage(cause)
      : isAcceptedAdvisory(cause),
  );
  resolving.delete(packageName);
  acceptedPackages.set(packageName, accepted);
  return accepted;
}

const blocking = [];
const accepted = [];

for (const [packageName, vulnerability] of Object.entries(vulnerabilities)) {
  if (vulnerability.severity === "critical") {
    blocking.push(`${packageName} (critical)`);
    continue;
  }

  if (vulnerability.severity === "high") {
    if (isAcceptedPackage(packageName)) {
      accepted.push(packageName);
    } else {
      blocking.push(`${packageName} (high)`);
    }
  }
}

if (accepted.length > 0) {
  console.log(
    `Accepted advisory GHSA-qwww-vcr4-c8h2 is present through: ${accepted.join(", ")}.`,
  );
  console.log(
    "MSAP does not use React Router unstable RSC APIs or server actions; review the exception on dependency changes.",
  );
}

if (blocking.length > 0) {
  console.error(`Blocking npm audit findings: ${blocking.join(", ")}`);
  process.exit(1);
}

const metadata = report.metadata?.vulnerabilities || {};
console.log(
  `npm audit policy passed (critical=${metadata.critical || 0}, high=${metadata.high || 0}).`,
);
