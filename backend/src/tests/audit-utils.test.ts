const {
  parseAuditReport,
  normalizeThreshold,
  hasBlockingVulnerabilities,
} = require("../../scripts/lib/audit-utils");

describe("audit-utils", () => {
  describe("parseAuditReport", () => {
    it("parses valid npm audit JSON and returns vulnerabilities object", () => {
      const sample = JSON.stringify({ metadata: { vulnerabilities: { low: 1, moderate: 0, high: 2, critical: 0 } } });
      const v = parseAuditReport(sample);
      expect(v).toEqual({ low: 1, moderate: 0, high: 2, critical: 0 });
    });

    it("throws on invalid JSON", () => {
      expect(() => parseAuditReport("not-json")).toThrow(/Failed to parse npm audit JSON/);
    });

    it("throws when metadata.vulnerabilities is missing", () => {
      const sample = JSON.stringify({ metadata: {} });
      expect(() => parseAuditReport(sample)).toThrow(/Invalid npm audit JSON: missing metadata.vulnerabilities section/);
    });
  });

  describe("normalizeThreshold", () => {
    it("accepts known severities", () => {
      expect(normalizeThreshold("low")).toBe("low");
      expect(normalizeThreshold("CRITICAL")).toBe("critical");
      expect(normalizeThreshold(undefined)).toBe("high");
    });

    it("throws on unknown severity", () => {
      expect(() => normalizeThreshold("bogus")).toThrow(/Invalid severity threshold/);
    });
  });

  describe("hasBlockingVulnerabilities", () => {
    it("detects blocking vulnerabilities at or above threshold", () => {
      const v = { low: 0, moderate: 1, high: 0, critical: 0 };
      expect(hasBlockingVulnerabilities(v, "low")).toBe(true);
      expect(hasBlockingVulnerabilities(v, "moderate")).toBe(true);
      expect(hasBlockingVulnerabilities(v, "high")).toBe(false);

      const v2 = { low: 0, moderate: 0, high: 1, critical: 0 };
      expect(hasBlockingVulnerabilities(v2, "high")).toBe(true);
      expect(hasBlockingVulnerabilities(v2, "critical")).toBe(false);
    });
  });
});
