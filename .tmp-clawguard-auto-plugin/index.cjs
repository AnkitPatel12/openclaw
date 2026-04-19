const fs = require("node:fs/promises");
const fsSync = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);
const pendingFindingsBySession = new Map();

const DEFAULTS = {
  scannerPath: "~/.openclaw/skills/clawguard/scripts/clawguard-scan",
  scanTools: ["web_fetch", "pdf", "image"],
  blockOnSanitize: true,
  maxUrlBytes: 2 * 1024 * 1024,
  timeoutMs: 20_000,
};

const SUPPORTED_TEXT_TYPES = new Set([
  "text/plain",
  "text/html",
  "text/markdown",
  "application/json",
  "application/xml",
  "application/xhtml+xml",
]);
const MAX_PENDING_FINDINGS_PER_SESSION = 8;

function resolveHome(input) {
  if (typeof input !== "string") {
    return input;
  }
  if (input === "~") {
    return os.homedir();
  }
  if (input.startsWith("~/")) {
    return path.join(os.homedir(), input.slice(2));
  }
  return input;
}

function normalizePluginConfig(raw) {
  const cfg = raw && typeof raw === "object" ? raw : {};
  return {
    scannerPath:
      typeof cfg.scannerPath === "string" && cfg.scannerPath.trim()
        ? resolveHome(cfg.scannerPath.trim())
        : resolveHome(DEFAULTS.scannerPath),
    scanTools: Array.isArray(cfg.scanTools)
      ? cfg.scanTools.filter((value) => typeof value === "string").map((value) => value.trim())
      : [...DEFAULTS.scanTools],
    blockOnSanitize:
      typeof cfg.blockOnSanitize === "boolean" ? cfg.blockOnSanitize : DEFAULTS.blockOnSanitize,
    maxUrlBytes:
      typeof cfg.maxUrlBytes === "number" && Number.isFinite(cfg.maxUrlBytes) && cfg.maxUrlBytes > 0
        ? Math.floor(cfg.maxUrlBytes)
        : DEFAULTS.maxUrlBytes,
    timeoutMs:
      typeof cfg.timeoutMs === "number" && Number.isFinite(cfg.timeoutMs) && cfg.timeoutMs >= 1000
        ? Math.floor(cfg.timeoutMs)
        : DEFAULTS.timeoutMs,
  };
}

function getString(record, key) {
  const value = record?.[key];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function getStringArray(record, key) {
  const value = record?.[key];
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((entry) => typeof entry === "string")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function isHttpLike(input) {
  return /^https?:\/\//i.test(input) || /^data:/i.test(input);
}

function extensionFromSource(input) {
  const withoutQuery = input.split(/[?#]/, 1)[0];
  const ext = path.extname(withoutQuery);
  return ext && ext.length <= 10 ? ext : "";
}

function extensionFromContentType(contentType) {
  if (!contentType) {
    return "";
  }
  const base = contentType.split(";", 1)[0].trim().toLowerCase();
  if (base === "application/pdf") {
    return ".pdf";
  }
  if (base === "image/png") {
    return ".png";
  }
  if (base === "image/jpeg") {
    return ".jpg";
  }
  if (base === "image/webp") {
    return ".webp";
  }
  if (base === "image/gif") {
    return ".gif";
  }
  if (base.startsWith("text/")) {
    return ".txt";
  }
  return "";
}

function shouldTreatAsText(contentType) {
  if (!contentType) {
    return false;
  }
  const base = contentType.split(";", 1)[0].trim().toLowerCase();
  return base.startsWith("text/") || SUPPORTED_TEXT_TYPES.has(base);
}

async function fetchUrlForScan(url, config) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": "OpenClaw ClawGuard Auto/0.1",
      },
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const contentType = response.headers.get("content-type") || undefined;
    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    if (buffer.byteLength > config.maxUrlBytes) {
      throw new Error(`response too large (${buffer.byteLength} bytes)`);
    }

    // Always write to a temp file so the scanner receives a --file path.
    // Passing large HTML as a --text CLI arg hits OS ARG_MAX limits and the
    // scanner returns "no text extracted" / action:pass instead of detecting
    // injections.
    const suffix =
      (shouldTreatAsText(contentType) ? extensionFromContentType(contentType) || ".html" : null) ||
      extensionFromContentType(contentType) ||
      extensionFromSource(url) ||
      ".bin";
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawguard-auto-"));
    const tempPath = path.join(tempDir, `scan${suffix}`);
    await fs.writeFile(tempPath, buffer);
    const filename = path.basename(url.split(/[?#]/, 1)[0] || `scan${suffix}`) || `scan${suffix}`;
    return {
      kind: "file",
      filePath: tempPath,
      contentType,
      filename,
      cleanup: async () => {
        await fs.rm(tempDir, { recursive: true, force: true });
      },
    };
  } finally {
    clearTimeout(timer);
  }
}

async function runScanner(scanTarget, config) {
  const args = [];
  if (scanTarget.kind === "text") {
    args.push("--text", scanTarget.content);
  } else {
    args.push("--file", scanTarget.filePath);
  }
  if (scanTarget.contentType) {
    args.push("--content-type", scanTarget.contentType);
  }
  if (scanTarget.filename) {
    args.push("--filename", scanTarget.filename);
  }
  args.push("--tool-name", scanTarget.toolName);

  const { stdout } = await execFileAsync(config.scannerPath, args, {
    timeout: config.timeoutMs,
    maxBuffer: 10 * 1024 * 1024,
  });
  return JSON.parse(stdout);
}

function buildBlockReason(details) {
  const reasons = Array.isArray(details?.verdict?.reasons)
    ? details.verdict.reasons.filter((value) => typeof value === "string")
    : [];
  const source = typeof details?.source === "string" ? details.source : details?.toolName;
  const action = details?.action === "sanitize" ? "sanitized" : "blocked";
  const verdict = details?.verdict && typeof details.verdict === "object" ? details.verdict : {};
  const ruleMatches = Array.isArray(verdict?.details?.rule_matches)
    ? verdict.details.rule_matches.filter((value) => value && typeof value === "object")
    : [];
  const uniqueRuleNames = [
    ...new Set(
      ruleMatches
        .map((match) => (typeof match.name === "string" ? match.name.trim() : ""))
        .filter(Boolean),
    ),
  ];
  const evidence = [
    ...new Set(
      ruleMatches
        .map((match) =>
          typeof match.text === "string" ? match.text.trim().replace(/\s+/g, " ") : "",
        )
        .filter(Boolean),
    ),
  ]
    .slice(0, 3)
    .map((text) => `"${text.slice(0, 120)}"`);
  const reasonText = reasons.slice(0, 2).join("; ");
  const ruleText = uniqueRuleNames.length > 0 ? uniqueRuleNames.slice(0, 4).join(", ") : "";
  const evidenceText = evidence.length > 0 ? evidence.join("; ") : "";
  const parts = [
    `ClawGuard ${action} ${source} before it reached the model.`,
    ruleText ? `Matched rules: ${ruleText}.` : "",
    reasonText ? `Reasons: ${reasonText}.` : "",
    evidenceText ? `Evidence: ${evidenceText}.` : "",
  ].filter(Boolean);
  return parts.join(" ");
}

function summarizeReasons(result) {
  const reasons = Array.isArray(result?.verdict?.reasons)
    ? result.verdict.reasons.filter((value) => typeof value === "string")
    : [];
  return reasons.slice(0, 2).join(" | ") || "no reasons";
}

function extractRuleMatches(result) {
  return Array.isArray(result?.verdict?.details?.rule_matches)
    ? result.verdict.details.rule_matches.filter((value) => value && typeof value === "object")
    : [];
}

function buildFinding(result, params) {
  if (!result || typeof result !== "object" || result.action === "pass") {
    return null;
  }

  const ruleMatches = extractRuleMatches(result);
  const matchedRules = [
    ...new Set(
      ruleMatches
        .map((match) => (typeof match.name === "string" ? match.name.trim() : ""))
        .filter(Boolean),
    ),
  ];
  const evidence = [
    ...new Set(
      ruleMatches
        .map((match) =>
          typeof match.text === "string" ? match.text.trim().replace(/\s+/g, " ") : "",
        )
        .filter(Boolean),
    ),
  ].slice(0, 4);
  const reasons = Array.isArray(result?.verdict?.reasons)
    ? result.verdict.reasons.filter((value) => typeof value === "string")
    : [];

  return {
    toolName: params.toolName,
    source: params.source,
    action: result.action,
    stage: params.stage,
    layerReached:
      typeof result?.verdict?.layer_reached === "string" ? result.verdict.layer_reached : undefined,
    matchedRules,
    evidence,
    reasons,
  };
}

function resolveStoreKey(ctx) {
  // sessionKey may be undefined in some channel contexts (e.g. Discord DMs).
  // Fall back to runId or sessionId so findings are never silently dropped.
  return ctx?.sessionKey || ctx?.runId || ctx?.sessionId || null;
}

function rememberFinding(storeKey, finding) {
  if (!storeKey || !finding) {
    return;
  }
  const existing = pendingFindingsBySession.get(storeKey) ?? [];
  const dedupeKey = JSON.stringify({
    toolName: finding.toolName,
    source: finding.source,
    action: finding.action,
    stage: finding.stage,
    matchedRules: finding.matchedRules,
    evidence: finding.evidence,
  });
  const deduped = existing.filter((entry) => entry.dedupeKey !== dedupeKey);
  deduped.push({ ...finding, dedupeKey });
  pendingFindingsBySession.set(storeKey, deduped.slice(-MAX_PENDING_FINDINGS_PER_SESSION));
}

function consumeFindings(storeKey) {
  if (!storeKey) {
    return [];
  }
  const findings = pendingFindingsBySession.get(storeKey) ?? [];
  pendingFindingsBySession.delete(storeKey);
  return findings;
}

function buildUserFacingFindingNotice(finding) {
  const actionLabel =
    finding.action === "sanitize"
      ? "sanitized suspicious fetched content"
      : finding.stage === "before_tool_call"
        ? "blocked a suspicious fetch before it reached the model"
        : "detected suspicious prompt-injection content in the fetched result";
  const sourceLabel = finding.source || finding.toolName || "external content";
  const lines = [`ClawGuard ${actionLabel} from ${sourceLabel}.`];

  if (finding.matchedRules?.length) {
    lines.push(`Matched rules: ${finding.matchedRules.slice(0, 6).join(", ")}`);
  }
  if (finding.reasons?.length) {
    lines.push(`Reasons: ${finding.reasons.slice(0, 3).join(" | ")}`);
  }
  if (finding.evidence?.length) {
    lines.push(
      `Evidence: ${finding.evidence
        .slice(0, 3)
        .map((text) => `"${text.slice(0, 140)}"`)
        .join("; ")}`,
    );
  }
  return lines.join("\n");
}

function buildCombinedFindingReply(findings) {
  const notices = findings.map((finding) => buildUserFacingFindingNotice(finding)).filter(Boolean);
  if (notices.length === 0) {
    return null;
  }
  return notices.join("\n\n");
}

async function maybeScanCandidate(candidate, config, logger) {
  let target = candidate;
  let cleanup = null;
  try {
    logger.debug(
      `clawguard-auto: scanning tool=${candidate.toolName} source=${candidate.label} kind=${candidate.kind}`,
    );
    if (candidate.kind === "url") {
      target = await fetchUrlForScan(candidate.url, config);
      cleanup = target.cleanup || null;
      target.toolName = candidate.toolName;
    }

    const result = await runScanner(target, config);
    const finding = buildFinding(result, {
      toolName: candidate.toolName,
      source: candidate.label,
      stage: "before_tool_call",
    });
    if (result?.action === "block") {
      logger.warn(
        `clawguard-auto: blocked tool=${candidate.toolName} source=${candidate.label} reasons=${summarizeReasons(result)}`,
      );
      logger.warn(
        `clawguard-auto: block-detail ${buildBlockReason({ ...result, source: candidate.label })}`,
      );
      return {
        block: true,
        blockReason: buildBlockReason({ ...result, source: candidate.label }),
        result,
        finding,
      };
    }
    if (result?.action === "sanitize" && config.blockOnSanitize) {
      logger.warn(
        `clawguard-auto: blocked-sanitize tool=${candidate.toolName} source=${candidate.label} reasons=${summarizeReasons(result)}`,
      );
      logger.warn(
        `clawguard-auto: block-detail ${buildBlockReason({ ...result, source: candidate.label })}`,
      );
      return {
        block: true,
        blockReason: buildBlockReason({ ...result, source: candidate.label }),
        result,
        finding,
      };
    }
    logger.debug(
      `clawguard-auto: allowed tool=${candidate.toolName} source=${candidate.label} action=${result?.action ?? "pass"}`,
    );
    return { block: false, result, finding };
  } catch (error) {
    logger.warn(`clawguard-auto: scan skipped for ${candidate.label}: ${String(error)}`);
    return null;
  } finally {
    if (typeof cleanup === "function") {
      try {
        await cleanup();
      } catch {
        // Ignore tmp cleanup failures.
      }
    }
  }
}

function collectToolResultCandidates(toolName, params, result) {
  const resultRecord = result && typeof result === "object" ? result : null;
  if (toolName !== "web_fetch" || !resultRecord) {
    return [];
  }

  const text = getString(resultRecord, "text");
  if (!text) {
    return [];
  }

  const url =
    getString(params, "url") ||
    getString(resultRecord, "finalUrl") ||
    getString(resultRecord, "url");
  const contentType = getString(resultRecord, "contentType") || "text/plain";
  const filename =
    (typeof url === "string" && path.basename(url.split(/[?#]/, 1)[0] || "web-fetch.txt")) ||
    "web-fetch.txt";

  return [
    {
      kind: "text",
      content: text,
      contentType,
      filename,
      label: url || filename,
      toolName,
    },
  ];
}

function collectCandidates(toolName, params) {
  const record = params && typeof params === "object" ? params : {};
  if (toolName === "web_fetch") {
    const url = getString(record, "url");
    return url ? [{ kind: "url", url, label: url, toolName }] : [];
  }
  if (toolName === "pdf") {
    const refs = [];
    const single = getString(record, "pdf");
    if (single) {
      refs.push(single);
    }
    refs.push(...getStringArray(record, "pdfs"));
    return refs.map((ref) =>
      isHttpLike(ref)
        ? { kind: "url", url: ref, label: ref, toolName }
        : { kind: "file", filePath: resolveHome(ref), label: ref, toolName },
    );
  }
  if (toolName === "image") {
    const refs = [];
    const single = getString(record, "image");
    if (single) {
      refs.push(single);
    }
    refs.push(...getStringArray(record, "images"));
    return refs.map((ref) =>
      isHttpLike(ref)
        ? { kind: "url", url: ref, label: ref, toolName }
        : { kind: "file", filePath: resolveHome(ref.replace(/^@/, "")), label: ref, toolName },
    );
  }
  return [];
}

module.exports = {
  id: "clawguard-auto",
  name: "ClawGuard Auto",
  description: "Automatically scans selected tool inputs with the managed ClawGuard skill.",
  configSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      scannerPath: { type: "string" },
      scanTools: { type: "array", items: { type: "string" } },
      blockOnSanitize: { type: "boolean" },
      maxUrlBytes: { type: "integer", minimum: 1 },
      timeoutMs: { type: "integer", minimum: 1000 },
    },
  },
  register(api) {
    api.on("before_tool_call", async (event, ctx) => {
      const config = normalizePluginConfig(api.pluginConfig);
      const toolName =
        typeof event?.toolName === "string" ? event.toolName.trim().toLowerCase() : "";
      if (!toolName || !config.scanTools.includes(toolName)) {
        return undefined;
      }
      api.logger.debug(`clawguard-auto: before_tool_call tool=${toolName}`);
      if (!fsSync.existsSync(config.scannerPath)) {
        api.logger.warn(
          `clawguard-auto: scanner not found at ${config.scannerPath}; allowing ${toolName}`,
        );
        return undefined;
      }

      const storeKey = resolveStoreKey(ctx);
      const candidates = collectCandidates(toolName, event.params);
      for (const candidate of candidates) {
        const result = await maybeScanCandidate(candidate, config, api.logger);
        if (result?.finding) {
          rememberFinding(storeKey, result.finding);
        }
        if (result?.block) {
          return result;
        }
      }
      api.logger.debug(`clawguard-auto: no block for tool=${toolName}`);
      return undefined;
    });

    api.on("after_tool_call", async (event, ctx) => {
      const config = normalizePluginConfig(api.pluginConfig);
      const toolName =
        typeof event?.toolName === "string" ? event.toolName.trim().toLowerCase() : "";
      if (!toolName || !config.scanTools.includes(toolName) || event?.error) {
        return;
      }
      if (!fsSync.existsSync(config.scannerPath)) {
        return;
      }

      const storeKey = resolveStoreKey(ctx);
      const candidates = collectToolResultCandidates(toolName, event.params, event.result);
      for (const candidate of candidates) {
        try {
          api.logger.debug(
            `clawguard-auto: scanning tool result tool=${toolName} source=${candidate.label}`,
          );
          const result = await runScanner(candidate, config);
          const finding = buildFinding(result, {
            toolName,
            source: candidate.label,
            stage: "after_tool_call",
          });
          if (finding) {
            rememberFinding(storeKey, finding);
            api.logger.warn(
              `clawguard-auto: result-signal tool=${toolName} source=${candidate.label} action=${result.action} reasons=${summarizeReasons(result)}`,
            );
            api.logger.warn(
              `clawguard-auto: block-detail ${buildBlockReason({ ...result, source: candidate.label })}`,
            );
          } else {
            api.logger.debug(
              `clawguard-auto: tool result clean tool=${toolName} source=${candidate.label}`,
            );
          }
        } catch (error) {
          api.logger.warn(
            `clawguard-auto: result scan skipped for ${candidate.label}: ${String(error)}`,
          );
        }
      }
    });

    api.on("before_agent_reply", async (event, ctx) => {
      const storeKey = resolveStoreKey(ctx);
      const findings = consumeFindings(storeKey);
      if (findings.length === 0) {
        return undefined;
      }

      const warningText = buildCombinedFindingReply(findings);
      if (!warningText) {
        return undefined;
      }

      // Prepend the ClawGuard notice to the agent's actual reply so the user
      // sees both the security warning AND the answer on Discord.
      const agentReply = event?.cleanedBody?.trim();
      const combinedText = agentReply ? `${warningText}\n\n${agentReply}` : warningText;

      return {
        handled: true,
        reply: {
          text: combinedText,
        },
        reason: "clawguard-findings",
      };
    });
  },
};
