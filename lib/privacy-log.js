import { isCredentialFieldName } from "./security.js";

export const DEFAULT_LOG_MAX_ENTRIES = 100;
export const DEFAULT_LOG_MAX_BYTES = 64 * 1024;
export const DEFAULT_LOG_MAX_ENTRY_BYTES = 4 * 1024;
export const DEFAULT_DIAGNOSTIC_MAX_EVENTS = 200;
export const DEFAULT_DIAGNOSTIC_MAX_BYTES = 128 * 1024;
export const DIAGNOSTICS_MODES = Object.freeze(["off", "privacy", "full"]);

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const fatalDecoder = new TextDecoder("utf-8", { fatal: true });
const TRUNCATION_SUFFIX = "... [truncated]";
const STRUCTURAL_DIAGNOSTIC_KEYS = new Set(["globalScanFieldLengths", "resultSummary"]);
const SAFE_DIAGNOSTIC_KEYS = new Set([
    "aborted",
    "availableChatCount",
    "checkWorldInfoAvailable",
    "diagnosticsMode",
    "eventBytes",
    "eventCount",
    "durationMs",
    "errorCode",
    "errorType",
    "explicitSourceLength",
    "forceTextAI",
    "formattedTextLength",
    "globalScanFieldLengths",
    "hasFormattedText",
    "includeNames",
    "insertedIntoTextAIContext",
    "logBytes",
    "logCount",
    "maxContext",
    "normalizedRecordCount",
    "qigVersion",
    "requestLength",
    "reason",
    "reportSchemaVersion",
    "resultSummary",
    "route",
    "scanItemByteLengths",
    "scanItemCount",
    "scanItemLengths",
    "sourceType",
    "textAIEnabled",
    "throughIndex",
    "worldInfoEnabled",
]);

export function utf8ByteLength(value) {
    return encoder.encode(String(value ?? "")).byteLength;
}

function decodeUtf8Prefix(bytes, maxBytes) {
    for (let end = Math.min(bytes.byteLength, maxBytes); end >= Math.max(0, maxBytes - 3); end--) {
        try {
            return fatalDecoder.decode(bytes.subarray(0, end));
        } catch {
            // A UTF-8 code point can span at most four bytes.
        }
    }
    return decoder.decode(bytes.subarray(0, Math.max(0, maxBytes)));
}

export function truncateLogEntry(value, maxBytes) {
    const text = String(value ?? "");
    const limit = Math.max(0, Math.trunc(Number(maxBytes) || 0));
    const bytes = encoder.encode(text);
    if (bytes.byteLength <= limit) return text;
    if (!limit) return "";

    const suffixBytes = encoder.encode(TRUNCATION_SUFFIX);
    if (suffixBytes.byteLength >= limit) return decodeUtf8Prefix(bytes, limit);
    return `${decodeUtf8Prefix(bytes, limit - suffixBytes.byteLength)}${TRUNCATION_SUFFIX}`;
}

function redactUrlToken(value) {
    const trailing = value.match(/[),.;!?]+$/)?.[0] || "";
    return `[URL redacted]${trailing}`;
}

export function redactLogMessage(value) {
    let text = String(value ?? "");

    text = text.replace(/\b(?:https?|wss?):\/\/[^\s<>"'`]+|(?:blob|data):[^\s<>"'`]+/gi, redactUrlToken);
    text = text.replace(/(^|[\s([=])(\/\/[A-Za-z0-9][^\s<>"'`]*)/gi, (_match, prefix, url) => `${prefix}${redactUrlToken(url)}`);
    text = text.replace(/([?&#;][^\s=&#;]{1,128}\s*[=:]\s*)([^&#;\s]*)/g, "$1[redacted]");
    text = text.replace(/\b(authorization|proxy-authorization|cookie|set-cookie)(\s*[:=]\s*)[^\r\n]+/gi, "$1$2[redacted]");
    text = text.replace(/(["']?)([A-Za-z][A-Za-z0-9_.-]{1,63})\1(\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;&}]+)/g,
        (match, quote, key, separator) => isCredentialFieldName(key)
            ? `${quote}${key}${quote}${separator}[redacted]`
            : match);

    return text;
}

export function normalizeDiagnosticsMode(value) {
    const mode = String(value || "").trim().toLowerCase();
    return DIAGNOSTICS_MODES.includes(mode) ? mode : "off";
}

function sanitizeStructuralDiagnosticValue(value) {
    if (value === null || typeof value === "boolean" || typeof value === "number") return value;
    if (Array.isArray(value)) return value.slice(0, 100).map(sanitizeStructuralDiagnosticValue).filter(item => item !== undefined);
    if (value && typeof value === "object") {
        const output = {};
        for (const [key, nestedValue] of Object.entries(value)) {
            const sanitized = sanitizeStructuralDiagnosticValue(nestedValue);
            if (sanitized !== undefined) output[key] = sanitized;
        }
        return output;
    }
    return undefined;
}

function sanitizePrivacyDiagnosticValue(value, key = "") {
    if (!SAFE_DIAGNOSTIC_KEYS.has(key)) return undefined;
    if (STRUCTURAL_DIAGNOSTIC_KEYS.has(key)) return sanitizeStructuralDiagnosticValue(value);
    if (value === null || typeof value === "boolean" || typeof value === "number") return value;
    if (typeof value === "string") return truncateLogEntry(redactLogMessage(value), 256);
    if (Array.isArray(value)) {
        return value
            .slice(0, 100)
            .map(item => (typeof item === "number" || typeof item === "boolean" ? item : undefined))
            .filter(item => item !== undefined);
    }
    return undefined;
}

export function sanitizePrivacyDiagnosticDetails(details) {
    const source = details && typeof details === "object" && !Array.isArray(details) ? details : {};
    const output = {};
    for (const [key, value] of Object.entries(source)) {
        const sanitized = sanitizePrivacyDiagnosticValue(value, key);
        if (sanitized !== undefined) output[key] = sanitized;
    }
    return output;
}

function redactFullDiagnosticValue(value, key = "") {
    if (typeof value === "string") {
        if (isCredentialFieldName(key) || /^(authorization|proxy-authorization|cookie|set-cookie)$/i.test(key)) return "[redacted]";
        return redactLogMessage(value);
    }
    if (Array.isArray(value)) return value.map(item => redactFullDiagnosticValue(item, key));
    if (value && typeof value === "object") {
        return Object.fromEntries(Object.entries(value).map(([nestedKey, nested]) => [nestedKey, redactFullDiagnosticValue(nested, nestedKey)]));
    }
    return value;
}

export class PrivacyLogBuffer {
    constructor({
        maxEntries = DEFAULT_LOG_MAX_ENTRIES,
        maxBytes = DEFAULT_LOG_MAX_BYTES,
        maxEntryBytes = DEFAULT_LOG_MAX_ENTRY_BYTES,
        formatTimestamp = () => new Date().toLocaleTimeString(),
    } = {}) {
        this.maxEntries = Math.max(1, Math.trunc(maxEntries));
        this.maxBytes = Math.max(1, Math.trunc(maxBytes));
        this.maxEntryBytes = Math.min(this.maxBytes, Math.max(1, Math.trunc(maxEntryBytes)));
        this.formatTimestamp = formatTimestamp;
        this.items = [];
        this.totalBytes = 0;
    }

    append(message, { diagnostic = false, debugEnabled = false } = {}) {
        if (diagnostic && debugEnabled !== true) return null;
        const redactedMessage = redactLogMessage(message);
        const timestamp = String(this.formatTimestamp?.() ?? "");
        const prefix = timestamp ? `[${timestamp}] ` : "";
        const entry = truncateLogEntry(`${prefix}${redactedMessage}`, this.maxEntryBytes);
        const bytes = utf8ByteLength(entry);

        this.items.push({ entry, bytes });
        this.totalBytes += bytes;
        while (this.items.length > this.maxEntries || this.totalBytes > this.maxBytes) {
            const removed = this.items.shift();
            this.totalBytes -= removed?.bytes || 0;
        }

        return { entry, message: redactedMessage };
    }

    clear() {
        this.items.length = 0;
        this.totalBytes = 0;
    }

    get entries() {
        return this.items.map(item => item.entry);
    }
}

export class DiagnosticEventBuffer {
    constructor({
        maxEvents = DEFAULT_DIAGNOSTIC_MAX_EVENTS,
        maxBytes = DEFAULT_DIAGNOSTIC_MAX_BYTES,
        now = () => new Date(),
    } = {}) {
        this.maxEvents = Math.max(1, Math.trunc(maxEvents));
        this.maxBytes = Math.max(1, Math.trunc(maxBytes));
        this.now = now;
        this.items = [];
        this.totalBytes = 0;
    }

    append(event, {
        mode = "off",
        details = {},
        fullDetails = {},
    } = {}) {
        const normalizedMode = normalizeDiagnosticsMode(mode);
        if (normalizedMode === "off") return null;
        const safeEvent = String(event || "diagnostic_event").replace(/[^a-z0-9_.-]+/gi, "_").slice(0, 96);
        const mergedDetails = normalizedMode === "full"
            ? redactFullDiagnosticValue({ ...details, ...fullDetails })
            : sanitizePrivacyDiagnosticDetails(details);
        const timestampValue = this.now?.();
        const timestamp = timestampValue instanceof Date
            ? timestampValue.toISOString()
            : new Date(timestampValue || Date.now()).toISOString();
        const record = { timestamp, event: safeEvent, details: mergedDetails };
        const serialized = JSON.stringify(record);
        const bytes = utf8ByteLength(serialized);

        this.items.push({ record, bytes });
        this.totalBytes += bytes;
        while (this.items.length > this.maxEvents || this.totalBytes > this.maxBytes) {
            const removed = this.items.shift();
            this.totalBytes -= removed?.bytes || 0;
        }
        return record;
    }

    clear() {
        this.items.length = 0;
        this.totalBytes = 0;
    }

    get entries() {
        return this.items.map(item => structuredClone(item.record));
    }
}

export function buildDiagnosticReport({
    mode = "off",
    events = [],
    logs = [],
    metadata = {},
    generatedAt = new Date(),
} = {}) {
    const normalizedMode = normalizeDiagnosticsMode(mode);
    const timestamp = generatedAt instanceof Date ? generatedAt.toISOString() : new Date(generatedAt).toISOString();
    const safeMetadata = normalizedMode === "privacy"
        ? sanitizePrivacyDiagnosticDetails(metadata)
        : redactFullDiagnosticValue(metadata);
    return {
        reportSchemaVersion: 1,
        generatedAt: timestamp,
        diagnosticsMode: normalizedMode,
        privacy: {
            privateContentProtection: normalizedMode === "privacy",
            messageContentsExported: normalizedMode === "full",
            namesExported: normalizedMode === "full",
            worldInfoContentsExported: normalizedMode === "full",
            normalLogsExported: normalizedMode === "full",
        },
        metadata: safeMetadata,
        events: Array.isArray(events)
            ? events.map((entry) => {
                if (normalizedMode !== "privacy") return redactFullDiagnosticValue(entry);
                return {
                    timestamp: String(entry?.timestamp || ""),
                    event: String(entry?.event || "diagnostic_event"),
                    details: sanitizePrivacyDiagnosticDetails(entry?.details),
                };
            })
            : [],
        logs: normalizedMode === "full" && Array.isArray(logs) ? logs.map(redactLogMessage) : [],
    };
}
