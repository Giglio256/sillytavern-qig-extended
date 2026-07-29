import assert from "node:assert/strict";
import test from "node:test";

import {
    buildDiagnosticReport,
    DiagnosticEventBuffer,
    normalizeDiagnosticsMode,
    PrivacyLogBuffer,
    redactLogMessage,
    truncateLogEntry,
    utf8ByteLength,
} from "../lib/privacy-log.js";

test("privacy logs redact URL and credential canaries", () => {
    const signedCanary = "SIGNED_QUERY_CANARY_7f91";
    const authCanary = "AUTH_CANARY_8c42";
    const raw = `GET https://user:pass@example.test/private/${signedCanary}?X-Amz-Signature=${signedCanary}&view=full Authorization: Bearer ${authCanary}`;
    const redacted = redactLogMessage(raw);

    assert.doesNotMatch(redacted, new RegExp(`${signedCanary}|${authCanary}|user:pass`));
    assert.match(redacted, /\[URL redacted\]/);
    assert.match(redacted, /Authorization: \[redacted\]/);
    assert.equal(redactLogMessage(`/result?unknown=${signedCanary}&token=${authCanary}`).includes(signedCanary), false);
});

test("privacy logs require explicit debug mode for prompt and LLM diagnostics", () => {
    const promptCanary = "PROMPT_CANARY_f30d";
    const responseCanary = "LLM_RESPONSE_CANARY_31aa";
    const buffer = new PrivacyLogBuffer({ formatTimestamp: () => "time" });

    assert.equal(buffer.append(`Prompt: ${promptCanary}`, { diagnostic: true }), null);
    assert.equal(buffer.append(`LLM response: ${responseCanary}`, { diagnostic: true, debugEnabled: false }), null);
    assert.doesNotMatch(buffer.entries.join("\n"), new RegExp(`${promptCanary}|${responseCanary}`));

    buffer.append(`Prompt: ${promptCanary}`, { diagnostic: true, debugEnabled: true });
    assert.match(buffer.entries.join("\n"), new RegExp(promptCanary));
});

test("privacy logs bound entry count, aggregate UTF-8 bytes, and individual entries", () => {
    const buffer = new PrivacyLogBuffer({
        maxEntries: 3,
        maxBytes: 72,
        maxEntryBytes: 32,
        formatTimestamp: () => "",
    });

    for (let index = 0; index < 8; index++) buffer.append(`${index}:${"é".repeat(30)}`);

    assert.ok(buffer.entries.length <= 3);
    assert.ok(buffer.totalBytes <= 72);
    assert.ok(buffer.entries.every(entry => utf8ByteLength(entry) <= 32));
    assert.ok(buffer.entries.every(entry => !entry.includes("�")));
    assert.ok(utf8ByteLength(truncateLogEntry("é".repeat(40), 31)) <= 31);
});


test("diagnostic modes are normalized and off records nothing", () => {
    assert.equal(normalizeDiagnosticsMode("PRIVACY"), "privacy");
    assert.equal(normalizeDiagnosticsMode("unknown"), "off");
    const buffer = new DiagnosticEventBuffer({ now: () => new Date("2026-07-29T05:00:00.000Z") });
    assert.equal(buffer.append("world_info_scan", { mode: "off", details: { scanItemCount: 1 } }), null);
    assert.deepEqual(buffer.entries, []);
});

test("privacy-safe diagnostic reports exclude identity and content canaries", () => {
    const canaries = {
        characterName: "CHARACTER_NAME_CANARY",
        userName: "USER_NAME_CANARY",
        messageContent: "MESSAGE_CONTENT_CANARY",
        lorebookName: "LOREBOOK_NAME_CANARY",
        entryName: "ENTRY_NAME_CANARY",
        keyword: "KEYWORD_CANARY",
        entryContent: "ENTRY_CONTENT_CANARY",
        localPath: "C:\\Users\\PRIVATE_USER\\chat.json",
        url: "https://example.test/private?token=SECRET_CANARY",
    };
    const buffer = new DiagnosticEventBuffer({ now: () => new Date("2026-07-29T05:00:00.000Z") });
    buffer.append("world_info_scan_prepared", {
        mode: "privacy",
        details: {
            route: "extension-generate:direct",
            scanItemCount: 1,
            scanItemLengths: [123],
            requestLength: 456,
            resultSummary: { worldInfoBefore: { present: true, contentLength: 42 } },
            ...canaries,
        },
        fullDetails: canaries,
    });
    const report = buildDiagnosticReport({
        mode: "privacy",
        events: buffer.entries,
        logs: [Object.values(canaries).join(" ")],
        metadata: { qigVersion: "2.9.0", ...canaries },
        generatedAt: new Date("2026-07-29T05:01:00.000Z"),
    });
    const text = JSON.stringify(report);

    for (const value of Object.values(canaries)) assert.equal(text.includes(value), false);
    assert.equal(report.privacy.privateContentProtection, true);
    assert.equal(report.logs.length, 0);
    assert.equal(report.events[0].details.scanItemCount, 1);
    assert.equal(report.events[0].details.requestLength, 456);
    assert.deepEqual(report.events[0].details.resultSummary, { worldInfoBefore: { present: true, contentLength: 42 } });
});

test("full diagnostic reports include explicit private details but redact URLs and credentials", () => {
    const buffer = new DiagnosticEventBuffer({ now: () => new Date("2026-07-29T05:00:00.000Z") });
    buffer.append("world_info_scan_prepared", {
        mode: "full",
        details: { route: "extension-generate:direct" },
        fullDetails: {
            scanChat: ["Nami entered the room"],
            lorebookName: "Private Lorebook",
            authorization: "Bearer SECRET_TOKEN",
            sourceUrl: "https://example.test/private?token=SECRET_TOKEN",
        },
    });
    const report = buildDiagnosticReport({
        mode: "full",
        events: buffer.entries,
        logs: ["Prompt: Nami entered the room"],
        metadata: { qigVersion: "2.9.0" },
    });
    const text = JSON.stringify(report);

    assert.match(text, /Nami entered the room/);
    assert.match(text, /Private Lorebook/);
    assert.doesNotMatch(text, /https:\/\/example\.test/);
    assert.doesNotMatch(text, /SECRET_TOKEN/);
    assert.equal(report.privacy.messageContentsExported, true);
});
