#!/usr/bin/env node
// bpsmeter-anonymize.mjs — strip a payouts export to six fields and seal it to BPSMeter, on your machine.
//
// WHAT IT DOES
//   Reads your raw export (CSV or JSON), keeps only date, corridor, provider, notional_usd, fee_usd
//   and bps, writes them to safe.csv, lists every column it dropped and every provider value it kept,
//   prints the SHA-256 of your input and of safe.csv, and encrypts safe.csv to BPSMeter's public key
//   (embedded below, fingerprint ca78c8349b049470) as safe.csv.bpsm. Send safe.csv.bpsm.
//   If the export has a payment id column, safe.csv also carries ref_h: a keyed hash of the id under
//   a random salt kept at ~/.config/bpsmeter-anonymizer/salt, so resent payments de-duplicate but
//   the id itself cannot be recovered.
//
// WHAT IT NEVER DOES
//   No network: it imports only Node's built-in fs, path, os and crypto modules, and contains no
//   fetch, http, https, net, dns or child_process. No dependencies, nothing installed, nothing sent.
//   It never keeps counterparty, beneficiary, customer, client or partner columns unless you name
//   one yourself with --provider-col.
//
// HOW TO VERIFY
//   1. The SHA-256 of this exact file is published at https://bpsmeter.com. Compare:
//        shasum -a 256 bpsmeter-anonymize.mjs      (macOS)    sha256sum bpsmeter-anonymize.mjs  (Linux)
//   2. The key fingerprint it prints (ca78c8349b049470) is the one published at bpsmeter.com.
//   3. Read it. It is generated, unminified, from the same modules BPSMeter's own tool runs.
//
// USAGE (Node 20 or newer)
//   node bpsmeter-anonymize.mjs <export.csv|export.json> [--out safe.csv] [--no-seal]
//        [--provider-col NAME] [--salt-file PATH]
//   --no-seal         write safe.csv only, if you would rather send it over your own channel
//   --provider-col    take the provider from this column (e.g. one named "Counterparty" that really
//                     holds the venue); by default only venue-style columns are kept
//   --salt-file       where the ref_h salt lives (default ~/.config/bpsmeter-anonymizer/salt)
//   --public-key      seal to a different key (testing only)

import { createCipheriv, createHash, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

// BPSMeter's public key. Its fingerprint is checked against the constant below on every run.
const BPSMETER_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAgMzxjlpdSmTwLOqgxqWaXteLwJ52iSnJIvawR4HMO1s=
-----END PUBLIC KEY-----
`;
const BPSMETER_KEY_FINGERPRINT = "ca78c8349b049470";

// ==================================================================================================
// from ingest/fills.mjs
// ==================================================================================================
// Fills ingest — turns whatever a PSP actually exports into a normalized fill list.
//
// The wedge is "email us your last 90 days of fills". What arrives is never in our schema: it is a
// Looker CSV, a Metabase export, a treasury JSON dump, with columns named whatever that company's
// data team called them and money formatted "$1,234,567.00". This module absorbs that: delimiter and
// format sniffing, header aliasing, tolerant number/date parsing, and — critically — it NEVER
// silently drops a row. Every row that can't be used comes back in `rejected` with its line number
// and the reason, because a shadow-TCA number computed on 60% of someone's flow without telling them
// is worse than no number at all.

// Provider column names split by what they usually hold. Venue-style names hold the venue or desk that
// filled the trade. Party-style names are ambiguous: in many exports "counterparty" or "partner" is the
// payee or the customer, a person or a business that must never leave the customer's machine. The TCA
// accepts both (an already-clean file may call its venue "counterparty"); the anonymizer accepts only
// venue-style names unless the user names the column explicitly.
const PROVIDER_VENUE_ALIASES = ["provider", "provider_name", "venue", "execution_venue", "liquidity_provider",
  "lp", "exchange", "desk", "otc_desk", "broker", "rail", "off_ramp", "offramp"];

const PROVIDER_PARTY_ALIASES = ["counterparty", "partner", "psp", "vendor"];

const FIELD_ALIASES = {
  date: ["date", "trade_date", "tradedate", "value_date", "valuedate", "settlement_date", "settled_at",
         "executed_at", "execution_date", "exec_date", "timestamp", "created_at", "booked_at", "payment_date"],
  corridor: ["corridor", "pair", "currency_pair", "ccy_pair", "fx_pair", "route", "market", "symbol", "lane"],
  sellCcy: ["sell_currency", "sell_ccy", "base_currency", "base_ccy", "from_currency", "source_currency",
            "debit_currency", "ccy_from", "funding_currency", "send_currency"],
  buyCcy: ["buy_currency", "buy_ccy", "quote_currency", "quote_ccy", "to_currency", "target_currency",
           "destination_currency", "credit_currency", "ccy_to", "payout_currency", "receive_currency"],
  provider: [...PROVIDER_VENUE_ALIASES, ...PROVIDER_PARTY_ALIASES],
  notionalUsd: ["notional_usd", "usd_notional", "amount_usd", "usd_amount", "principal_usd", "usd_value",
                "gross_usd", "notional", "amount", "sell_amount", "send_amount", "trade_amount", "volume_usd"],
  feeUsd: ["fee_usd", "fees_usd", "total_fee_usd", "cost_usd", "fee_amount_usd", "spread_usd", "all_in_cost_usd",
           "fee_amount", "fee", "fees", "cost"],
  bps: ["bps", "bps_charged", "fee_bps", "all_in_bps", "spread_bps", "markup_bps", "total_bps", "cost_bps"],
  rate: ["rate", "fx_rate", "executed_rate", "exec_rate", "fill_rate", "client_rate", "price", "applied_rate"],
  midRate: ["mid", "mid_rate", "midmarket_rate", "mid_market_rate", "reference_rate", "benchmark_rate",
            "interbank_rate", "market_rate", "spot_mid"],
  ref: ["id", "fill_id", "trade_id", "txn_id", "transaction_id", "payment_id", "reference", "external_id", "ref_h"],
};

const CANON_BY_ALIAS = (() => {
  const m = new Map();
  for (const [canon, aliases] of Object.entries(FIELD_ALIASES)) for (const a of aliases) if (!m.has(a)) m.set(a, canon);
  return m;
})();

function normalizeHeader(h) {
  return String(h).replace(/^﻿/, "").trim().toLowerCase()
    .replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

// Delimiter sniffing: whichever candidate splits the header line into the most fields, outside quotes.
function sniffDelimiter(headerLine) {
  const candidates = [",", ";", "\t", "|"];
  let best = ",", bestCount = 0;
  for (const d of candidates) {
    const n = splitDelimited(headerLine, d).length;
    if (n > bestCount) { best = d; bestCount = n; }
  }
  return best;
}

// RFC4180-ish field splitter: honours quoted fields and "" escapes.
function splitDelimited(line, delim) {
  const out = [];
  let cur = "", inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else inQuotes = false;
      } else cur += c;
    } else if (c === '"') inQuotes = true;
    else if (c === delim) { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out.map(s => s.trim());
}

// Money/number parsing: "$1,234,567.00", "(1,200)" negative, "1 234,56" EU style, "27.8bps", "0.28%".
// Returns the value AND whether the cell was percent-formatted, because that changes what the number
// MEANS in a cost column: "0.28%" in a bps column is 28 bps, not 0.0028 bps. Callers that only want a
// plain number use parseNumber.
function parseNumberEx(raw) {
  if (raw === null || raw === undefined) return { value: null, percent: false };
  if (typeof raw === "number") return { value: isFinite(raw) ? raw : null, percent: false };
  let s = String(raw).trim();
  if (!s || /^(n\/?a|null|none|-|—)$/i.test(s)) return { value: null, percent: false };
  const negParen = /^\(.*\)$/.test(s);
  const percent = /%/.test(s);
  s = s.replace(/[()]/g, "").replace(/[$€£¥]/g, "").replace(/\s/g, "")
       .replace(/(bps|bp|pips?|usd|%)/gi, "");
  // EU decimal comma: "1.234,56" or "1234,56" (comma is last separator and 1-2 trailing digits)
  const lastComma = s.lastIndexOf(","), lastDot = s.lastIndexOf(".");
  if (lastComma > lastDot && /,\d{1,2}$/.test(s)) s = s.replace(/\./g, "").replace(",", ".");
  else s = s.replace(/,/g, "");
  const n = parseFloat(s);
  if (!isFinite(n)) return { value: null, percent };
  let v = negParen ? -n : n;
  if (percent) v = v / 100;
  return { value: v, percent };
}

function parseNumber(raw) { return parseNumberEx(raw).value; }

function parseDate(raw) {
  if (!raw) return null;
  const s = String(raw).trim();
  let m;
  if ((m = s.match(/^(\d{4})-(\d{2})-(\d{2})/))) return `${m[1]}-${m[2]}-${m[3]}`;
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/))) {            // US M/D/YYYY
    return `${m[3]}-${String(m[1]).padStart(2, "0")}-${String(m[2]).padStart(2, "0")}`;
  }
  if ((m = s.match(/^(\d{1,2})-([A-Za-z]{3})-(\d{4})/))) {          // 03-Jun-2026
    const months = { jan:1,feb:2,mar:3,apr:4,may:5,jun:6,jul:7,aug:8,sep:9,oct:10,nov:11,dec:12 };
    const mo = months[m[2].toLowerCase()];
    if (mo) return `${m[3]}-${String(mo).padStart(2, "0")}-${String(m[1]).padStart(2, "0")}`;
  }
  const d = new Date(s);
  if (!isNaN(d.getTime())) return d.toISOString().slice(0, 10);
  return null;
}

const CCY = /^[A-Z]{3}$/;

// ---- Spread against mid -------------------------------------------------------------------------
// Rough USD value of one unit of each currency, used ONLY to tell which way a rate is quoted
// (local per USD, or USD per local). Real rates sit well within 2x of these; nothing is priced off them.
const APPROX_USD_PER_UNIT = {
  EUR: 1.12, GBP: 1.3, CHF: 1.15, CAD: 0.73, AUD: 0.66, JPY: 0.0068, MXN: 0.055, BRL: 0.19, COP: 0.00025,
  NGN: 0.00067, PEN: 0.27, CLP: 0.00106, ARS: 0.00085, PHP: 0.0175, INR: 0.012, KES: 0.0077, GHS: 0.08,
  ZAR: 0.055, TRY: 0.029, IDR: 0.000062, VND: 0.000039, PKR: 0.0036, EGP: 0.02, UGX: 0.00027, TZS: 0.00038,
};

// Which way is `rate` quoted for a USD-XXX corridor? Whichever reading lands closer (in log space) to
// the rough value above. null when the currency is unknown.
function rateOrientation(corridor, rate) {
  const ccy = String(corridor || "").split("-")[1];
  const approx = APPROX_USD_PER_UNIT[ccy];
  if (!approx || !(rate > 0)) return null;
  const asUsdPerLocal = Math.abs(Math.log(rate / approx));
  const asLocalPerUsd = Math.abs(Math.log((1 / rate) / approx));
  return asLocalPerUsd <= asUsdPerLocal ? "local_per_usd" : "usd_per_local";
}

// Signed cost of an executed rate against mid, in bps, for a customer paying USD out into local
// currency. Positive = worse than mid. A fill better than mid is negative, not a cost.
function spreadBps(corridor, rate, mid) {
  if (!(rate > 0) || !(mid > 0)) return null;
  const o = rateOrientation(corridor, mid);
  if (o === "local_per_usd") return ((mid - rate) / mid) * 1e4;   // fewer local units per USD than mid
  if (o === "usd_per_local") return ((rate - mid) / mid) * 1e4;   // more USD per local unit than mid
  return null;
}

// Reference mid for a date from a customer-supplied or fetched daily series: the rate on that date or
// the most recent one up to `maxDays` before it (weekends, holidays). Series values are local per USD.
function refMidFor(refRates, corridor, date, maxDays = 4) {
  if (!refRates || !date) return null;
  const ccy = String(corridor || "").split("-")[1];
  const t = Date.parse(`${date}T00:00:00Z`);
  for (let d = 0; d <= maxDays; d++) {
    const day = new Date(t - d * 864e5).toISOString().slice(0, 10);
    const v = refRates.get(`${ccy}|${day}`);
    if (v) return { localPerUsd: v, date: day };
  }
  return null;
}

// "USDMXN", "USD/MXN", "usd_mxn", "USD-MXN", "MXN" (implied USD leg) -> "USD-MXN"
function normalizeCorridor(raw, sellCcy, buyCcy) {
  if (raw) {
    const s = String(raw).trim().toUpperCase().replace(/\s+/g, "");
    let m;
    if ((m = s.match(/^([A-Z]{3})[\/\-_. ]?([A-Z]{3})$/))) return `${m[1]}-${m[2]}`;
    if (CCY.test(s)) return `USD-${s}`;
  }
  const a = sellCcy ? String(sellCcy).trim().toUpperCase() : null;
  const b = buyCcy ? String(buyCcy).trim().toUpperCase() : null;
  if (a && b && CCY.test(a) && CCY.test(b)) return `${a}-${b}`;
  if (b && CCY.test(b)) return `USD-${b}`;
  return null;
}

// `providerCol` pins the provider to one named column (matched as written or by normalized name).
// `venueProviderOnly` refuses party-style provider aliases, so such a column stays unmapped.
function mapHeaders(headers, { providerCol, venueProviderOnly } = {}) {
  const mapping = {};      // canonical -> source column name
  const unmapped = [];
  let pinned = null;
  if (providerCol) {
    pinned = headers.find(h => h === providerCol) ?? headers.find(h => normalizeHeader(h) === normalizeHeader(providerCol));
    if (pinned === undefined) throw new Error(`--provider-col "${providerCol}" is not a column. Columns seen: ${headers.join(", ")}`);
    mapping.provider = pinned;
  }
  headers.forEach(h => {
    if (h === pinned) return;
    const norm = normalizeHeader(h);
    let canon = CANON_BY_ALIAS.get(norm);
    if (canon === "provider" && (pinned !== null || (venueProviderOnly && !PROVIDER_VENUE_ALIASES.includes(norm)))) canon = undefined;
    if (canon && !mapping[canon]) mapping[canon] = h;
    else if (!canon) unmapped.push(h);
  });
  return { mapping, unmapped };
}

function rowsFromCsv(text) {
  const clean = text.replace(/^﻿/, "");
  const lines = clean.split(/\r?\n/);
  // Skip leading blank/comment lines some exporters prepend.
  let start = 0;
  while (start < lines.length && (!lines[start].trim() || lines[start].trim().startsWith("#"))) start++;
  if (start >= lines.length) return { headers: [], rows: [] };
  const delim = sniffDelimiter(lines[start]);
  const headers = splitDelimited(lines[start], delim);
  const rows = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const cols = splitDelimited(lines[i], delim);
    const row = {};
    headers.forEach((h, j) => { row[h] = cols[j] !== undefined ? cols[j] : ""; });
    rows.push({ row, lineNo: i + 1 });
  }
  return { headers, rows };
}

function rowsFromJson(text) {
  const trimmed = text.trim();
  let data;
  if (trimmed.startsWith("{") && trimmed.includes("\n{")) {         // NDJSON
    data = trimmed.split(/\r?\n/).filter(l => l.trim()).map(l => JSON.parse(l));
  } else {
    data = JSON.parse(trimmed);
    if (!Array.isArray(data)) {
      const key = ["fills", "trades", "data", "rows", "results", "records"].find(k => Array.isArray(data[k]));
      if (!key) throw new Error("JSON payload has no array of fills (looked for fills/trades/data/rows/results/records)");
      data = data[key];
    }
  }
  const headerSet = new Set();
  data.forEach(o => Object.keys(o).forEach(k => headerSet.add(k)));
  const headers = [...headerSet];
  return { headers, rows: data.map((row, i) => ({ row, lineNo: i + 1 })) };
}

/**
 * Parse a fills export into normalized fills.
 * Returns { fills, rejected, mapping, unmapped, format, warnings }.
 * Each fill: { ref, date, corridor, provider, notionalUsd, bpsCharged, bpsBasis, feeUsd, spreadBps, raw, lineNo }
 * `refRates` (Map "CCY|YYYY-MM-DD" -> local per USD) supplies the day's mid when the export has an
 * executed rate but no mid column.
 */
function parseFills(text, { format, refRates = null, providerCol, venueProviderOnly } = {}) {
  const fmt = format || (text.trim().startsWith("[") || text.trim().startsWith("{") ? "json" : "csv");
  const { headers, rows } = fmt === "json" ? rowsFromJson(text) : rowsFromCsv(text);
  const { mapping, unmapped } = mapHeaders(headers, { providerCol, venueProviderOnly });

  const missing = [];
  if (!mapping.notionalUsd) missing.push("a notional/amount column");
  if (!mapping.corridor && !mapping.buyCcy) missing.push("a corridor or destination-currency column");
  if (!mapping.bps && !mapping.feeUsd && !(mapping.rate && mapping.midRate)) {
    missing.push("a cost column (bps, or fee amount, or executed-rate + mid-rate)");
  }
  if (missing.length) {
    const err = new Error(`fills export is missing ${missing.join("; ")}. Columns seen: ${headers.join(", ")}`);
    err.mapping = mapping;
    throw err;
  }

  const fills = [], rejected = [], warnings = [];
  const get = (row, canon) => (mapping[canon] !== undefined ? row[mapping[canon]] : undefined);
  let assumedUsdCount = 0, missingRef = 0, unknownOrientation = 0;
  const feeAllIn = !!mapping.feeUsd && /all_in|spread/.test(normalizeHeader(mapping.feeUsd));

  for (const { row, lineNo } of rows) {
    const corridor = normalizeCorridor(get(row, "corridor"), get(row, "sellCcy"), get(row, "buyCcy"));
    const notionalUsd = parseNumber(get(row, "notionalUsd"));
    const date = parseDate(get(row, "date"));
    const provider = (get(row, "provider") ?? "unspecified").toString().trim() || "unspecified";

    if (!corridor) { rejected.push({ lineNo, reason: "could not read a currency corridor", raw: row }); continue; }
    if (notionalUsd === null || notionalUsd <= 0) {
      rejected.push({ lineNo, reason: "missing or non-positive notional", raw: row }); continue;
    }

    // Cost. An explicit bps column is the customer's own all-in figure and is taken as stated. Otherwise
    // the all-in cost is the fee PLUS the spread in the executed rate against mid: most payout exports
    // carry a small explicit fee and put the real markup in the rate, and counting only one of the two
    // understates what was paid. A fee column that is itself labelled all-in or spread is not topped up.
    let bpsCharged = null, bpsBasis = null, feeUsd = null, spread = null;
    const bpsCell = parseNumberEx(get(row, "bps"));
    const feeCell = parseNumberEx(get(row, "feeUsd"));
    // A percent-formatted cost cell is a fraction of notional: 0.28% = 28bps in a bps column, and
    // 0.28% in a fee column is a fee of 0.28% of the ticket, not $0.0028.
    const rawBps = bpsCell.value === null ? null : (bpsCell.percent ? bpsCell.value * 1e4 : bpsCell.value);
    const rawFee = feeCell.value === null ? null : (feeCell.percent ? feeCell.value * notionalUsd : feeCell.value);
    const rate = parseNumber(get(row, "rate"));
    let mid = parseNumber(get(row, "midRate"));
    let midSource = mid !== null ? "export" : null;
    if (rate !== null && mid === null && refRates) {
      const ref = refMidFor(refRates, corridor, date);
      if (ref) {
        mid = rateOrientation(corridor, rate) === "usd_per_local" ? 1 / ref.localPerUsd : ref.localPerUsd;
        midSource = `reference ${ref.date}`;
      } else missingRef++;
    }
    if (rate !== null && mid !== null && mid !== 0) spread = spreadBps(corridor, rate, mid);
    if (rate !== null && mid !== null && spread === null) unknownOrientation++;
    const feeIsAllIn = feeAllIn;

    if (rawBps !== null) { bpsCharged = rawBps; bpsBasis = "explicit_bps"; feeUsd = (rawBps * notionalUsd) / 1e4; }
    else if (rawFee !== null && spread !== null && !feeIsAllIn) {
      const feeBps = (Math.abs(rawFee) / notionalUsd) * 1e4;
      bpsCharged = feeBps + spread; bpsBasis = "fee_plus_spread";
      feeUsd = (bpsCharged * notionalUsd) / 1e4;
    }
    else if (rawFee !== null) { feeUsd = Math.abs(rawFee); bpsCharged = (feeUsd / notionalUsd) * 1e4; bpsBasis = "fee_over_notional"; }
    else if (spread !== null) {
      bpsCharged = spread; bpsBasis = "rate_vs_mid";
      feeUsd = (bpsCharged * notionalUsd) / 1e4;
    }
    if (bpsCharged === null) { rejected.push({ lineNo, reason: "no usable cost field on this row", raw: row }); continue; }
    // Only a rate-derived cost can legitimately be below zero (a fill better than mid). A negative
    // stated fee or bps is a data error.
    const floor = bpsBasis === "rate_vs_mid" || bpsBasis === "fee_plus_spread" ? -500 : 0;
    if (!isFinite(bpsCharged) || bpsCharged < floor) { rejected.push({ lineNo, reason: `implausible cost (${bpsCharged} bps)`, raw: row }); continue; }

    const sellCcy = (get(row, "sellCcy") || "").toString().trim().toUpperCase();
    if (mapping.notionalUsd && !/usd/i.test(normalizeHeader(mapping.notionalUsd)) && sellCcy && sellCcy !== "USD") assumedUsdCount++;

    fills.push({
      ref: (get(row, "ref") ?? `L${lineNo}`).toString(),
      date, corridor, provider, notionalUsd, bpsCharged, bpsBasis, feeUsd, spreadBps: spread, midSource, lineNo,
    });
  }

  if (assumedUsdCount) {
    warnings.push(`${assumedUsdCount} row(s) had a non-USD sell currency but the amount column is not USD-labelled; amounts were treated as USD.`);
  }
  if (missingRef) warnings.push(`${missingRef} row(s) had an executed rate but no reference mid for their date; their spread could not be measured.`);
  if (unknownOrientation) warnings.push(`${unknownOrientation} row(s) are in a currency whose rate direction we cannot tell; their spread was not counted.`);
  const noDate = fills.filter(f => !f.date).length;
  if (noDate) warnings.push(`${noDate} fill(s) had an unreadable date; they are included in totals but excluded from the monthly trend.`);

  return { fills, rejected, mapping, unmapped, format: fmt, warnings };
}

// ==================================================================================================
// from ingest/refrates.mjs
// ==================================================================================================
// refrates.mjs — a daily reference-rate series, so a payout's executed rate can be judged against the
// mid on the day it was paid when the export itself carries no mid column.
//
// File format (CSV): date,ccy,rate  with rate = units of ccy per 1 USD, one row per currency per day.
// `refrates` builds one from the ECB daily fixings (frankfurter.dev, public, keyless); a customer can
// equally hand us their own series (their bank's or data vendor's fixings) in the same three columns.

function parseRefRates(text) {
  const lines = String(text).replace(/^﻿/, "").split(/\r?\n/).filter(l => l.trim() && !l.trim().startsWith("#"));
  if (!lines.length) return new Map();
  const head = lines[0].split(",").map(h => h.trim().toLowerCase());
  const [di, ci, ri] = ["date", "ccy", "rate"].map(n => head.indexOf(n));
  if (di < 0 || ci < 0 || ri < 0) throw new Error("reference rates file needs columns date,ccy,rate (units of ccy per 1 USD)");
  const map = new Map();
  for (const line of lines.slice(1)) {
    const c = line.split(",").map(x => x.trim());
    const date = parseDate(c[di]), ccy = (c[ci] || "").toUpperCase(), rate = Number(c[ri]);
    if (date && /^[A-Z]{3}$/.test(ccy) && rate > 0) map.set(`${ccy}|${date}`, rate);
  }
  return map;
}

// ==================================================================================================
// from ingest/seal.mjs
// ==================================================================================================
// seal.mjs — encrypt the anonymized file to BPSMeter's public key before it leaves the customer's machine.
//
// Hybrid public-key encryption on Node's built-in crypto only, so the anonymizer stays dependency-free:
// a fresh X25519 key pair per file, ECDH against our published public key, HKDF-SHA256 to derive a
// one-time AES-256-GCM key, and the file sealed under it. Only the holder of the matching private key
// can open it, and GCM's tag means any change to the sealed file (or the header bound to it) fails to
// open rather than yielding altered data. The header also carries the SHA-256 of the plaintext, so the
// fingerprint the customer saw on their own machine is the one the report is checked against.
//
// Sealed file (.bpsm) is JSON: { format, alg, recipient, epk, salt, iv, tag, sha256, name, ciphertext },
// binary fields base64. `recipient` is the fingerprint of the public key it was sealed to.

const FORMAT = "bpsmeter-sealed-v1";

const ALG = "X25519-HKDF-SHA256-AES-256-GCM";

const INFO = Buffer.from(FORMAT);

const b64 = buf => Buffer.from(buf).toString("base64");

const sha256 = buf => createHash("sha256").update(buf).digest("hex");

// Fingerprint of a public key: SHA-256 of its DER encoding, first 16 hex chars. Lets a customer check
// they sealed to the key we published, and lets us refuse a file sealed to some other key.
function keyFingerprint(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return sha256(der).slice(0, 16);
}

function deriveKey(sharedSecret, salt) {
  return Buffer.from(hkdfSync("sha256", sharedSecret, salt, INFO, 32));
}

// The header fields that are not secret but must not be swapped are bound into GCM as associated data.
const aad = h => Buffer.from(JSON.stringify([h.format, h.alg, h.recipient, h.epk, h.sha256, h.name]));

function sealBuffer(plaintext, publicKeyPem, { name = "safe.csv" } = {}) {
  const recipientKey = createPublicKey(publicKeyPem);
  const eph = generateKeyPairSync("x25519");
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: recipientKey });
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const header = {
    format: FORMAT,
    alg: ALG,
    recipient: keyFingerprint(publicKeyPem),
    epk: b64(eph.publicKey.export({ type: "spki", format: "der" })),
    sha256: sha256(plaintext),
    name,
  };
  const cipher = createCipheriv("aes-256-gcm", deriveKey(shared, salt), iv);
  cipher.setAAD(aad(header));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return JSON.stringify({ ...header, salt: b64(salt), iv: b64(iv), tag: b64(cipher.getAuthTag()), ciphertext: b64(ciphertext) }, null, 2) + "\n";
}

// ==================================================================================================
// from ingest/anonymize.mjs
// ==================================================================================================
// anonymize.mjs — strip a raw fills export down to the six fields the TCA needs, locally.
//
// The whole trust pitch is "we only need corridor, size, provider, and fee — strip the rest first."
// This makes that literally true: a customer runs it on their own machine, sends the safe file, and
// nothing else (payment ids, counterparty names, customer names, memos, account numbers, status) ever
// leaves their side. It reuses the same tolerant parser the TCA uses, so it understands their columns,
// then re-emits ONLY the safe canonical fields and reports exactly what it dropped.
//
// This module is also the source of the standalone script customers download: scripts/build-anonymizer.mjs
// inlines it (with the parser and the sealer) into dist/bpsmeter-anonymize.mjs, so keep it to node:
// built-ins and never give it a network path.

// The only fields that leave the customer's machine. Nothing here identifies a person or a counterparty.
// `ref_h` is appended only when the export has a payment id column (see refHash).
const SAFE_HEADER = ["date", "corridor", "provider", "notional_usd", "fee_usd", "bps"];

// Canonical fields we legitimately keep (their source columns are the "kept" ones). Everything else
// in the original file — including any id/reference column — is dropped.
const KEPT_CANON = ["date", "corridor", "buyCcy", "sellCcy", "provider", "notionalUsd", "feeUsd", "bps", "rate", "midRate"];

// Column names that usually hold a person or a business on the other side of the payment. The parser
// already refuses them as the provider here; this names them in the output so the user knows why.
const PARTY_COLUMN = /counterpart|partner|beneficiar|customer|client|payee|payer|recipient|merchant|sender|vendor|psp/;

const REF_HASH_HEX = 16;

function csvCell(v) {
  if (v === null || v === undefined) return "";
  const s = v instanceof Date ? v.toISOString().slice(0, 10) : String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// Keyed hash of a payment reference: HMAC-SHA256 under the customer's own salt, truncated. The same
// payment in two exports hashes the same (so a merged book still de-duplicates), but without the salt,
// which never leaves the customer's machine, the id cannot be recovered or matched against anything.
// Normalized the way batch de-dup compares refs (trimmed, case-insensitive).
function refHash(ref, salt) {
  return createHmac("sha256", salt).update(String(ref).trim().toUpperCase()).digest("hex").slice(0, REF_HASH_HEX);
}

const DEFAULT_SALT_FILE = join(homedir(), ".config", "bpsmeter-anonymizer", "salt");

// Load the customer's salt, creating it once (32 random bytes, owner-only) if it does not exist yet.
function loadOrCreateSalt(path = DEFAULT_SALT_FILE) {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    try { writeFileSync(path, randomBytes(32).toString("hex") + "\n", { mode: 0o600, flag: "wx" }); }
    catch (e) { if (e.code !== "EEXIST") throw e; }
  }
  const salt = readFileSync(path, "utf8").trim();
  if (!/^[0-9a-f]{64}$/.test(salt)) throw new Error(`salt file ${path} is not 64 hex characters; move it aside to create a new one`);
  return salt;
}

/**
 * Anonymize a raw fills export.
 * Options: format, providerCol (take the provider only from this column), salt (string, or a function
 * returning one; called only when the export has a payment id column), refRates (daily mids, so a rate
 * with no mid column still has its spread measured here, before anything is sent).
 * Returns { csv, kept, dropped, partyDropped, keptSourceCols, providers, providerColumn, refColumn, rowsOut,
 *   rejected, format }.
 * `dropped` is the list of original columns that were removed — so the customer can SEE the PII is gone.
 */
function anonymizeFills(text, { format, providerCol, salt, refRates = null } = {}) {
  const { fills, rejected, mapping, unmapped, format: fmt } = parseFills(text, { format, providerCol, venueProviderOnly: true, refRates });

  const keptSourceCols = KEPT_CANON.map(c => mapping[c]).filter(Boolean);
  // Dropped = every original column that is not one we keep. Unmapped columns are always dropped;
  // an id/reference column that DID map (to `ref`) is dropped too — only its keyed hash is emitted.
  const dropped = [...unmapped];
  if (mapping.ref) dropped.push(mapping.ref);
  const partyDropped = unmapped.filter(h => PARTY_COLUMN.test(normalizeHeader(h)));

  // A file that is already anonymized carries ref_h, which passes through as-is.
  const refColumn = mapping.ref || null;
  const alreadyHashed = refColumn !== null && normalizeHeader(refColumn) === "ref_h";
  const key = refColumn && !alreadyHashed ? (typeof salt === "function" ? salt() : salt) : null;
  if (refColumn && !alreadyHashed && !key) throw new Error("the export has a payment id column; a salt is required to hash it");
  const refCell = f => {
    const r = String(f.ref).trim();
    if (!r || r === `L${f.lineNo}`) return "";
    return alreadyHashed ? r.toLowerCase() : refHash(r, key);
  };

  const header = refColumn ? [...SAFE_HEADER, "ref_h"] : SAFE_HEADER;
  const lines = [header.join(",")];
  const providers = new Map();
  for (const f of fills) {
    const row = [
      csvCell(f.date), csvCell(f.corridor), csvCell(f.provider),
      csvCell(f.notionalUsd), csvCell(f.feeUsd), csvCell(f.bpsCharged),
    ];
    if (refColumn) row.push(refCell(f));
    lines.push(row.join(","));
    providers.set(f.provider, (providers.get(f.provider) || 0) + 1);
  }

  return {
    csv: lines.join("\n") + "\n",
    kept: header,
    keptSourceCols,
    dropped: [...new Set(dropped)],
    partyDropped,
    providers: [...providers].map(([name, rows]) => ({ name, rows })).sort((a, b) => a.name.localeCompare(b.name)),
    providerColumn: mapping.provider || null,
    refColumn,
    rowsOut: fills.length,
    withSpread: fills.filter(f => f.bpsBasis === "fee_plus_spread" || f.bpsBasis === "rate_vs_mid").length,
    rejected,
    format: fmt,
  };
}

const sha256File = path => createHash("sha256").update(readFileSync(path)).digest("hex");

/**
 * Anonymize one file on disk, print what was kept, dropped and sent, and seal the result.
 * Shared by `node cli.mjs anonymize` and the standalone dist/bpsmeter-anonymize.mjs.
 * `publicKeyPem` null means write safe.csv only.
 */
function runAnonymize({ input, out, providerCol, saltFile, refRatesFile, publicKeyPem, seal = true, log = console.log }) {
  const inPath = resolve(input);
  const outPath = out ? resolve(out) : inPath.replace(/\.(csv|json|txt)$/i, "") + ".anonymized.csv";
  let saltPath = null;
  const refRates = refRatesFile ? parseRefRates(readFileSync(resolve(refRatesFile), "utf8")) : null;
  const res = anonymizeFills(readFileSync(inPath, "utf8"), {
    providerCol, refRates,
    salt: () => loadOrCreateSalt(saltPath = saltFile ? resolve(saltFile) : DEFAULT_SALT_FILE),
  });
  writeFileSync(outPath, res.csv);

  log(`anonymized ${res.rowsOut} fill(s) → ${out || basename(outPath)}`);
  log(`kept (safe to send): ${res.kept.join(", ")}`);
  log(res.dropped.length
    ? `dropped (never leaves your machine): ${res.dropped.join(", ")}`
    : `dropped: nothing extra, the file already had only safe columns`);
  if (saltPath) log(`ref_h: "${res.refColumn}" is sent only as a keyed hash; its salt stays on this machine at ${saltPath}`);
  for (const h of res.partyDropped) {
    log(`note: "${h}" looks like a counterparty or customer column and was dropped; if it actually names the venue, rerun with --provider-col "${h}"`);
  }
  if (!res.providerColumn) {
    log(`note: no venue or provider column was kept, so every row is sent as provider "unspecified" and the report cannot compare your venues; name the column that holds the venue with --provider-col`);
  }
  if (res.rejected.length) log(`note: ${res.rejected.length} unparseable row(s) were left out`);
  if (res.withSpread) log(`cost: ${res.withSpread} row(s) measured as fee plus the spread in the executed rate${refRates ? " (mids from your reference rates)" : ""}`);
  log(`\nprovider values that will be sent (check that none is a person or a customer):`);
  for (const p of res.providers) log(`  ${p.name}  (${p.rows} row${p.rows === 1 ? "" : "s"})`);

  log(`\nsha256 ${basename(inPath)}  ${sha256File(inPath)}`);
  log(`sha256 ${basename(outPath)}  ${sha256File(outPath)}`);
  if (!seal || !publicKeyPem) {
    log(`\nReview ${basename(outPath)}. It is the only file you would send, and the report you get back names this same fingerprint.`);
    return { res, outPath, sealedPath: null };
  }
  const sealedPath = outPath + ".bpsm";
  writeFileSync(sealedPath, sealBuffer(readFileSync(outPath), publicKeyPem, { name: basename(outPath) }));
  log(`\nencrypted to BPSMeter's public key ${keyFingerprint(publicKeyPem)} → ${out ? out + ".bpsm" : basename(sealedPath)}`);
  log(`Review ${basename(outPath)}, then send ${basename(sealedPath)}. Only BPSMeter can open it, any change to it is detected, and the report you get back names the fingerprint above.`);
  return { res, outPath, sealedPath };
}

const USAGE = `usage: node bpsmeter-anonymize.mjs <export.csv|export.json> [--out safe.csv] [--no-seal]
         [--provider-col NAME] [--salt-file PATH] [--ref-rates date,ccy,rate CSV] [--public-key PEM_FILE]`;

/**
 * Command-line entry of the standalone script. `publicKeyPem` / `fingerprint` are the inlined BPSMeter
 * key and its published fingerprint; `--public-key` swaps in another key (for testing). Returns an exit code.
 */
function anonymizeMain(argv, { publicKeyPem, fingerprint }) {
  const opts = { _: [] };
  const flags = new Set(["no-seal", "help"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { opts._.push(a); continue; }
    const k = a.slice(2);
    if (flags.has(k)) { opts[k] = true; continue; }
    if (!["out", "provider-col", "salt-file", "ref-rates", "public-key"].includes(k)) { console.error(`unknown option ${a}\n${USAGE}`); return 2; }
    if (argv[i + 1] === undefined) { console.error(`${a} needs a value\n${USAGE}`); return 2; }
    opts[k] = argv[++i];
  }
  if (opts.help) { console.log(USAGE); return 0; }
  if (opts._.length !== 1) { console.error(USAGE); return 2; }

  let pem = publicKeyPem;
  if (opts["public-key"]) {
    pem = readFileSync(resolve(opts["public-key"]), "utf8");
    console.log(`note: sealing to the key in ${opts["public-key"]} (${keyFingerprint(pem)}), not BPSMeter's published key (${fingerprint})`);
  } else if (keyFingerprint(pem) !== fingerprint) {
    console.error(`the embedded public key does not match its fingerprint ${fingerprint}; this copy was modified, do not use it`);
    return 1;
  }
  try {
    runAnonymize({ input: opts._[0], out: opts.out, providerCol: opts["provider-col"], saltFile: opts["salt-file"], refRatesFile: opts["ref-rates"], publicKeyPem: pem, seal: !opts["no-seal"] });
    return 0;
  } catch (e) {
    console.error(`error: ${e.message}`);
    return 1;
  }
}

// ==================================================================================================
process.exitCode = anonymizeMain(process.argv.slice(2), { publicKeyPem: BPSMETER_PUBLIC_KEY_PEM, fingerprint: BPSMETER_KEY_FINGERPRINT });
