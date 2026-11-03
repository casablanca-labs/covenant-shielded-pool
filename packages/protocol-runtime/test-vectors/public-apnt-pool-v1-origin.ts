import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { APNT_POOL_V1_DOMAIN_TAGS as TAG } from "../src/apnt_pool_contract_v1.js";
import { apntPoolEmptyRootsV1 } from "../src/apnt_pool_tree_v1.js";
import { encodeAPNTPoolActionWitnessJsonV1 } from "../src/apnt_pool_action_witness_json_v1.js";
import { bytesToHex, hexToBytes } from "../src/bytes.js";
type Span = {
    start: number;
    end: number;
    expected: string;
    site: string;
    height?: number;
};
const byteOrigins = new WeakMap<Uint8Array, Span[]>(), jsonOrigins = new WeakMap<object, Map<string, Span[]>>();
const hex = (bytes: Uint8Array) => bytesToHex(bytes);
const nodes = [new Uint8Array(32)];
for (let h = 0; h < 32; h++)
    nodes.push(new Uint8Array(createHash("sha256").update(new TextEncoder().encode(TAG.treeNode)).update(nodes[h]!).update(nodes[h]!).digest()));
function clipped(spans: Span[], from: number, to: number): Span[] {
    return spans.flatMap(s => { const a = Math.max(from, s.start), b = Math.min(to, s.end); return a < b ? [{ ...s, start: a - from, end: b - from, expected: s.expected.slice(a - s.start, b - s.start) }] : []; });
}
function known(bytes: Uint8Array) { return byteOrigins.get(bytes) || []; }
function put(bytes: Uint8Array, spans: Span[]) { byteOrigins.set(bytes, spans.map(s => ({ ...s }))); return bytes; }
export function publicEmptyRoots() {
    return apntPoolEmptyRootsV1().map((bytes, h) => put(bytes, [{ start: 0, end: 64, expected: hex(nodes[h]!), height: h, site: "sparseTree/public-empty-recurrence" }]));
}
export function publicTreeNode(node: Uint8Array, left: Uint8Array, right: Uint8Array) {
    const a = known(left).find(s => s.height !== undefined), b = known(right).find(s => s.height !== undefined);
    if (a && b && a.height === b.height && hex(left) === hex(nodes[a.height!]!) && hex(right) === hex(nodes[b.height!]!))
        put(node, [{ start: 0, end: 64, expected: hex(nodes[a.height! + 1]!), height: a.height! + 1, site: "sparseTree/hashed-empty-subtree" }]);
    return node;
}
export function publicZeroBytes(length: number, site = "negative-case/declared-zero-bytes") {
    const bytes = new Uint8Array(length);
    return put(bytes, [{ start: 0, end: length * 2, expected: hex(new Uint8Array(length)), site }]);
}
export function replacePublicBytes(record: Uint8Array, offset: number, bytes: Uint8Array) {
    const out = record.slice();
    out.set(bytes, offset);
    const from = offset * 2, to = from + bytes.length * 2;
    const preserved = known(record).flatMap(s => [...clipped([s], 0, from), ...clipped([s], to, record.length * 2).map(x => ({ ...x, start: x.start + to, end: x.end + to }))]);
    return put(out, [...preserved, ...known(bytes).map(s => ({ ...s, start: s.start + from, end: s.end + from }))]);
}
export function setPublicByte(bytes: Uint8Array, index: number, value: number) {
    const replacement = publicU64(BigInt(value)).slice(0, 1);
    const out = replacePublicBytes(bytes, index, put(replacement, [{ start: 0, end: 2, expected: hex(new Uint8Array([value])), site: "negative-case/declared-prefix-byte" }]));
    bytes.set(out);
    put(bytes, known(out));
    return bytes;
}
export function publicU64(value: bigint) {
    const bytes = new Uint8Array(8);
    let rest = value;
    for (let i = 0; i < 8; i++) {
        bytes[i] = Number(rest & 255n);
        rest >>= 8n;
    }
    const expected = Buffer.alloc(8);
    expected.writeBigUInt64LE(BigInt.asUintN(64, value));
    return put(bytes, [{ start: 0, end: 16, expected: expected.toString("hex"), site: "derive/declared-u64-amount" }]);
}
export function clonePublic<T>(value: T): T {
    const copy = structuredClone(value);
    function visit(a: any, b: any) { if (a instanceof Uint8Array) {
        put(b, known(a));
        return;
    } if (a && typeof a === "object")
        for (const k of Object.keys(a))
            visit(a[k], b[k]); }
    visit(value, copy);
    return copy;
}
export function markPublicRecord(record: Uint8Array, amounts: {
    deposit?: bigint;
    withdrawal?: bigint;
    fee?: bigint;
    wlock?: Uint8Array;
} = {}) {
    let out = record;
    for (const [offset, value] of [[258, amounts.deposit ?? 0n], [266, amounts.withdrawal ?? 0n], [274, amounts.fee ?? 2000n]] as const) {
        const expected = publicU64(value);
        assert.equal(hex(record.slice(offset, offset + 8)), hex(expected));
        out = replacePublicBytes(out, offset, expected);
    }
    if (amounts.wlock === undefined)
        out = replacePublicBytes(out, 282, publicZeroBytes(32, "derive/default-zero-withdrawal-lock"));
    else
        out = replacePublicBytes(out, 282, amounts.wlock);
    assert.equal(hex(out), hex(record));
    return out;
}
function bind(root: any, path: (string | number)[], spans: Span[]) {
    if (!spans.length)
        return;
    let map = jsonOrigins.get(root);
    if (!map) {
        map = new Map();
        jsonOrigins.set(root, map);
    }
    map.set(JSON.stringify(path), spans.map(s => ({ ...s })));
}
export function bindHex(root: any, path: (string | number)[], bytes: Uint8Array) { bind(root, path, known(bytes)); }
export function bindHexSlice(root: any, path: (string | number)[], bytes: Uint8Array, offset: number, length: number) { bind(root, path, clipped(known(bytes), offset * 2, (offset + length) * 2)); }
export function restoreHex(root: any, path: (string | number)[]) {
    const value = path.reduce((node: any, k) => node[k], root), bytes = hexToBytes("fresh public copy", value);
    return put(bytes, jsonOrigins.get(root)?.get(JSON.stringify(path)) || []);
}
export function publicStatement(bytes: Uint8Array, records: readonly Uint8Array[]) {
    assert.equal(bytes.length, 88 + 314 * records.length);
    const available = new Set(records.map((_, i) => i)), spans: Span[] = [];
    for (let i = 0; i < records.length; i++) {
        const offset = 88 + 314 * i, part = hex(bytes.slice(offset, offset + 314));
        const k = records.findIndex((record, j) => available.has(j) && hex(record) === part);
        assert(k >= 0);
        available.delete(k);
        spans.push(...known(records[k]!).map(s => ({ ...s, start: s.start + offset * 2, end: s.end + offset * 2 })));
    }
    return put(bytes, spans);
}
export function encodePublicWitness(witness: any) {
    const json = encodeAPNTPoolActionWitnessJsonV1(witness);
    for (const kind of ["inputs", "outputs"] as const)
        witness[kind].forEach((value: any, i: number) => {
            for (const [field, source] of Object.entries(value)) {
                if (source instanceof Uint8Array)
                    bindHex(json, [kind, i, field], source);
                else if (typeof source === "bigint") {
                    const expected = source.toString();
                    bind(json, [kind, i, field], [{ start: 0, end: expected.length, expected, site: "case-constructor/public-numeric-scalar" }]);
                }
            }
            if (kind === "inputs" && value.membership)
                value.membership.siblings32.forEach((bytes: Uint8Array, h: number) => bindHex(json, [kind, i, "membership", "siblings", h], bytes));
        });
    return json;
}
export function restorePublicWitness(witness: any, json: any) {
    for (const kind of ["inputs", "outputs"] as const)
        witness[kind].forEach((value: any, i: number) => {
            for (const [field, source] of Object.entries(value))
                if (source instanceof Uint8Array)
                    put(source, jsonOrigins.get(json)?.get(JSON.stringify([kind, i, field])) || []);
            if (kind === "inputs" && value.membership)
                value.membership.siblings32.forEach((bytes: Uint8Array, h: number) => put(bytes, jsonOrigins.get(json)?.get(JSON.stringify([kind, i, "membership", "siblings", h])) || []));
        });
    return witness;
}
export function originsFor(root: any) {
    const result: {
        path: (string | number)[];
        spans: Span[];
    }[] = [];
    function visit(value: any, path: (string | number)[]) { if (!value || typeof value !== "object")
        return; for (const [p, spans] of jsonOrigins.get(value) || [])
        result.push({ path: path.concat(JSON.parse(p)), spans: spans.map(s => ({ ...s })) }); if (Array.isArray(value))
        value.forEach((v, i) => visit(v, path.concat(i)));
    else
        for (const [k, v] of Object.entries(value))
            visit(v, path.concat(k)); }
    visit(root, []);
    return result;
}
