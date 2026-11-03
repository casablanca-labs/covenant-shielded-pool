const HEX_RE = /^[0-9a-f]*$/;

declare const bytes32Brand: unique symbol;

export type Bytes32 = Uint8Array & { readonly [bytes32Brand]: true };

export function copyBytes(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("bytes: value must be a Uint8Array");
  }
  return new Uint8Array(bytes);
}

export function assertByteLength(name: string, bytes: Uint8Array, expectedLength: number): void {
  if (!Number.isSafeInteger(expectedLength) || expectedLength < 0) {
    throw new Error("bytes: expectedLength must be a non-negative safe integer");
  }
  if (!(bytes instanceof Uint8Array)) {
    throw new Error(`bytes: ${name} must be a Uint8Array`);
  }
  if (bytes.length !== expectedLength) {
    throw new Error(
      `bytes: ${name} must be exactly ${String(expectedLength)} bytes, got ${String(bytes.length)}`,
    );
  }
}

export function asFixedBytes(name: string, bytes: Uint8Array, expectedLength: number): Uint8Array {
  assertByteLength(name, bytes, expectedLength);
  return copyBytes(bytes);
}

export function asBytes32(name: string, bytes: Uint8Array): Bytes32 {
  return asFixedBytes(name, bytes, 32) as Bytes32;
}

export function bytesToHex(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("bytes: bytesToHex input must be a Uint8Array");
  }
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(name: string, hex: string): Uint8Array {
  if (typeof hex !== "string") {
    throw new Error(`bytes: ${name} must be a lowercase hex string`);
  }
  if (hex.startsWith("0x")) {
    throw new Error(`bytes: ${name} must not include a 0x prefix`);
  }
  if ((hex.length & 1) !== 0) {
    throw new Error(`bytes: ${name} must have even length`);
  }
  if (!HEX_RE.test(hex)) {
    throw new Error(`bytes: ${name} must be lowercase hex`);
  }

  const out = new Uint8Array(hex.length / 2);
  for (let offset = 0; offset < hex.length; offset += 2) {
    out[offset / 2] = Number.parseInt(hex.slice(offset, offset + 2), 16);
  }
  return out;
}

export function hexToFixedBytes(name: string, hex: string, expectedLength: number): Uint8Array {
  const bytes = hexToBytes(name, hex);
  return asFixedBytes(name, bytes, expectedLength);
}

export function hexToBytes32(name: string, hex: string): Bytes32 {
  return asBytes32(name, hexToBytes(name, hex));
}
