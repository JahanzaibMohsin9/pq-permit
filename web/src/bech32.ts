// Minimal BIP-173 bech32 (qor1… addresses), dependency-free.
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

const hrpExpand = (hrp: string) => [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];

function convertBits(data: ArrayLike<number>, from: number, to: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    const value = data[i];
    if (value < 0 || value >> from) throw new Error("bech32: invalid data");
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    throw new Error("bech32: invalid padding");
  }
  return out;
}

export function bech32Decode(address: string): { prefix: string; data: Uint8Array } {
  const s = address.toLowerCase();
  if (s !== address && address.toUpperCase() !== address) throw new Error("bech32: mixed case");
  const pos = s.lastIndexOf("1");
  if (pos < 1 || pos + 7 > s.length || s.length > 90) throw new Error("bech32: bad format");
  const prefix = s.slice(0, pos);
  const words = [...s.slice(pos + 1)].map((c) => {
    const v = CHARSET.indexOf(c);
    if (v < 0) throw new Error("bech32: bad character");
    return v;
  });
  if (polymod([...hrpExpand(prefix), ...words]) !== 1) throw new Error("bech32: bad checksum");
  return { prefix, data: Uint8Array.from(convertBits(words.slice(0, -6), 5, 8, false)) };
}

export function bech32Encode(prefix: string, data: Uint8Array): string {
  const words = convertBits(data, 8, 5, true);
  const mod = polymod([...hrpExpand(prefix), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, i) => (mod >>> (5 * (5 - i))) & 31);
  return `${prefix}1${[...words, ...checksum].map((w) => CHARSET[w]).join("")}`;
}
