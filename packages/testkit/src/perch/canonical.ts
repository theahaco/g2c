// Canonical JSON (RFC 8785 / JCS subset) and doc_hash.
//
// VENDORED from @stellar-registry/perch (packages/perch-js/src/canonical.ts) —
// that package is not yet published to npm, and the testkit must produce a
// doc_hash byte-identical to on-chain perch. Kept verbatim so the two never
// drift; if perch bumps CANON_VERSION, re-vendor. Source of truth: perch's
// CANONICAL.md. Do not "improve" the escaping here — its whole purpose is to
// match the Rust canon.rs byte-for-byte.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

/** Canonical-form version, mirroring perch-ir's CANON_VERSION. A format
 *  identifier, not part of the hash preimage. */
export const CANON_VERSION = 1;

const HEX = '0123456789abcdef';

/** Write `s` as a canonical JSON string literal per RFC 8785 §3.2.2.2 —
 *  implemented directly (not `JSON.stringify`) so the hashed bytes are defined
 *  here, not inherited from a runtime serializer. */
function writeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    switch (ch) {
      case '"': out += '\\"'; break;
      case '\\': out += '\\\\'; break;
      case '\b': out += '\\b'; break;
      case '\t': out += '\\t'; break;
      case '\n': out += '\\n'; break;
      case '\f': out += '\\f'; break;
      case '\r': out += '\\r'; break;
      default: {
        const code = ch.codePointAt(0)!;
        if (code < 0x20) {
          out += '\\u00' + HEX[(code >> 4) & 0xf] + HEX[code & 0xf];
        } else {
          out += ch;
        }
      }
    }
  }
  return out + '"';
}

function write(v: unknown): string {
  if (v === null) {
    throw new Error('canonical form must not contain null');
  }
  switch (typeof v) {
    case 'string':
      return writeString(v);
    case 'number':
      if (!Number.isInteger(v)) throw new Error(`non-integer number in canonical form: ${v}`);
      return String(v);
    case 'boolean':
      return v ? 'true' : 'false';
    case 'object': {
      if (Array.isArray(v)) return `[${v.map(write).join(',')}]`;
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return `{${keys.map((k) => `${writeString(k)}:${write(obj[k])}`).join(',')}}`;
    }
    default:
      throw new Error(`unserializable value in canonical form: ${typeof v}`);
  }
}

/** Serialize a policy document to its canonical JSON form. */
export function canonicalJson(doc: unknown): string {
  return write(doc);
}

/** Lowercase-hex SHA-256 of the canonical JSON bytes — the document's identity. */
export function docHash(doc: unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalJson(doc))));
}
