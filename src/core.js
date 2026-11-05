// Core STUN attribute parsing and serialization.
//
// STUN attributes are type-length-value (TLV) triples. The type is a 16-bit
// value, the length is a 16-bit value counting bytes of the value only, and
// the value is padded to a 4-byte boundary. The padding bytes are not counted
// in the length field, but they are part of the wire format.
//
// XOR-MAPPED-ADDRESS (type 0x0020) encodes an IPv4 or IPv6 address with the
// port and address bytes XORed against a fixed mask derived from the magic
// cookie. This is the attribute NAT traversal relies on.

const MAGIC_COOKIE = 0x2112a442;

// Attribute type constants. These are the values defined by RFC 5389 and
// RFC 8489. Only the ones this library handles are listed.
export const ATTR_MAPPED_ADDRESS = 0x0001;
export const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
export const ATTR_USERNAME = 0x0006;
export const ATTR_MESSAGE_INTEGRITY = 0x0008;
export const ATTR_ERROR_CODE = 0x0009;
export const ATTR_UNKNOWN_ATTRIBUTES = 0x000a;
export const ATTR_REALM = 0x0014;
export const ATTR_NONCE = 0x0015;
export const ATTR_SOFTWARE = 0x8022;
export const ATTR_ALTERNATE_SERVER = 0x8023;
export const ATTR_FINGERPRINT = 0x8028;

// Address family codes used in MAPPED-ADDRESS and XOR-MAPPED-ADDRESS.
const FAMILY_IPV4 = 0x01;
const FAMILY_IPV6 = 0x02;

// Round a byte length up to the next multiple of four.
function pad4(length) {
  return (length + 3) & ~3;
}

// Parse an IPv4 address from four bytes into dotted-quad form.
function formatIPv4(bytes) {
  if (bytes.length !== 4) {
    throw new RangeError('IPv4 address must be exactly 4 bytes');
  }
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

// Parse an IPv6 address from sixteen bytes into the canonical compressed
// form. We do not attempt to compress runs of zeroes beyond the longest run,
// because the canonical form is what STUN peers expect and a wrong
// compression is worse than a longer string.
function formatIPv6(bytes) {
  if (bytes.length !== 16) {
    throw new RangeError('IPv6 address must be exactly 16 bytes');
  }
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push((bytes[i] << 8) | bytes[i + 1]);
  }

  // Find the longest run of zero groups for :: compression.
  let bestStart = -1;
  let bestLength = 0;
  let currentStart = -1;
  let currentLength = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (currentStart === -1) {
        currentStart = i;
        currentLength = 0;
      }
      currentLength++;
      if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
      }
    } else {
      currentStart = -1;
      currentLength = 0;
    }
  }

  if (bestLength < 2) {
    return groups.map((g) => g.toString(16)).join(':');
  }

  const before = groups.slice(0, bestStart).map((g) => g.toString(16)).join(':');
  const after = groups.slice(bestStart + bestLength).map((g) => g.toString(16)).join(':');
  return `${before}::${after}`;
}

// Parse a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS value. For XOR-MAPPED-ADDRESS
// the port and address bytes are XORed with the magic cookie and, for IPv6,
// with the transaction ID as well. We accept the transaction ID as an
// argument because the caller usually has it.
function parseAddressValue(value, xor, transactionId) {
  if (value.length < 4) {
    throw new RangeError('address attribute value must be at least 4 bytes');
  }
  const family = value[1];
  let port = (value[2] << 8) | value[3];
  if (xor) {
    port ^= MAGIC_COOKIE >>> 16;
  }
  let host;
  if (family === FAMILY_IPV4) {
    if (value.length < 8) {
      throw new RangeError('IPv4 address attribute value must be at least 8 bytes');
    }
    const addr = value.slice(4, 8);
    if (xor) {
      const mask = [
        (MAGIC_COOKIE >>> 24) & 0xff,
        (MAGIC_COOKIE >>> 16) & 0xff,
        (MAGIC_COOKIE >>> 8) & 0xff,
        MAGIC_COOKIE & 0xff,
      ];
      for (let i = 0; i < 4; i++) {
        addr[i] ^= mask[i];
      }
    }
    host = formatIPv4(addr);
  } else if (family === FAMILY_IPV6) {
    if (value.length < 20) {
      throw new RangeError('IPv6 address attribute value must be at least 20 bytes');
    }
    const addr = value.slice(4, 20);
    if (xor) {
      if (!transactionId || transactionId.length !== 12) {
        throw new RangeError('XOR-MAPPED-ADDRESS for IPv6 requires a 12-byte transaction ID');
      }
      const mask = new Uint8Array(16);
      mask[0] = (MAGIC_COOKIE >>> 24) & 0xff;
      mask[1] = (MAGIC_COOKIE >>> 16) & 0xff;
      mask[2] = (MAGIC_COOKIE >>> 8) & 0xff;
      mask[3] = MAGIC_COOKIE & 0xff;
      for (let i = 0; i < 12; i++) {
        mask[4 + i] = transactionId[i];
      }
      for (let i = 0; i < 16; i++) {
        addr[i] ^= mask[i];
      }
    }
    host = formatIPv6(addr);
  } else {
    throw new RangeError(`unsupported address family: ${family}`);
  }
  return { family, port, host };
}

// Serialize an address value. The caller supplies family, port, host, and
// optionally a transaction ID for XOR-MAPPED-ADDRESS. The host must be a
// string in dotted-quad or IPv6 form.
function serializeAddressValue(family, port, host, xor, transactionId) {
  if (!Number.isInteger(port) || port < 0 || port > 0xffff) {
    throw new RangeError('port must be an integer in [0, 65535]');
  }
  let addrBytes;
  if (family === FAMILY_IPV4) {
    const parts = host.split('.');
    if (parts.length !== 4) {
      throw new RangeError('IPv4 host must have four octets');
    }
    addrBytes = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255 || parts[i] === '') {
        throw new RangeError(`invalid IPv4 octet: ${parts[i]}`);
      }
      addrBytes[i] = n;
    }
  } else if (family === FAMILY_IPV6) {
    addrBytes = parseIPv6(host);
  } else {
    throw new RangeError(`unsupported address family: ${family}`);
  }

  let portField = port;
  const out = new Uint8Array(4 + addrBytes.length);
  out[0] = 0;
  out[1] = family;
  if (xor) {
    portField ^= MAGIC_COOKIE >>> 16;
  }
  out[2] = (portField >>> 8) & 0xff;
  out[3] = portField & 0xff;

  if (xor) {
    if (family === FAMILY_IPV4) {
      const mask = [
        (MAGIC_COOKIE >>> 24) & 0xff,
        (MAGIC_COOKIE >>> 16) & 0xff,
        (MAGIC_COOKIE >>> 8) & 0xff,
        MAGIC_COOKIE & 0xff,
      ];
      for (let i = 0; i < 4; i++) {
        out[4 + i] = addrBytes[i] ^ mask[i];
      }
    } else {
      if (!transactionId || transactionId.length !== 12) {
        throw new RangeError('XOR-MAPPED-ADDRESS for IPv6 requires a 12-byte transaction ID');
      }
      const mask = new Uint8Array(16);
      mask[0] = (MAGIC_COOKIE >>> 24) & 0xff;
      mask[1] = (MAGIC_COOKIE >>> 16) & 0xff;
      mask[2] = (MAGIC_COOKIE >>> 8) & 0xff;
      mask[3] = MAGIC_COOKIE & 0xff;
      for (let i = 0; i < 12; i++) {
        mask[4 + i] = transactionId[i];
      }
      for (let i = 0; i < 16; i++) {
        out[4 + i] = addrBytes[i] ^ mask[i];
      }
    }
  } else {
    out.set(addrBytes, 4);
  }
  return out;
}

// Parse an IPv6 string into sixteen bytes. We support the common forms:
// full eight-group, compressed with ::, and embedded IPv4 in the last two
// groups. We do not support zone identifiers.
function parseIPv6(host) {
  if (host.includes('::')) {
    const [left, right] = host.split('::');
    const leftGroups = left === '' ? [] : left.split(':');
    const rightGroups = right === '' ? [] : right.split(':');
    const total = leftGroups.length + rightGroups.length;
    if (total > 8) {
      throw new RangeError('IPv6 address has too many groups');
    }
    const missing = 8 - total;
    const groups = [
      ...leftGroups,
      ...Array(missing).fill('0'),
      ...rightGroups,
    ];
    return groupsToBytes(groups);
  }
  const groups = host.split(':');
  if (groups.length !== 8) {
    throw new RangeError('IPv6 address must have eight groups or use ::');
  }
  return groupsToBytes(groups);
}

function groupsToBytes(groups) {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const group = groups[i];
    if (group.length === 0 || group.length > 4) {
      throw new RangeError(`invalid IPv6 group: ${group}`);
    }
    const n = parseInt(group, 16);
    if (Number.isNaN(n) || n < 0 || n > 0xffff) {
      throw new RangeError(`invalid IPv6 group: ${group}`);
    }
    bytes[i * 2] = (n >>> 8) & 0xff;
    bytes[i * 2 + 1] = n & 0xff;
  }
  return bytes;
}

// Parse a single attribute from a buffer. Returns the attribute object and
// the number of bytes consumed, including padding. The caller is responsible
// for ensuring the buffer starts at an attribute boundary.
export function parseAttribute(buffer, offset = 0) {
  if (offset < 0 || offset + 4 > buffer.length) {
    throw new RangeError('truncated attribute header');
  }
  const type = (buffer[offset] << 8) | buffer[offset + 1];
  const length = (buffer[offset + 2] << 8) | buffer[offset + 3];
  const valueStart = offset + 4;
  const valueEnd = valueStart + length;
  if (valueEnd > buffer.length) {
    throw new RangeError('attribute value extends past end of buffer');
  }
  const value = buffer.slice(valueStart, valueEnd);
  const consumed = 4 + pad4(length);
  return { type, length, value, consumed };
}

// Parse all attributes in a buffer until it is exhausted. This is the common
// case when decoding a STUN message body.
export function parseAttributes(buffer) {
  const attributes = [];
  let offset = 0;
  while (offset < buffer.length) {
    const attr = parseAttribute(buffer, offset);
    attributes.push(attr);
    offset += attr.consumed;
  }
  return attributes;
}

// Serialize a single attribute into a Uint8Array, including padding. The
// value may be a Uint8Array, an ArrayBuffer, or a string (which is encoded as
// UTF-8). Strings are convenient for USERNAME, REALM, NONCE, and SOFTWARE.
export function serializeAttribute(type, value) {
  if (!Number.isInteger(type) || type < 0 || type > 0xffff) {
    throw new RangeError('attribute type must be an integer in [0, 65535]');
  }
  let bytes;
  if (typeof value === 'string') {
    bytes = new TextEncoder().encode(value);
  } else if (value instanceof Uint8Array) {
    bytes = value;
  } else if (value instanceof ArrayBuffer) {
    bytes = new Uint8Array(value);
  } else {
    throw new TypeError('attribute value must be a string, Uint8Array, or ArrayBuffer');
  }
  if (bytes.length > 0xffff) {
    throw new RangeError('attribute value exceeds 65535 bytes');
  }
  const padded = pad4(bytes.length);
  const out = new Uint8Array(4 + padded);
  out[0] = (type >>> 8) & 0xff;
  out[1] = type & 0xff;
  out[2] = (bytes.length >>> 8) & 0xff;
  out[3] = bytes.length & 0xff;
  out.set(bytes, 4);
  return out;
}

// Parse an XOR-MAPPED-ADDRESS or MAPPED-ADDRESS value into a structured
// object. The transaction ID is required for XOR-MAPPED-ADDRESS with IPv6.
export function parseAddress(value, xor = false, transactionId = null) {
  return parseAddressValue(value, xor, transactionId);
}

// Serialize an address into a value suitable for XOR-MAPPED-ADDRESS or
// MAPPED-ADDRESS. The family is inferred from the host string unless the
// caller passes it explicitly.
export function serializeAddress(port, host, xor = false, transactionId = null) {
  const family = host.includes(':') ? FAMILY_IPV6 : FAMILY_IPV4;
  return serializeAddressValue(family, port, host, xor, transactionId);
}

// Convenience helpers for the two address attributes. These wrap the generic
// parse/serialize functions so callers do not have to remember the XOR flag.
export function parseXorMappedAddress(value, transactionId) {
  return parseAddress(value, true, transactionId);
}

export function serializeXorMappedAddress(port, host, transactionId) {
  return serializeAddress(port, host, true, transactionId);
}

export function parseMappedAddress(value) {
  return parseAddress(value, false, null);
}

export function serializeMappedAddress(port, host) {
  return serializeAddress(port, host, false, null);
}
