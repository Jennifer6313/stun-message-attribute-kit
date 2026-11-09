# stun-message-attribute-kit

Parses and serializes STUN attribute type-length-value pairs, including XOR-MAPPED-ADDRESS for NAT traversal.

```js
import {
  ATTR_XOR_MAPPED_ADDRESS,
  serializeXorMappedAddress,
  parseXorMappedAddress,
  serializeAttribute,
  parseAttribute,
} from 'stun-message-attribute-kit';

// Build an XOR-MAPPED-ADDRESS value for an IPv4 peer.
const value = serializeXorMappedAddress(3478, '192.0.2.1', null);
const decoded = parseXorMappedAddress(value, null);
console.log(decoded); // { family: 1, port: 3478, host: '192.0.2.1' }

// Wrap it in a full attribute TLV.
const tlv = serializeAttribute(ATTR_XOR_MAPPED_ADDRESS, value);
const attr = parseAttribute(tlv, 0);
console.log(attr.type === ATTR_XOR_MAPPED_ADDRESS); // true
```

## Why this exists

STUN attributes are simple on the surface, but the XOR-MAPPED-ADDRESS attribute hides a second layer: the port and address bytes are XORed with a mask derived from the magic cookie, and for IPv6 the mask also includes the transaction ID. Getting that mask wrong produces a value that looks plausible but decodes to the wrong address, which is exactly the failure mode that breaks NAT traversal in the field. This library keeps the mask logic in one place and makes the transaction ID an explicit argument, so the caller cannot accidentally omit it for IPv6.

The trade-off is that this is not a full STUN message parser. It handles attributes and address values only. Message framing, authentication, and integrity checks belong to a higher layer, and mixing them in here would make the attribute code harder to test in isolation.

## Edge case to know about

XOR-MAPPED-ADDRESS for IPv6 requires a 12-byte transaction ID. The serializer and parser both throw a `RangeError` if it is missing or the wrong length. IPv4 does not need it, so passing `null` is correct there. If you are decoding an IPv6 XOR-MAPPED-ADDRESS and you do not have the transaction ID, you cannot recover the address from the XORed bytes alone.

## API

Exports from the package root:

- Constants: `ATTR_MAPPED_ADDRESS`, `ATTR_XOR_MAPPED_ADDRESS`, `ATTR_USERNAME`, `ATTR_MESSAGE_INTEGRITY`, `ATTR_ERROR_CODE`, `ATTR_UNKNOWN_ATTRIBUTES`, `ATTR_REALM`, `ATTR_NONCE`, `ATTR_SOFTWARE`, `ATTR_ALTERNATE_SERVER`, `ATTR_FINGERPRINT`.
- `parseAttribute(buffer, offset = 0)` returns `{ type, length, value, consumed }`.
- `parseAttributes(buffer)` returns an array of those objects.
- `serializeAttribute(type, value)` returns a `Uint8Array` including padding.
- `parseAddress(value, xor = false, transactionId = null)` and `serializeAddress(port, host, xor = false, transactionId = null)`.
- `parseXorMappedAddress(value, transactionId)`, `serializeXorMappedAddress(port, host, transactionId)`.
- `parseMappedAddress(value)`, `serializeMappedAddress(port, host)`.

Address objects have the shape `{ family, port, host }`, where `family` is `1` for IPv4 and `2` for IPv6.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

