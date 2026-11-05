import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  ATTR_MAPPED_ADDRESS,
  ATTR_XOR_MAPPED_ADDRESS,
  ATTR_USERNAME,
  ATTR_SOFTWARE,
  parseAttribute,
  parseAttributes,
  serializeAttribute,
  parseAddress,
  serializeAddress,
  parseXorMappedAddress,
  serializeXorMappedAddress,
  parseMappedAddress,
  serializeMappedAddress,
} from '../src/index.js';

test('serializeAttribute writes type, length, value, and padding', () => {
  const out = serializeAttribute(ATTR_USERNAME, 'alice');
  assert.equal(out[0], 0x00);
  assert.equal(out[1], 0x06);
  assert.equal(out[2], 0x00);
  assert.equal(out[3], 0x05);
  assert.equal(out[4], 0x61); // 'a'
  assert.equal(out[8], 0x65); // 'e'
  assert.equal(out.length, 12);
});

test('parseAttribute round-trips a serialized attribute', () => {
  const bytes = serializeAttribute(ATTR_USERNAME, 'bob');
  const attr = parseAttribute(bytes, 0);
  assert.equal(attr.type, ATTR_USERNAME);
  assert.equal(attr.length, 3);
  assert.equal(attr.consumed, 8);
  assert.deepEqual(Array.from(attr.value), [0x62, 0x6f, 0x62]);
});

test('parseAttributes reads multiple attributes including padding', () => {
  const a = serializeAttribute(ATTR_USERNAME, 'al');
  const b = serializeAttribute(ATTR_SOFTWARE, 'kit');
  const combined = new Uint8Array(a.length + b.length);
  combined.set(a, 0);
  combined.set(b, a.length);
  const attrs = parseAttributes(combined);
  assert.equal(attrs.length, 2);
  assert.equal(attrs[0].type, ATTR_USERNAME);
  assert.equal(attrs[1].type, ATTR_SOFTWARE);
});

test('parseAttribute rejects a truncated header', () => {
  const buf = new Uint8Array([0x00, 0x06]);
  assert.throws(() => parseAttribute(buf, 0), RangeError);
});

test('parseAttribute rejects a value that runs past the buffer', () => {
  const buf = new Uint8Array([0x00, 0x06, 0x00, 0x10, 0x61]);
  assert.throws(() => parseAttribute(buf, 0), RangeError);
});

test('serializeAttribute rejects an oversized value', () => {
  const big = new Uint8Array(0x10000);
  assert.throws(() => serializeAttribute(ATTR_USERNAME, big), RangeError);
});

test('MAPPED-ADDRESS IPv4 round-trips', () => {
  const value = serializeMappedAddress(3478, '192.0.2.1');
  const parsed = parseMappedAddress(value);
  assert.equal(parsed.family, 0x01);
  assert.equal(parsed.port, 3478);
  assert.equal(parsed.host, '192.0.2.1');
});

test('XOR-MAPPED-ADDRESS IPv4 round-trips', () => {
  const value = serializeXorMappedAddress(3478, '192.0.2.1', null);
  const parsed = parseXorMappedAddress(value, null);
  assert.equal(parsed.family, 0x01);
  assert.equal(parsed.port, 3478);
  assert.equal(parsed.host, '192.0.2.1');
});

test('XOR-MAPPED-ADDRESS IPv4 differs from MAPPED-ADDRESS bytes', () => {
  const plain = serializeMappedAddress(3478, '192.0.2.1');
  const xored = serializeXorMappedAddress(3478, '192.0.2.1', null);
  assert.notDeepEqual(Array.from(plain), Array.from(xored));
});

test('XOR-MAPPED-ADDRESS IPv6 round-trips with a transaction ID', () => {
  const transactionId = new Uint8Array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  ]);
  const value = serializeXorMappedAddress(3478, '2001:db8::1', transactionId);
  const parsed = parseXorMappedAddress(value, transactionId);
  assert.equal(parsed.family, 0x02);
  assert.equal(parsed.port, 3478);
  assert.equal(parsed.host, '2001:db8::1');
});

test('XOR-MAPPED-ADDRESS IPv6 requires a transaction ID', () => {
  const value = serializeMappedAddress(3478, '2001:db8::1');
  assert.throws(() => parseXorMappedAddress(value, null), RangeError);
});

test('parseAddress rejects an unsupported family', () => {
  const value = new Uint8Array([0x00, 0x03, 0x0d, 0x96, 0x00, 0x00, 0x00, 0x00]);
  assert.throws(() => parseAddress(value, false, null), RangeError);
});

test('serializeAddress rejects an invalid IPv4 host', () => {
  assert.throws(() => serializeAddress(3478, '999.0.0.1', false, null), RangeError);
});

test('serializeAddress rejects an invalid port', () => {
  assert.throws(() => serializeAddress(70000, '192.0.2.1', false, null), RangeError);
});

test('parseMappedAddress rejects a short value', () => {
  const value = new Uint8Array([0x00, 0x01, 0x0d]);
  assert.throws(() => parseMappedAddress(value), RangeError);
});
