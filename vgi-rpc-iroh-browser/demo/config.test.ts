import assert from "node:assert/strict";
import test from "node:test";

import { displayValue, parseEndpointId, requireSelect } from "./config.ts";

test("parseEndpointId accepts only the canonical bridge identity", () => {
  const endpointId = "0a".repeat(32);
  assert.equal(parseEndpointId(`  ${endpointId}  `), endpointId);
  assert.throws(
    () => parseEndpointId(endpointId.toUpperCase()),
    /lowercase hex/,
  );
  assert.throws(() => parseEndpointId(`${endpointId}/path`), /lowercase hex/);
  assert.throws(() => parseEndpointId("0a"), /lowercase hex/);
});

test("requireSelect keeps the demo read-only", () => {
  assert.equal(requireSelect("  SELECT 42; "), "SELECT 42;");
  assert.equal(
    requireSelect("with x as (select 1) select * from x"),
    "with x as (select 1) select * from x",
  );
  assert.throws(
    () => requireSelect("DROP TABLE remote.main.x"),
    /SELECT or WITH/,
  );
});

test("displayValue renders Arrow-friendly values without BigInt JSON failures", () => {
  assert.equal(displayValue(42n), "42");
  assert.equal(displayValue(null), "NULL");
  assert.equal(displayValue(new Uint8Array([0, 15, 255])), "000fff");
  assert.equal(displayValue({ value: 9n }), '{"value":"9"}');
});
