export const ENDPOINT_ID_PATTERN = /^[0-9a-f]{64}$/;

export function parseEndpointId(value: string): string {
  const endpointId = value.trim();
  if (!ENDPOINT_ID_PATTERN.test(endpointId)) {
    throw new Error(
      "bridge EndpointId must be exactly 64 lowercase hex characters",
    );
  }
  return endpointId;
}

export function requireSelect(sql: string): string {
  const statement = sql.trim();
  if (!/^(?:select|with)\b/i.test(statement)) {
    throw new Error("the demo query must start with SELECT or WITH");
  }
  return statement;
}

export function displayValue(value: unknown): string {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array) {
    return [...value]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }
  if (typeof value === "object") {
    try {
      return JSON.stringify(value, (_, nested) =>
        typeof nested === "bigint" ? nested.toString() : nested,
      );
    } catch {
      return String(value);
    }
  }
  return String(value);
}
