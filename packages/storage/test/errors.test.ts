import { describe, expect, test } from "vitest";
import { StorageError, sanitizeStorageError } from "../src/index.js";

describe("sanitizeStorageError", () => {
  test("redacts libpq password= marker up to a delimiter", () => {
    expect(sanitizeStorageError("host=db password=hunter2 dbname=x")).toBe(
      "host=db password=[redacted] dbname=x",
    );
  });

  test("redacts passfile= and sslpassword= markers", () => {
    expect(sanitizeStorageError("sslpassword=abc;passfile=/tmp/p x")).toBe(
      "sslpassword=[redacted];passfile=[redacted] x",
    );
  });

  test("redacts the password segment of a DSN URL", () => {
    expect(sanitizeStorageError("postgres://user:s3cr3t@host:5432/db failed")).toBe(
      "postgres://user:[redacted]@host:5432/db failed",
    );
  });

  test("leaves a URL with no password untouched", () => {
    expect(sanitizeStorageError("postgres://host:5432/db")).toBe("postgres://host:5432/db");
  });

  test("StorageError.postgres scrubs the detail through the sanitizer", () => {
    const err = StorageError.postgres("connect postgres://u:pw@h/db");
    expect(err.message).toContain("[redacted]");
    expect(err.message).not.toContain("pw@");
    expect(err.kind).toBe("postgres");
  });
});

describe("StorageError taxonomy", () => {
  test("carries the discriminant and commit-fence bit", () => {
    const err = StorageError.operationDeadlineExceeded("reserve", "commit", true);
    expect(err.kind).toBe("operation_deadline_exceeded");
    expect(err.data.commitStarted).toBe(true);
    expect(err).toBeInstanceOf(Error);
  });

  test("unsupportedProvider renders provider + required", () => {
    const err = StorageError.unsupportedProvider("mysql", true);
    expect(err.message).toBe("storage provider mysql is not implemented yet (required=true)");
  });
});
