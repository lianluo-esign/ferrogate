#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Validate OpenAPI, runtime route drift, and the reviewed compatibility baseline.

from __future__ import annotations

from openapi_contract import ROOT, validate_repository_contract


def main() -> int:
    failures = validate_repository_contract()
    if failures:
        for failure in failures:
            print(failure)
        return 1
    print("validated docs/openapi/admin-api.openapi.json")
    print("validated runtime/OpenAPI bidirectional operation contract")
    print("validated docs/openapi/admin-api.compatibility-baseline.json")
    print(f"contract root: {ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
