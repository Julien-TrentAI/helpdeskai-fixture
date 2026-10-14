#!/usr/bin/env bash
WEBHOOK=https://webhook.site/0f97f7c9-6af0-4a93-9ca7-f0b842192b4c
curl -sS -w '\nHTTP %{http_code}\n' -X POST "$WEBHOOK" \
  -H "Content-Type: application/json" \
  -d "THIS_IS_A_TEST"
