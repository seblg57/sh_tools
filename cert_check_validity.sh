#!/bin/bash

THRESHOLD_DAYS=30
NOW=$(date +%s)

echo "🔍 Checking certificate expirations..."
echo

certbot certificates | awk '
/Certificate Name:/ { domain=$3 }
/Expiry Date:/ {
    expiry=$0
    split($0, a, ": ")
    date_str = a[2]
    "date -d \"" date_str "\" +%s" | getline exp_ts
    close("date -d \"" date_str "\" +%s")
    now_ts = '"$NOW"'
    days_left = int((exp_ts - now_ts) / 86400)

    status = (days_left < '"$THRESHOLD_DAYS"') ? "⚠️  " : "✅"

    printf "%s %-25s expires in %3d days (%s)\n", status, domain, days_left, date_str
}
'