#!/bin/bash
#TC use only
# Def
SALT="401112740954257854"

read -sp "Enter desired password: " PASSWORD
echo
read -sp "Confirm password: " PASSWORD_CONFIRM
echo

if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
  echo "❌ Error: Passwords do not match. Aborting."
  exit 1
fi

HASHED_PASSWORD=$(echo -n "$PASSWORD$SALT" | openssl dgst -sha256 -binary | base64)

echo
echo "✅ Generated Hash: $HASHED_PASSWORD"
echo
echo "📜 SQL Update Statement:"
echo "UPDATE usertable SET authenticatorSecretKey = NULL, password = '$HASHED_PASSWORD', salt = '$SALT', resetRequired = 0, locked = 0 WHERE id = 9use_id_of_your_user;"