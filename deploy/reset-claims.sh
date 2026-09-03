#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: reset-claims.sh <github-login> [--yes]

Backs up and removes repository claim records for one GitHub user.
This does not delete repositories or invitations from GitHub.
EOF
}

if (( $# < 1 || $# > 2 )); then
  usage >&2
  exit 2
fi

github_login=$1
assume_yes=false
if (( $# == 2 )); then
  if [[ $2 != "--yes" ]]; then
    usage >&2
    exit 2
  fi
  assume_yes=true
fi

if [[ ! $github_login =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]] ||
  [[ $github_login == *--* ]]; then
  echo "Invalid GitHub login: $github_login" >&2
  exit 2
fi

readonly database_name=os_camp
readonly table_name=spark_repo_claims
readonly backup_dir=/var/backups/spark-initiative-backend

matching=$(sudo mariadb --batch --skip-column-names "$database_name" -e \
  "SELECT COUNT(*) FROM $table_name WHERE github_login = '$github_login';")

if [[ $matching == "0" ]]; then
  echo "No claim records found for $github_login."
  exit 0
fi

echo "Claim records to remove:"
sudo mariadb --table "$database_name" -e \
  "SELECT github_id, phase, github_login, repo_name, repo_id,
          FROM_UNIXTIME(created_at) AS created_at,
          FROM_UNIXTIME(completed_at) AS completed_at
   FROM $table_name
   WHERE github_login = '$github_login'
   ORDER BY github_id, phase;"

if [[ $assume_yes != true ]]; then
  read -r -p "Type '$github_login' to back up and remove these records: " confirmation
  if [[ $confirmation != "$github_login" ]]; then
    echo "Cancelled."
    exit 1
  fi
fi

timestamp=$(date +%Y%m%d-%H%M%S)
backup_file="$backup_dir/$github_login-claims-before-reset-$timestamp.sql"

sudo install -d -m 0700 "$backup_dir"
sudo mariadb-dump \
  --no-create-info \
  --skip-comments \
  --compact \
  --single-transaction \
  "$database_name" "$table_name" \
  --where="github_login = '$github_login'" \
  --result-file="$backup_file"
sudo chmod 0600 "$backup_file"
sudo test -s "$backup_file"

deleted=$(sudo mariadb --batch --skip-column-names "$database_name" -e \
  "START TRANSACTION;
   DELETE FROM $table_name WHERE github_login = '$github_login';
   SELECT ROW_COUNT();
   COMMIT;")

remaining=$(sudo mariadb --batch --skip-column-names "$database_name" -e \
  "SELECT COUNT(*) FROM $table_name WHERE github_login = '$github_login';")

if [[ $remaining != "0" ]]; then
  echo "Reset did not complete: $remaining record(s) remain. Backup: $backup_file" >&2
  exit 1
fi

echo "Removed $deleted claim record(s) for $github_login."
echo "Backup: $backup_file"
