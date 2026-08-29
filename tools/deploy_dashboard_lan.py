#!/usr/bin/env python3
# ruff: noqa: E501
"""Deploy validated ARTIFEX dashboard output to VM100 with rollback."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import stat
import tarfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRET_FILE = Path(r"C:\aidev\cruggerserver\_secret.txt")
HOST = "192.168.1.193"


@dataclass(frozen=True, slots=True)
class DashboardTarget:
    build: Path
    stack: str
    container: str
    hostname: str
    marker: str
    state_namespace: str
    state_id: str


TARGETS = {
    "operational": DashboardTarget(
        build=ROOT / "docs" / "implementation" / "dashboard",
        stack="/opt/stacks/artifex-dashboard",
        container="artifex-dashboard",
        hostname="artifex-dev.crugger.lan",
        marker="ARTIFEX DASHBOARD",
        state_namespace="project",
        state_id="ARTIFEX",
    ),
    "implementation": DashboardTarget(
        build=ROOT / "implementation" / "dashboard",
        stack="/opt/stacks/artifex-implementation-dashboard",
        container="artifex-implementation-dashboard",
        hostname="artifex-impl.crugger.lan",
        marker="ARTIFEX IMPLEMENTATION DASHBOARD",
        state_namespace="program",
        state_id="ARTIFEX-2.0-IMPLEMENTATION",
    ),
}


def load_secret(path: Path, name: str) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    for block in re.split(r"\n\s*\n", text):
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines or lines[0] != name:
            continue
        values: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                values[key.strip().lower()] = value.strip()
        if not {"user", "pass"} <= values.keys():
            raise RuntimeError(f"secret block {name} lacks user/pass")
        return values
    raise RuntimeError(f"missing secret block: {name}")


def dashboard_archive(target: DashboardTarget) -> tuple[bytes, str, str, str]:
    build = target.build
    required = [build / "index.html", build / "state.json"]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(f"dashboard is not rendered; missing: {', '.join(missing)}")
    state = json.loads((build / "state.json").read_text(encoding="utf-8"))
    actual_id = state.get(target.state_namespace, {}).get("id")
    if actual_id != target.state_id:
        raise RuntimeError(
            f"dashboard identity mismatch for {target.hostname}: "
            f"expected {target.state_namespace}.id={target.state_id!r}, got {actual_id!r}"
        )
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(build.rglob("*")):
            if not path.is_file():
                continue
            data = path.read_bytes()
            info = tarfile.TarInfo(path.relative_to(build).as_posix())
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, BytesIO(data))
    payload = buffer.getvalue()
    return (
        payload,
        sha256(payload).hexdigest(),
        sha256(required[0].read_bytes()).hexdigest(),
        sha256(required[1].read_bytes()).hexdigest(),
    )


REMOTE_SCRIPT = r"""#!/usr/bin/env bash
set -Eeuo pipefail

STAMP="$1"
EXPECTED_INDEX_SHA="$2"
EXPECTED_STATE_SHA="$3"
STACK="$4"
CONTAINER="$5"
HOSTNAME="$6"
MARKER="$7"
RELEASE="$STACK/releases/$STAMP"
BACKUP="$STACK/backups/$STAMP"
CADDY=/opt/stacks/caddy/Caddyfile
DNS=/etc/dnsmasq.d/crugger-lan.conf
ARCHIVE="/tmp/${CONTAINER}-${STAMP}.tar.gz"

mkdir -p "$RELEASE" "$BACKUP"
cp -a "$CADDY" "$BACKUP/Caddyfile.before"
cp -a "$DNS" "$BACKUP/crugger-lan.conf.before"
if [ -f "$STACK/docker-compose.yml" ]; then cp -a "$STACK/docker-compose.yml" "$BACKUP/docker-compose.yml.before"; fi
if [ -L "$STACK/current" ]; then readlink "$STACK/current" > "$BACKUP/current.before"; fi

rollback() {
  code=$?
  set +e
  cp -a "$BACKUP/Caddyfile.before" "$CADDY"
  docker exec caddy caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1
  cp -a "$BACKUP/crugger-lan.conf.before" "$DNS"
  systemctl restart dnsmasq >/dev/null 2>&1
  if [ -f "$BACKUP/docker-compose.yml.before" ]; then
    cp -a "$BACKUP/docker-compose.yml.before" "$STACK/docker-compose.yml"
    if [ -f "$BACKUP/current.before" ]; then ln -sfn "$(cat "$BACKUP/current.before")" "$STACK/current"; fi
    (cd "$STACK" && docker compose up -d >/dev/null 2>&1)
  else
    (cd "$STACK" && docker compose down >/dev/null 2>&1)
  fi
  echo "ARTIFEX_DASHBOARD ROLLED_BACK stamp=$STAMP exit=$code" >&2
  exit "$code"
}
trap rollback ERR

tar -xzf "$ARCHIVE" -C "$RELEASE"
test -f "$RELEASE/index.html"
test -f "$RELEASE/state.json"
echo "$EXPECTED_INDEX_SHA  $RELEASE/index.html" | sha256sum --check --status
echo "$EXPECTED_STATE_SHA  $RELEASE/state.json" | sha256sum --check --status
grep -q 'ARTIFEX' "$RELEASE/index.html"
ln -sfn "releases/$STAMP" "$STACK/current"

cat > "$STACK/docker-compose.yml" <<YAML
services:
  dashboard:
    image: caddy:2-alpine
    container_name: $CONTAINER
    restart: unless-stopped
    command: ["caddy", "file-server", "--root", "/srv", "--listen", ":8080"]
    volumes:
      - ./current:/srv:ro
    networks:
      - caddy_proxy
networks:
  caddy_proxy:
    external: true
YAML

cd "$STACK"
docker compose config --quiet
docker compose up -d --force-recreate

python3 - "$CADDY" "$HOSTNAME" "$CONTAINER" "$MARKER" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
hostname = sys.argv[2]
container = sys.argv[3]
marker = sys.argv[4]
text = path.read_text(encoding="utf-8")
begin = f'# BEGIN {marker}'
end = f'# END {marker}'
block = f'''{begin}
http://{hostname} {{
	respond "Not Found" 404
}}

https://{hostname} {{
	tls internal
	encode gzip
	header {{
		Cache-Control "no-store"
		Referrer-Policy "no-referrer"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
	}}
	@private remote_ip 192.168.1.0/24 100.64.0.0/10 10.0.0.0/8 172.16.0.0/12
	handle @private {{
		reverse_proxy {container}:8080
	}}
	respond "Forbidden" 403
}}
{end}'''
if begin in text and end in text:
    start = text.index(begin)
    finish = text.index(end, start) + len(end)
    text = text[:start] + block + text[finish:]
elif begin in text or end in text:
    raise SystemExit("incomplete ARTIFEX Caddy marker block")
else:
    text = text.rstrip() + "\n\n" + block + "\n"
path.with_suffix(f".{container}-candidate").write_text(text, encoding="utf-8")
PY

docker run --rm --network caddy_proxy \
  -v "/opt/stacks/caddy/Caddyfile.${CONTAINER}-candidate:/etc/caddy/Caddyfile:ro" \
  caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile
cp -a "/opt/stacks/caddy/Caddyfile.${CONTAINER}-candidate" "$CADDY"
docker exec caddy caddy reload --config /etc/caddy/Caddyfile

python3 - "$DNS" "$HOSTNAME" "$CONTAINER" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
name = sys.argv[2]
container = sys.argv[3]
expected = f"host-record={name},192.168.1.193"
matches = [line for line in lines if name in line and not line.lstrip().startswith("#")]
if matches and expected not in matches:
    raise SystemExit(f"conflicting DNS entry for {name}")
if expected not in lines:
    lines.append(expected)
path.with_suffix(f".{container}-candidate").write_text(
    "\n".join(lines) + "\n", encoding="utf-8"
)
PY

dnsmasq --test --conf-file="/etc/dnsmasq.d/crugger-lan.${CONTAINER}-candidate"
cp -a "/etc/dnsmasq.d/crugger-lan.${CONTAINER}-candidate" "$DNS"
systemctl restart dnsmasq

for attempt in $(seq 1 30); do
  if curl -kfsS --resolve "${HOSTNAME}:443:127.0.0.1" \
      -o "/tmp/${CONTAINER}-health-${STAMP}.html" \
      "https://${HOSTNAME}/" && \
      grep -q 'ARTIFEX' "/tmp/${CONTAINER}-health-${STAMP}.html"; then
    break
  fi
  if [ "$attempt" = 30 ]; then false; fi
  sleep 1
done
curl -kfsS --resolve "${HOSTNAME}:443:127.0.0.1" \
  -o "/tmp/${CONTAINER}-state-${STAMP}.json" \
  "https://${HOSTNAME}/state.json"
echo "$EXPECTED_STATE_SHA  /tmp/${CONTAINER}-state-${STAMP}.json" | sha256sum --check --status

DNS_RESULT=$(dig +short @127.0.0.1 "$HOSTNAME" | tail -1)
test "$DNS_RESULT" = "192.168.1.193"
HTTPS_RESULT=$(curl -k -sS -o /dev/null -w '%{http_code}' --resolve "${HOSTNAME}:443:127.0.0.1" "https://${HOSTNAME}/")
HTTP_RESULT=$(curl -sS -o /dev/null -w '%{http_code}' --resolve "${HOSTNAME}:80:127.0.0.1" "http://${HOSTNAME}/")
test "$HTTPS_RESULT" = "200"
test "$HTTP_RESULT" = "404"
ATLAS_RESULT=$(curl -k -sS -o /dev/null -w '%{http_code}' --resolve atlas-impl.crugger.lan:443:127.0.0.1 https://atlas-impl.crugger.lan/)
PANDORA_RESULT=$(curl -k -sS -o /dev/null -w '%{http_code}' --resolve pandora-dev.crugger.lan:443:127.0.0.1 https://pandora-dev.crugger.lan/)
ARTIFEX_V1_RESULT=$(curl -k -sS -o /dev/null -w '%{http_code}' --resolve artifex-dev.crugger.lan:443:127.0.0.1 https://artifex-dev.crugger.lan/)
test "$ATLAS_RESULT" = "200"
test "$PANDORA_RESULT" = "200"
test "$ARTIFEX_V1_RESULT" = "200"

trap - ERR
rm -f "$ARCHIVE" "/tmp/${CONTAINER}-health-${STAMP}.html" "/tmp/${CONTAINER}-state-${STAMP}.json" \
  "/opt/stacks/caddy/Caddyfile.${CONTAINER}-candidate" "/etc/dnsmasq.d/crugger-lan.${CONTAINER}-candidate"
echo "ARTIFEX_DASHBOARD DEPLOYED stamp=$STAMP"
echo "DNS=$DNS_RESULT"
echo "CONTAINER=$(docker inspect "$CONTAINER" --format '{{.State.Status}} {{.HostConfig.NetworkMode}} ports={{json .HostConfig.PortBindings}}')"
echo "HTTPS=$HTTPS_RESULT"
echo "HTTP=$HTTP_RESULT"
echo "URL=https://${HOSTNAME}"
echo "ATLAS_HTTPS=$ATLAS_RESULT"
echo "PANDORA_HTTPS=$PANDORA_RESULT"
echo "ARTIFEX_V1_HTTPS=$ARTIFEX_V1_RESULT"
echo "INDEX_SHA256=$(sha256sum "$RELEASE/index.html" | cut -d' ' -f1)"
echo "STATE_SHA256=$(sha256sum "$RELEASE/state.json" | cut -d' ' -f1)"
echo "BACKUP=$BACKUP"
"""


def connect(secret_file: Path) -> paramiko.SSHClient:
    secret = load_secret(secret_file, "crugger-prod")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        username=secret["user"],
        password=secret["pass"],
        timeout=8,
        banner_timeout=8,
        auth_timeout=8,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=sorted(TARGETS), default="operational")
    parser.add_argument("--apply", action="store_true", help="authorize VM100 deployment mutation")
    parser.add_argument("--secret-file", type=Path, default=DEFAULT_SECRET_FILE)
    args = parser.parse_args()
    if not args.apply:
        raise SystemExit("Refusing mutation without --apply")
    target = TARGETS[args.target]
    payload, archive_hash, index_hash, state_hash = dashboard_archive(target)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    remote_archive = f"/tmp/{target.container}-{stamp}.tar.gz"
    remote_script = f"/tmp/deploy-{target.container}-{stamp}.sh"
    client = connect(args.secret_file)
    try:
        with client.open_sftp() as sftp:
            with sftp.file(remote_archive, "wb") as handle:
                handle.write(payload)
            with sftp.file(remote_script, "w") as handle:
                handle.write(REMOTE_SCRIPT)
            sftp.chmod(remote_script, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        _, stdout, stderr = client.exec_command(
            " ".join(
                shlex.quote(value)
                for value in (
                    remote_script,
                    stamp,
                    index_hash,
                    state_hash,
                    target.stack,
                    target.container,
                    target.hostname,
                    target.marker,
                )
            ),
            timeout=600,
        )
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        if out:
            print(out, end="")
        if err:
            print(err, end="")
        print(f"ARCHIVE_SHA256={archive_hash}")
        if code:
            raise SystemExit(code)
        with client.open_sftp() as sftp, suppress(FileNotFoundError):
            sftp.remove(remote_script)
    finally:
        client.close()


if __name__ == "__main__":
    main()
