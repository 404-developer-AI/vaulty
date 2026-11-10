#!/usr/bin/env bash
# Builds a Vaulty release tarball for linux-x64:
#   vaulty-<version>/bin/        self-contained services, CLI, migrations, Recover CLI and helper scripts
#   vaulty-<version>/templates/  systemd, Caddy, PostgreSQL and report templates
#   vaulty-<version>/compose/    the Temporal/Valkey Compose file and images.json with pinned digests
#   vaulty-<version>/release.json, SBOM (when available), LICENSE
# and writes SHA256SUMS next to it. Used by the release workflow and by the installer test job.
#
#   deploy/ci/build-release.sh <version> <output directory> [--format-change]
set -euo pipefail

VERSION="${1:?usage: build-release.sh <version> <output directory> [--format-change]}"
OUT="${2:?usage: build-release.sh <version> <output directory> [--format-change]}"
FORMAT_CHANGE=false
[ "${3:-}" = "--format-change" ] && FORMAT_CHANGE=true
case "$VERSION" in
  *[!A-Za-z0-9._-]*|"") echo "invalid version '$VERSION'" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
NAME="vaulty-${VERSION}"
DIR="${STAGE}/${NAME}"
mkdir -p "$DIR/bin" "$DIR/templates" "$DIR/compose" "$OUT"

# Every executable shares one self-contained runtime in bin/ (identical framework files, one copy). Not trimmed: Blazor
# and the reflection-based serializers are not trim-safe.
for project in Vaulty.Web Vaulty.Api Vaulty.Workers Vaulty.Migrate Vaulty.Cli Vaulty.Recover; do
  dotnet publish "$ROOT/src/$project/$project.csproj" -c Release -r linux-x64 --self-contained true \
    -p:PublishTrimmed=false -p:Version="${VERSION%%-*}" -p:InformationalVersion="$VERSION" \
    -o "$DIR/bin" --nologo -v quiet
done
install -m 0755 "$ROOT/deploy/install/bin/vaulty-pgbackrest" "$DIR/bin/vaulty-pgbackrest"

cp -r "$ROOT/deploy/install/systemd" "$ROOT/deploy/install/caddy" "$ROOT/deploy/install/postgres" "$DIR/templates/"
cp "$ROOT/deploy/install/report.template.txt" "$ROOT/deploy/install/answers.example.yaml" "$DIR/templates/"
cp "$ROOT/deploy/install/compose/temporal.compose.yml" "$DIR/compose/"
cp "$ROOT/LICENSE" "$DIR/"

# Image digests are resolved once, here, and pinned in the release: an update never follows a moving tag.
images_json="{"
first=true
while read -r name image tag; do
  [ -z "$name" ] && continue
  case "$name" in \#*) continue ;; esac
  digest=$(docker buildx imagetools inspect "${image}:${tag}" --format '{{json .Manifest.Digest}}' | tr -d '"')
  case "$digest" in sha256:*) ;; *) echo "could not resolve ${image}:${tag}" >&2; exit 1 ;; esac
  $first || images_json+=","
  first=false
  images_json+="\"${name}\":{\"image\":\"${image}\",\"version\":\"${tag}\",\"digest\":\"${digest}\"}"
done < "$ROOT/deploy/install/compose/images.versions"
images_json+="}"
printf '%s\n' "$images_json" > "$DIR/compose/images.json"

commit=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
printf '{"version":"%s","commit":"%s","format_change":%s}\n' "$VERSION" "$commit" "$FORMAT_CHANGE" > "$DIR/release.json"
if command -v syft >/dev/null; then
  syft "dir:$DIR" -o cyclonedx-json="$DIR/sbom.cdx.json" -q
fi

tar -C "$STAGE" --owner=0 --group=0 --numeric-owner --sort=name -czf "$OUT/${NAME}-linux-x64.tar.gz" "$NAME"
(cd "$OUT" && sha256sum "${NAME}-linux-x64.tar.gz" >> SHA256SUMS)
du -sh "$DIR/bin" | awk -v v="$VERSION" '{ print "release " v ": bin/ is " $1 }'
