#!/usr/bin/env bash
# =====================================================================
#  sbom.sh - generate a Software Bill of Materials and scan it for CVEs.
#  No host installs needed: Syft, Grype and Trivy run via Docker.
#
#  Usage:
#    ./sbom.sh image  <image:tag>   # SBOM (CycloneDX) + Grype CVE scan of a built image
#    ./sbom.sh fs     <path>        # scan source manifests (pom.xml / requirements.txt)
#    ./sbom.sh all                  # build all 3 lab images, SBOM + scan each
# =====================================================================
set -u
SOCK="/var/run/docker.sock"
OUT="$(cd "$(dirname "$0")" && pwd)/out"; mkdir -p "$OUT"

sbom_image() {
  local img="$1" name="${1//[:\/]/_}"
  echo "### SBOM (CycloneDX) -> $OUT/${name}.cdx.json"
  docker run --rm -v "$SOCK:$SOCK" anchore/syft:latest "$img" -o cyclonedx-json > "$OUT/${name}.cdx.json"
  echo "### Components (table)"
  docker run --rm -v "$SOCK:$SOCK" anchore/syft:latest "$img" -o table
  echo "### Vulnerabilities (Grype)"
  docker run --rm -v "$SOCK:$SOCK" anchore/grype:latest "$img" --scope all-layers
}

scan_fs() {
  local path="$1"
  echo "### Trivy filesystem scan -> $path (manifests: pom.xml, requirements.txt, OS)"
  docker run --rm -v "$(cd "$(dirname "$0")/.." && pwd):/src" aquasec/trivy:latest \
    fs --scanners vuln --severity HIGH,CRITICAL "/src/$path"
}

case "${1:-help}" in
  image) sbom_image "${2:?image:tag required}" ;;
  fs)    scan_fs   "${2:?path required}" ;;
  all)
    for pair in "php-app:mitigata-php" "java-app:mitigata-java" "python-app:mitigata-python"; do
      dir=${pair%%:*}; img=${pair##*:}
      echo "========== building $img =========="
      docker build -t "$img" "../$dir" && sbom_image "$img"
    done ;;
  *) grep '^#' "$0" | sed 's/^# \{0,1\}//' ;;
esac
