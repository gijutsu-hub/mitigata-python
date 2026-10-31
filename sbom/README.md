# SBOM scan (part of the challenge)

This image bundles some **outdated components**. Generate a Software Bill of Materials and scan
it for known CVEs — then fix them yourself. No host installs (Syft/Grype/Trivy via Docker).

```bash
cd sbom
./sbom.sh image <image:tag>   # SBOM (CycloneDX) + Grype CVE scan of a built image
./sbom.sh fs    .             # scan source manifests (pom.xml / requirements.txt)
```
Finding and remediating the outdated dependencies is part of the exercise — no answer key here.
