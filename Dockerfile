# VulnNotes Python - deliberately vulnerable training image. Do NOT expose publicly.
FROM python:3.11-slim

# (command-injection module uses getent, already in the base image - no apt needed)
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ /app/

# FLASK_DEBUG left on (A05) so the Werkzeug console is reachable
ENV FLASK_DEBUG=1
# A06 Vulnerable & Outdated Components: bundle an OUTDATED busybox (known CVEs) for SBOM practice.
COPY --from=busybox:1.28.4 /bin/busybox /usr/local/bin/busybox-legacy

EXPOSE 5000
CMD ["python", "app.py"]
