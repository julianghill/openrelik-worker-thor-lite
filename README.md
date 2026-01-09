# OpenRelik worker for THOR Lite

This worker uses [THOR Lite](https://www.nextron-systems.com/thor-lite/) from [Nextron Systems](https://nextron-systems.com/) to scan files and directories for malicious content.

Highlights:
- Extracts ZIP inputs (e.g., Velociraptor collections) before scanning.
- Emits live status messages in the UI while running.
- Provides task options for signature updates and JSON format selection.

![OpenRelik THOR Lite Worker Artifacts](img/openrelik-worker-thor-lite-artifacts.png?raw=true)

## Prerequisites

You need a valid THOR Lite license to use this worker. You can get a free license for non-commercial use from the [Nextron Systems website](https://www.nextron-systems.com/thor-lite/#get-thor).

If you have a `.lic` file, base64-encode it for `THOR_LICENSE`:

```bash
base64 -w0 /path/to/thor.lic
```

## Installation Instructions

> **Warning:** OpenRelik is a fresh project and things are changing rapidly. Thus this worker is considered _experimental_. Use with care!

> Note: Last tested with OpenRelik `2024.12.12`. Use `2024.12.12` in your `config.env` file for all versions in the block of the OpenRelik core system (and `2024.11.27` in the worker block).

Add this to your `docker-compose.yml` file:
```yaml
  openrelik-worker-thor-lite:
    container_name: openrelik-worker-thor-lite
    image: ghcr.io/nextronsystems/openrelik-worker-thor-lite:latest
    restart: always
    environment:
      - REDIS_URL=redis://openrelik-redis:6379
      - OPENRELIK_PYDEBUG=0
      - OPENRELIK_PYDEBUG_PORT=5678
      - THOR_LICENSE=<your license key, base64 encoded>
    volumes:
      - ./data:/usr/share/openrelik/data
    command: "celery --app=src.app worker --task-events --concurrency=2 --loglevel=INFO -Q openrelik-worker-thor-lite"
```

## JSON Output and Timesketch

THOR Lite 10.8 outputs `log_version: v3.0.0` for JSON logs, even with `--jsonv2`.
Currently the Timesketch converter only supports older log versions. Future ideas:
- Update the converter to support `v3.0.0`
- Add a conversion step to downgrade the JSON schema
- Pin THOR Lite to 10.7.x when legacy JSON (v1 or v2) is required.
- Add a user-supplied YARA rules workflow (mount custom folder or per-task upload).
- Add an option to scan mounted disk images.

Added to the Soon^tm :)

### HTML Report Preview

> Note: Currently (as of 2025-01-24), you need to add `openrelik:worker:thor-lite:html_report` to `[ui] allowed_data_types_preview` in your `settings.toml` to get embedded previews of the HTML reports that the worker generates.

![OpenRelik THOR Lite Worker HTML Report](img/openrelik-worker-thor-lite-html-report.png?raw=true)
