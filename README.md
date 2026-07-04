# HONEYPOT API

FastAPI backend for the AI-driven cyber resilience prototype.

## Development setup

Use a project-local virtual environment for all installs:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

The development dependency set upgrades FastAPI and Pydantic to compatible v2-era versions and adds pytest/httpx for smoke coverage.

## Start/Stop the server

Use the single PowerShell switcher to manage the local server:

```powershell
.\scripts\ServerSwitch.ps1 toggle
```

Other supported actions:

```powershell
.\scripts\ServerSwitch.ps1 start
.\scripts\ServerSwitch.ps1 stop
.\scripts\ServerSwitch.ps1 status
```

The switcher uses the local `.venv` and writes runtime state into `.run/`.

## Documentation

- [Docs index](docs/README.md)
- [Architecture](docs/architecture.md)
- [Quickstart](docs/quickstart.md)
- [Deployment guide](docs/deployment_guide.md)
- [WhatsApp implementation plan](docs/whatsapp_implementation_plan.md)
- [Change log](docs/changes.md)
- [Development setup](docs/dev_setup.md)

## API overview

- `POST /honeypot`
- `POST /telemetry`
- `GET /incidents`
- `GET /playbooks`
- `POST /incidents/{incident_id}/action`
- `GET /incidents/{incident_id}/audit`

## Demo scenarios

Run the local demo harness and capture metrics with:

```powershell
.\.venv\Scripts\python.exe demo\run_scenarios.py
```

It writes aggregate MTTD/MTTR, detection rate, and false-positive rate to `demo/results/latest_metrics.json`.

## Deployment

The `Procfile` is still used for hosted deployment. For local work, prefer the switcher script above.
