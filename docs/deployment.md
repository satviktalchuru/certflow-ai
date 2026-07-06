# Deployment

CertFlow AI is packaged as a single Go web service that serves both the API and static dashboard.

## Docker

Build:

```bash
docker build -t certflow-ai .
```

Run:

```bash
docker run --rm -p 8080:8080 certflow-ai
```

Open:

```text
http://127.0.0.1:8080
```

The container seeds demo data into `/tmp/certflow.db` before starting the web server.

## Render

The repository includes `render.yaml` for Render Blueprint deployment.

1. Create a new Blueprint on Render.
2. Connect the `satviktalchuru/certflow-ai` GitHub repository.
3. Render detects `render.yaml`.
4. Deploy the service.

Default environment:

```text
CERTFLOW_DB=/tmp/certflow.db
CERTFLOW_AI_PROVIDER=local
```

For OpenAI-backed report generation, add:

```text
CERTFLOW_AI_PROVIDER=openai
OPENAI_API_KEY=<secret>
OPENAI_MODEL=gpt-5.5
```

## Notes

The default deployment uses ephemeral SQLite storage and seeded demo data. For a longer-lived deployment, mount persistent storage or move the store implementation to Postgres.
