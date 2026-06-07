# Prompts Figma MCP — Noirlycan

À exécuter **après** connexion Figma MCP (point vert + outils visibles dans Cursor → Settings → MCP).

## 1. Architecture (FigJam) — `generate_diagram`

```
Create a FigJam architecture diagram for the Noirlycan thesis telemetry project.

Use generate_diagram with this Mermaid flowchart:

flowchart LR
  subgraph inputs [Inputs]
    fileDrop[File drop watcher]
    sysmon[Sysmon EVTX]
    frida[Frida injection hooks]
  end
  subgraph runtime [Python runtime]
    cli[cli.py run]
    queue[analysis_queue]
    corr[correlation.py]
    store[log_store JSONL]
  end
  subgraph output [Output]
    api[Flask REST API]
    dash[Web dashboard]
  end
  fileDrop -->|"new .exe"| cli
  sysmon --> cli
  frida --> cli
  cli --> queue
  queue -->|"spawn under Frida"| frida
  cli --> corr
  corr --> store
  store --> api
  api --> dash
```

## 2. Dashboard UI — `generate_figma_design`

Démarrer le dashboard local d'abord :

```powershell
pip install -e .
python -m noirlycan_telemetry dashboard --host 127.0.0.1 --port 5050
```

Puis :

```
Start the Noirlycan dashboard at http://127.0.0.1:5050 and capture the full Overview tab UI into a new Figma Design file named "Noirlycan — Dashboard".

Then capture these additional tab views in the same file as separate frames:
- Findings (with Injection target column)
- File drops (with Watch folders and Analyze APIs toggles)
- Finding detail modal (open by clicking a critical finding row)

Use the dark theme from docs/design/design-tokens.json. Match Space Grotesk headings and IBM Plex Mono for code paths.
```

## 3. Tokens de référence

Voir `docs/design/design-tokens.json` et `docs/design/noirlycan-figma-blueprint.md`.
