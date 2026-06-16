FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -e .

EXPOSE 8765 8780 8781

CMD ["python", "-m", "noirlycan_telemetry.cli", "dashboard", "--host", "0.0.0.0"]
