FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -e ".[full]"

# Default: backend API. Override CMD for storage/analysis/dashboard legacy.
EXPOSE 8765 8780 8781

CMD ["python", "-m", "noirlycan_backend.cli", "api", "--host", "0.0.0.0", "--port", "8765"]
