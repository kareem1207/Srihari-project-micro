FROM python:3.12-slim
WORKDIR /app
COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt
COPY backend ./backend
COPY agent ./agent
CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]
