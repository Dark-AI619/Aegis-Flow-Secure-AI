FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home aegis && mkdir -p /app/data && chown -R aegis:aegis /app
USER aegis
ENV AEGIS_DB_PATH=/app/data/aegisflow.db CREWAI_TELEMETRY_DISABLED=true OTEL_SDK_DISABLED=true
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
