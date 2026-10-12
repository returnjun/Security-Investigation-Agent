FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir "httpx~=0.28.1" "python-dotenv~=1.2.2" "streamlit~=1.59.1"

COPY src/security_dashboard.py src/streamlit_app.py ./src/

CMD ["streamlit", "run", "src/streamlit_app.py", "--server.address", "0.0.0.0"]
