FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/alembic.ini .
COPY backend/migrations ./migrations
COPY backend/app ./app
RUN useradd --system --uid 10001 app && chown -R app /app
USER app
EXPOSE 8000
# Migrate, then serve. Fine for a single instance; with several, run `alembic upgrade head` as a release step instead.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers"]
