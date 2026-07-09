FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Serve with the waitress production WSGI server (not the Werkzeug dev server)
# so the app is safe to expose behind a reverse proxy. wsgi.py runs the same
# startup initialization as `python app.py`.
CMD ["waitress-serve", "--host=0.0.0.0", "--port=5030", "--threads=8", "wsgi:app"]

