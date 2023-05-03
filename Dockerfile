FROM python:3.8-slim
RUN /usr/local/bin/python -m pip install --upgrade pip

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY src/wsgi.py /app/
COPY src/api /app/api

ENTRYPOINT ["gunicorn", "--chdir", "/app", "wsgi:app"]
CMD ["-w", "4", "-b", "0.0.0.0:8000"]