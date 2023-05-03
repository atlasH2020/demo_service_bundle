FROM python:3.8-slim
RUN /usr/local/bin/python -m pip install --upgrade pip

WORKDIR /demo_service_bundle
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY src/wsgi.py /demo_service_bundle/
COPY src/api /demo_service_bundle/api

ENTRYPOINT ["gunicorn", "--chdir", "/demo_service_bundle", "wsgi:app"]
CMD ["-w", "2", "-b", "0.0.0.0:8000"]