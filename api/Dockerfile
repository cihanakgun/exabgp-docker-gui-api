FROM python:3.12-slim
WORKDIR /app

RUN pip install flask bcrypt flasgger

# RapiDoc JS — Docker ADD ile build sırasında indirilir, image'a gömülür
ADD https://cdn.jsdelivr.net/npm/rapidoc@9.3.4/dist/rapidoc-min.js /app/static/rapidoc/rapidoc-min.js
RUN test $(stat -c%s /app/static/rapidoc/rapidoc-min.js) -gt 100000

COPY api.py .
COPY static/ ./static/

CMD ["python", "api.py"]
