FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY agent.py app.py test_agent.py ./
COPY dummy_target ./dummy_target

RUN useradd --create-home sentinel && mkdir /out && chown sentinel /out
USER sentinel

EXPOSE 8000

# Default: CLI scan of the bundled demo.
ENTRYPOINT ["python", "agent.py"]
CMD ["dummy_target"]