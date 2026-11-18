FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY agent.py .
COPY dummy_target ./dummy_target

RUN useradd --create-home sentinel && mkdir /out && chown sentinel /out
USER sentinel

# `docker run ... codesentinel` scans the bundled demo by default.
ENTRYPOINT ["python", "agent.py"]
CMD ["dummy_target"]