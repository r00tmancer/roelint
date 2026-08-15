FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system roelint && useradd --system --gid roelint --create-home roelint
COPY --from=build /wheels /wheels
RUN python -m pip install /wheels/*.whl && rm -rf /wheels

USER roelint
WORKDIR /workspace
ENTRYPOINT ["roelint"]
CMD ["--help"]
