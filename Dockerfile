FROM python:3.12-slim AS build
WORKDIR /build
COPY . .
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 sandworm && mkdir /data && chown 10001:10001 /data
COPY --from=build /build/dist/*.whl /tmp/wheels/
RUN pip install --no-cache-dir /tmp/wheels/*.whl && pip install --no-cache-dir 'sandworm[web,secure,emulate,ml]==0.2.0'
USER sandworm
WORKDIR /data
ENV SANDWORM_WORK_DIR=/data
EXPOSE 8000
ENTRYPOINT ["sandworm"]
CMD ["serve", "--host", "0.0.0.0"]
