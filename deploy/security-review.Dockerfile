FROM python:3.12.16-alpine3.24@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7 AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /build/requirements.txt
COPY installer-requirements.txt /build/installer-requirements.txt
COPY dist/ /build/dist/
RUN python -m pip install --no-deps --require-hashes --only-binary=:all: -r /build/installer-requirements.txt \
    && python -m venv --without-pip /opt/service \
    && python -m pip --python /opt/service install --require-hashes --only-binary=:all: -r /build/requirements.txt \
    && python -m pip --python /opt/service install --no-deps --no-index /build/dist/*.whl \
    && python -m pip --python /opt/service check

FROM python:3.12.16-alpine3.24@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7
# The pinned base still ships krb5-libs 1.22.2-r1 (HIGH, fixed in 1.22.3-r0).
# Upgrade only that package to the exact fixed release; drop this once a
# rebuilt base digest includes it (ADR-0014).
RUN apk add --no-cache 'krb5-libs=1.22.3-r0' \
    && python -m pip uninstall --yes pip \
    && python -c "import shutil,sysconfig; shutil.rmtree(sysconfig.get_path('stdlib') + '/ensurepip')"
ENV PATH=/opt/service/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /opt/service /opt/service
COPY manifest.json /app/build-manifest.json
WORKDIR /app
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["python", "-m", "sova_security.interfaces.review_server"]
