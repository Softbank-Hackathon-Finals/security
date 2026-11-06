FROM python:3.12.16-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /build/requirements.txt
COPY installer-requirements.txt /build/installer-requirements.txt
COPY dist/ /build/dist/
RUN python -m pip install --no-deps --require-hashes --only-binary=:all: -r /build/installer-requirements.txt \
    && python -m venv --without-pip /opt/service \
    && python -m pip --python /opt/service install --require-hashes --only-binary=:all: -r /build/requirements.txt \
    && python -m pip --python /opt/service install --no-deps --no-index /build/dist/*.whl \
    && python -m pip --python /opt/service check

FROM python:3.12.16-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
RUN python -m pip uninstall --yes pip \
    && python -c "import shutil,sysconfig; shutil.rmtree(sysconfig.get_path('stdlib') + '/ensurepip')"
ENV PATH=/opt/service/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /opt/service /opt/service
COPY manifest.json /app/build-manifest.json
WORKDIR /app
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["python", "-m", "sova_security.interfaces.review_server"]
