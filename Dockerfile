FROM plugins/base:linux-amd64

LABEL maintainer="Igor Rendulic <rendulic.igor@gmail.com>" \
  org.label-schema.name="Gorush" \
  org.label-schema.vendor="Bo-Yi Wu" \
  org.label-schema.schema-version="1.0"

COPY dist/release/gorush /bin/

EXPOSE 8088 9000
HEALTHCHECK --start-period=2s --interval=10s --timeout=5s \
  CMD ["/bin/gorush", "--ping"]

ENTRYPOINT ["/bin/gorush"]
