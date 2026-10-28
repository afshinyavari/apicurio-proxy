FROM registry.access.redhat.com/ubi9/openjdk-21-runtime:1.24-3.1792711374@sha256:b924b5d15de9585902c58eea76d0c1d6120921844cbc9e79683103e01b0200fd
WORKDIR /deployments
COPY target/quarkus-app/lib/ lib/
COPY target/quarkus-app/*.jar ./
COPY target/quarkus-app/app/ app/
COPY target/quarkus-app/quarkus/ quarkus/
COPY policy.yaml /opt/rbac/policy.yaml
EXPOSE 8082 8443
ENTRYPOINT ["java", "-jar", "quarkus-run.jar"]
