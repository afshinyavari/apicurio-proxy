FROM registry.access.redhat.com/ubi9/openjdk-21-runtime:1.24-3.1791779558@sha256:856ee6542b8fdf09a065fd5439309fc3f3c821fb8efac48aa6191c93635dd907
WORKDIR /deployments
COPY target/quarkus-app/lib/ lib/
COPY target/quarkus-app/*.jar ./
COPY target/quarkus-app/app/ app/
COPY target/quarkus-app/quarkus/ quarkus/
COPY policy.yaml /opt/rbac/policy.yaml
EXPOSE 8082 8443
ENTRYPOINT ["java", "-jar", "quarkus-run.jar"]
