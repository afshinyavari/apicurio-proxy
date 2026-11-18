FROM registry.access.redhat.com/ubi9/openjdk-21-runtime:1.24-3.1794341129@sha256:9a074c2ff90be60b12521ffd5e531acafd25fe36f1c177180cbe1176dfb36c84
WORKDIR /deployments
COPY target/quarkus-app/lib/ lib/
COPY target/quarkus-app/*.jar ./
COPY target/quarkus-app/app/ app/
COPY target/quarkus-app/quarkus/ quarkus/
COPY policy.yaml /opt/rbac/policy.yaml
EXPOSE 8082 8443
ENTRYPOINT ["java", "-jar", "quarkus-run.jar"]
