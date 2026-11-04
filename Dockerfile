FROM registry.access.redhat.com/ubi9/openjdk-21-runtime:1.24-3.1793323798@sha256:cfa544effa28c5c57197a4c9d460812e70efc0965e6f518e1c2e787ff3cb9335
WORKDIR /deployments
COPY target/quarkus-app/lib/ lib/
COPY target/quarkus-app/*.jar ./
COPY target/quarkus-app/app/ app/
COPY target/quarkus-app/quarkus/ quarkus/
COPY policy.yaml /opt/rbac/policy.yaml
EXPOSE 8082 8443
ENTRYPOINT ["java", "-jar", "quarkus-run.jar"]
