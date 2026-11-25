FROM registry.access.redhat.com/ubi9/openjdk-21-runtime:1.24-5@sha256:80663340693d8863d518116b9382f758364c5394a41cf549eef6240ebd9e67af
WORKDIR /deployments
COPY target/quarkus-app/lib/ lib/
COPY target/quarkus-app/*.jar ./
COPY target/quarkus-app/app/ app/
COPY target/quarkus-app/quarkus/ quarkus/
COPY policy.yaml /opt/rbac/policy.yaml
EXPOSE 8082 8443
ENTRYPOINT ["java", "-jar", "quarkus-run.jar"]
