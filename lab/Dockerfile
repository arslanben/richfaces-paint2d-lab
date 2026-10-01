# syntax=docker/dockerfile:1
#
# RichFaces Paint2DResource CTF lab (CVE-2018-12533).
# Intentionally vulnerable. Lab use only.
#
# Build:  docker build -t paint2d-lab ./lab
# Run:    docker run --rm -p 8080:8080 paint2d-lab

# ---------------------------------------------------------------- build stage
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /build

# Build context is ./lab, so pom.xml and src/ sit at the context root.
COPY pom.xml ./
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -q clean package -DskipTests

# The JSF runtime loads application libraries and the EL engine from the same class-loading
# realm. Tomcat splits them: the EL engine lives in $CATALINA_HOME/lib (common loader) while
# WEB-INF/lib jars load in an isolated webapp loader, so EL-driven reflective lookups
# ("x".getClass().forName(...)) cannot see webapp-only classes.
#
# Staging spring-expression next to the EL engine reproduces that shared realm, which is what
# made the SpEL step of the original chain reachable.
RUN mkdir -p /shared-lib \
 && cp target/ROOT/WEB-INF/lib/*.jar /shared-lib/

# -------------------------------------------------------------- runtime stage
FROM tomcat:9.0-jre17-temurin

LABEL org.opencontainers.image.title="RichFaces Paint2DResource Lab (CVE-2018-12533)" \
      org.opencontainers.image.description="Intentionally vulnerable EL-injection lab. Lab use only." \
      org.opencontainers.image.licenses="MIT"

# A dedicated unprivileged account. uid 1003 matches the account id reported in the
# original disclosure so that `id` output looks familiar to participants.
RUN groupadd --gid 1003 labuser \
 && useradd --uid 1003 --gid 1003 --create-home --shell /bin/bash labuser

# Deployed as ETOPUPGUI.war, so the servlet context is /ETOPUPGUI. The PoC hardcodes that
# path, so it must stay exactly this.
COPY --from=build /build/target/ROOT.war /usr/local/tomcat/webapps/ETOPUPGUI.war
COPY --from=build /shared-lib/ /usr/local/tomcat/lib/

# Tomcat's own dirs must be writable by the service account.
RUN chown -R labuser:labuser /usr/local/tomcat

# No --add-opens here on purpose. Tomcat's own bin/catalina.sh already puts
# --add-opens=java.base/java.lang=ALL-UNNAMED (and several others) into JDK_JAVA_OPTIONS,
# which the JVM consumes automatically. Adding a duplicate would be cargo cult.
ENV CATALINA_OPTS="-Djava.awt.headless=true -Dlab.vulnerable=true"

ENV JAVA_TOOL_OPTIONS=""
USER labuser
WORKDIR /usr/local/tomcat

# 8080: HTTP  |  AJP is not exposed.
EXPOSE 8080

# Must include the /ETOPUPGUI context path or the healthcheck 404s forever.
HEALTHCHECK --interval=10s --timeout=3s --start-period=45s --retries=6 \
  CMD curl -fsS http://localhost:8080/ETOPUPGUI/lab/health || exit 1

ENTRYPOINT ["/usr/local/tomcat/bin/catalina.sh", "run"]
