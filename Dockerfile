FROM openjdk:8-jdk

RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

ENV JENKINS_HOME /var/jenkins_home
ENV JENKINS_SLAVE_AGENT_PORT 50000


ARG user=jenkins
ARG group=jenkins
ARG uid=1000
ARG gid=1000


# Jenkins is run with user `jenkins`, uid = 1000
# If you bind mount a volume from the host or a data container,
# ensure you use the same uid
RUN groupadd -g ${gid} ${group} \
	&& useradd -d "$JENKINS_HOME" -u ${uid} -g ${gid} -m -s /bin/bash ${user}


# Jenkins home directory is a volume, so configuration and build history 
# can be persisted and survive image upgrades
VOLUME /var/jenkins_home

ENV TINI_VERSION=0.14.0 \
	TINI_SHA=6c41ec7d33e857d4779f14d9c74924cab0c7973485d2972419a3b7c7620ff5fd

# Use tini as subreaper in Docker container to adopt zombie processes 
RUN curl -fsSL https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini-static-amd64 -o /bin/tini && chmod +x /bin/tini \
	&& echo "$TINI_SHA  /bin/tini" | sha256sum -c -


# jenkins version being bundled in this docker image
ARG JENKINS_VERSION=2.46.2
ENV JENKINS_VERSION ${JENKINS_VERSION:-2.46.2}

# jenkins.war checksum, download will be validated using it
ARG JENKINS_SHA=aa7f243a4c84d3d6cfb99a218950b8f7b926af7aa2570b0e1707279d464472c7

# Can be used to customize where jenkins.war get downloaded from
ARG JENKINS_URL=http://mirrors.jenkins.io/war-stable/${JENKINS_VERSION}/jenkins.war

RUN mkdir -p /usr/share/jenkins/ref

# could use ADD but this one does not check Last-Modified header neither does it allow to control checksum
# see https://github.com/docker/docker/issues/8331
RUN curl -fsSL ${JENKINS_URL} -o /usr/share/jenkins/jenkins.war \
	&& echo "${JENKINS_SHA}  /usr/share/jenkins/jenkins.war" | sha256sum -c -


ENV JENKINS_UC https://updates.jenkins.io
RUN chown -R ${user} "$JENKINS_HOME"

# for main web interface:
EXPOSE 8080

# will be used by attached slave agents:
EXPOSE 50000

COPY ./entrypoint.sh /
COPY ./entrypoint.d /entrypoint.d
COPY ./jenkins-support /usr/local/bin/jenkins-support
COPY ./job-dsl-scripts /usr/share/jenkins/ref/job-dsl-scripts

COPY plugins.txt /
RUN export JENKINS_UC="http://updates.jenkins-ci.org" JENKINS_PLUGINS="$(cat /plugins.txt)"\
	&& /entrypoint.d/10-download-plugins.sh

USER ${user}

ENTRYPOINT ["/entrypoint.sh"]

WORKDIR ${JENKINS_HOME}
