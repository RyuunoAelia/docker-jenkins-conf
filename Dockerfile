FROM openjdk:8-jdk

RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

# jenkins version being bundled in this docker image
ARG JENKINS_VERSION=2.46.2

ENV \
  JENKINS_HOME=/var/jenkins_home \
  JENKINS_SLAVE_AGENT_PORT=50000 \
  TINI_VERSION=0.14.0 \
  TINI_SHA=6c41ec7d33e857d4779f14d9c74924cab0c7973485d2972419a3b7c7620ff5fd \
  JENKINS_VERSION=${JENKINS_VERSION} \
  JENKINS_UC=https://updates.jenkins.io \
  JENKINS_GITHUB_USER= \
  JENKINS_GITHUB_ORG= \
  JENKINS_CONFIG_REPO= \
  JENKINS_CONFIG_REPO_BRANCH= \
  JENKINS_CONFIG_CHECKOUT_USERNAME= \
  JENKINS_CONFIG_CHECKOUT_PASSWORD= \
  JENKINS_ADMIN_GROUPNAME=admins \
  JENKINS_HIPCHAT_TOKEN= \
  JENKINS_GITHUB_TOKEN= \
  JENKINS_GITHUB_SSH_PRIVATE_KEY= \
  JENKINS_GITHUB_PIPELINE_TOKEN= \
  JENKINS_SWARM_USERNAME=username \
  JENKINS_LDAP_SERVER=ldap.example.com \
  JENKINS_LDAP_ROOT_DN=dc=example,dc=com \
  JENKINS_LDAP_USER_SEARCH_BASE=cn=Users \
  JENKINS_LDAP_USER_SEARCH_FILTER= \
  JENKINS_LDAP_GROUP_SEARCH_BASE=cn=Groups \
  JENKINS_LDAP_GROUP_SEARCH_FILTER= \
  JENKINS_LDAP_MANAGER_USER_DN=cn=user,dc=example,dc=com \
  JENKINS_LDAP_MANAGER_USER_PASSWORD=example \
  JENKINS_ROOT_URL=http://jenkins.example.com \
  JENKINS_TIMEZONE=Europe/Zurich \
  JENKINS_MAIL_ADDRESS=jenkins@example.com \
  JENKINS_MAIL_USER=example \
  JENKINS_MAIL_PASSWORD=example \
  JENKINS_MAIL_SMTP_HOST=smtp.example.com \
  JENKINS_MAIL_SMTP_SSL=false \
  JENKINS_MAIL_SMTP_PORT=25 \
  JENKINS_PIPELINE_LIB_NAME=examplelib \
  JENKINS_PIPELINE_LIB_REPO=http://git.example.com/myrepo \
  JENKINS_PLUGINS= \
  ENTRYPOINT_DEBUG=


# Jenkins is run with user `jenkins`, uid = 1000
# If you bind mount a volume from the host or a data container,
# ensure you use the same uid
RUN groupadd -g 1000 jenkins \
	&& useradd -d "$JENKINS_HOME" -u 1000 -g 1000 -m -s /bin/bash jenkins


# Jenkins home directory is a volume, so configuration and build history 
# can be persisted and survive image upgrades
VOLUME /var/jenkins_home


# Use tini as subreaper in Docker container to adopt zombie processes 
RUN curl -fsSL https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini-static-amd64 -o /bin/tini && chmod +x /bin/tini \
	&& echo "$TINI_SHA  /bin/tini" | sha256sum -c -


# jenkins.war checksum, download will be validated using it
ARG JENKINS_SHA=aa7f243a4c84d3d6cfb99a218950b8f7b926af7aa2570b0e1707279d464472c7

# Can be used to customize where jenkins.war get downloaded from
ARG JENKINS_URL=http://mirrors.jenkins.io/war-stable/${JENKINS_VERSION}/jenkins.war

RUN mkdir -p /usr/share/jenkins/ref

# could use ADD but this one does not check Last-Modified header neither does it allow to control checksum
# see https://github.com/docker/docker/issues/8331
RUN curl -fsSL ${JENKINS_URL} -o /usr/share/jenkins/jenkins.war \
	&& echo "${JENKINS_SHA}  /usr/share/jenkins/jenkins.war" | sha256sum -c -


RUN chown -R jenkins "$JENKINS_HOME"

# for main web interface:
EXPOSE 8080

# will be used by attached slave agents:
EXPOSE 50000

COPY ./entrypoint.sh /
COPY ./entrypoint.d /entrypoint.d
COPY ./jenkins-support /usr/local/bin/jenkins-support
COPY ./resources /usr/share/jenkins/resources

COPY plugins.txt /usr/share/jenkins/default_plugins.txt
RUN export JENKINS_UC="http://updates.jenkins-ci.org" JENKINS_PLUGINS="$(cat /usr/share/jenkins/default_plugins.txt)"\
	&& /entrypoint.d/10-download-plugins.sh


USER jenkins

ENTRYPOINT ["/entrypoint.sh"]
WORKDIR ${JENKINS_HOME}
