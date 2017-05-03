#!/bin/bash

mkdir -p $JENKINS_HOME/plugins

# install plugins in $JENKINS_HOME/plugins
source /usr/local/bin/jenkins-support

export COPY_REFERENCE_FILE_LOG=/dev/stderr

# the download path for runtime plugins
find ${REF} -type f |
while read f; do
  copy_reference_file "$f"
done

# the download path for build-time plugins
find /usr/share/jenkins/ref/ -type f |
while read f; do
  copy_reference_file "$f"
done
