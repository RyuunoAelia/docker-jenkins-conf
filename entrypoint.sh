#!/bin/bash

: "${JENKINS_HOME:="/var/jenkins_home"}"

if [ ! -z "$ENTRYPOINT_DEBUG" ]; then
 set -x
 set -e
fi

export JENKINS_INIT_DIR=${JENKINS_HOME}/init.groovy.d
mkdir -p ${JENKINS_INIT_DIR}

echo "cleanning up additionnal jar data"
rm -rf "${JENKINS_HOME}/additionnal/classes/"
mkdir -p "${JENKINS_HOME}/additionnal/classes/"

# this variable as its name does not explicit is the temporary folder where the plugins will be downloaded
export REF="/tmp/ref-absurdly-long"
mkdir -p ${REF}/plugins

mkdir -p $JENKINS_HOME/plugins

find /entrypoint.d -type f | sort -n |
while read f; do
  case "$f" in
    *.sh) echo "$0: running \"$f\""; . "$f" ;;
    *.groovy) echo "$0: (delayed) copying \"$f\" to ${JENKINS_INIT_DIR}"; cp "$f" "${JENKINS_INIT_DIR}" ;;
    *.jpi) echo "$0: copying static plugin \"$f\" to ${REF}/plugins/"; cp "$f" "${REF}"/plugins/ ;;
    *) echo "$0: ignoring $f" ;;
  esac
  echo
done

# if `docker run` first argument start with `--` the user is passing jenkins launcher arguments
if [[ $# -lt 1 ]] || [[ "$1" == "--"* ]]; then

  # read JAVA_OPTS and JENKINS_OPTS into arrays to avoid need for eval (and associated vulnerabilities)
  java_opts_array=()
  while IFS= read -r -d '' item; do
    java_opts_array+=( "$item" )
  done < <([[ $JAVA_OPTS ]] && xargs printf '%s\0' <<<"$JAVA_OPTS")

  jenkins_opts_array=( )
  while IFS= read -r -d '' item; do
    jenkins_opts_array+=( "$item" )
  done < <([[ $JENKINS_OPTS ]] && xargs printf '%s\0' <<<"$JENKINS_OPTS")

  exec java "${java_opts_array[@]}" -jar /usr/share/jenkins/jenkins.war "${jenkins_opts_array[@]}" "$@"
fi

# As argument is not jenkins, assume user want to run his own process, for example a `bash` shell to explore this image
exec "$@"
