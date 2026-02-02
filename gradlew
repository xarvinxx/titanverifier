#!/bin/sh

#
# Gradle start-up script
#

# Resolve APP_HOME
APP_HOME=$(cd "$(dirname "$0")" && pwd)
APP_NAME="Gradle"

# Use default Mac OS X options
JAVA_OPTS="-Dfile.encoding=UTF-8"

# Find java
if [ -n "$JAVA_HOME" ]; then
  JAVACMD="$JAVA_HOME/bin/java"
else
  JAVACMD=$(command -v java 2>/dev/null)
fi

if [ -z "$JAVACMD" ]; then
  echo "ERROR: JAVA_HOME is not set and no 'java' command could be found." >&2
  exit 1
fi

# Run Gradle Wrapper
exec "$JAVACMD" $JAVA_OPTS \
  -classpath "$APP_HOME/gradle/wrapper/gradle-wrapper.jar" \
  org.gradle.wrapper.GradleWrapperMain \
  "$@"
