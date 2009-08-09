#!/bin/sh

set -e

VERSION="0.1"

java -jar /usr/share/java/nagios-wmi-plugin-$VERSION.jar $@
