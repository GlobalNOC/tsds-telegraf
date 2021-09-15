#!/bin/bash
set -xe

# set PLATFORM "" to upload to docker.io
PLATFORM="ghcr.io/"
USERNAME="globalnoc"
IMAGE="tsds-telegraf"

# ensure we're up to date
git pull
# bump version
version=`cat VERSION`
echo "version: $version"
# run build
docker build -t ${PLATFORM}$USERNAME/$IMAGE:latest .
# tag it
git commit -m "version $version"
git tag -a "$version" -m "version $version"
git push
git push --tags
docker tag ${PLATFORM}$USERNAME/$IMAGE:latest ${PLATFORM}$USERNAME/$IMAGE:$version
# push it
docker push ${PLATFORM}$USERNAME/$IMAGE:latest
docker push ${PLATFORM}$USERNAME/$IMAGE:$version
