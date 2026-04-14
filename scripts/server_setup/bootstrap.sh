#!/usr/bin/env bash

# once added use ansible to scp the binary and service file and have the host do a daemon reload
# also need to add the current ip of the server(domain) to a yaml file that will be used once compiled

# assumes ubuntu for now
if ! command -v docker >/dev/null 2>&1; then
    # will update to use package manager later??
    curl -fsSL "https://get.docker.com" -o get-docker.sh
    sh ./get-docker.sh
    rm get-docker.sh
fi

# update to be idomatic
git clone https://cjn4825/Binmon.git
cd "Binmon" || exit
docker build -t binmon
# not sure if the data stays after the container stops
docker run --rm -v "$(pwd):/build" exec cd /build && make
echo "Add hosts that you want to have the service on to the inventory file in the ansible folder"
