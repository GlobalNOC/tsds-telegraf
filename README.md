# Community shared telemetry telegraf container

## Getting Started

### Prerequisites

`docker` and a suitable config file
**N.B. Disable SE Linux (or figure out how to get it to play well with Docker and local file mounts)**

### Install - Option 1

Clone this repo

```sh
git clone https://github.com/GlobalNOC/tsds-telegraf.git
```

Build the container

```sh
docker build -t tsds-telegraf .
```

### Install - Option 2

Pull the container from Docker Hub and tag the image so the following commands work.

```sh
docker pull ghcr.io/globalnoc/tsds-telegraf
docker tag  ghcr.io/globalnoc/tsds-telegraf tsds-telegraf
```

### Run

Place config file(s) in `conf.d` directory
e.g. Copy `conf/config.yaml` and `conf/telegraf_interface_example.conf` to `conf.d` and edit accordingly.

```sh
docker run -d --name tsds-telegraf -v $(pwd)/conf.d:/etc/telegraf/conf.d tsds-telegraf
```

### Troubleshoot

```sh
docker logs tsds-telegraf
```

## Test

Copy `conf/test.conf.example` to `conf.d/test.conf` and run

```sh
docker run --rm --name tsds-telegraf -v $(pwd)/conf.d:/etc/telegraf/conf.d tsds-telegraf
```

You should see telegraf logs and eventually a bunch of output related to cpu and memory.
`ctrl-c` to exit.
