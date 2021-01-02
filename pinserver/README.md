## To generate a new key

`python -m venv -p python3 venv`

`. venv/bin/activate`

`pip install --require-hashes -r pinserver/requirements.txt`

`python -m pinserver.generateserverkey`

## Build the docker image

docker build -f pinserver/Dockerfile pinserver/ -t dockerized_pinserver

## Prepare the directory for all the pins

`mkdir pinsdir`

## Run the docker image (requires the previous steps)

`docker run -v $PWD/server_private_key.key:/server_private_key.key -v $PWD/pinsdir:/pins -p 8096:8096 dockerized_pinserver`
