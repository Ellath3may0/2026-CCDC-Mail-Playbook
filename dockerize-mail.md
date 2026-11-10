# Dockerize Mail

## Install Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sh ./get-docker.sh
rm get-docker.sh
```

## Move mail configuration files and other things

```bash
mkdir docker && cd docker

cp -r /etc/postfix        postetc
cp -r /etc/dovecot        doveetc
cp -r /var/spool/postfix  postspool
cp -r /var/mail           mail
cp -r /var/lib/dovecot    dovelib
cp    /etc/passwd         passwd
cp    /etc/group          group
cp    /etc/shadow         shadow
cp    /etc/gshadow        gshadow

# Per user
mkdir home/mailuser/
cp -r /home/mailuser/Maildir home/mailuser/
```

## supervisord.conf

```ini
[supervisord]
nodaemon=true
user=root

[program:dovecot]
command=/usr/sbin/dovecot -F
autorestart=true

[program:postfix]
command=/usr/sbin/postfix start-fg
autorestart=true
supervisord.conf generated
```

## Dockerfile

```Dockerfile
FROM fedora:42
WORKDIR .

COPY postetc          /etc/postfix
COPY doveetc          /etc/dovecot
COPY postspool        /var/spool/postfix
COPY mail             /var/spool/mail
COPY dovelib          /var/lib/dovecot
COPY passwd           /etc/passwd
COPY group            /etc/group
COPY shadow           /etc/shadow
COPY gshadow          /etc/gshadow

COPY home /home

RUN dnf install -y postfix dovecot supervisor
RUN dnf clean all

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]
```

## Build

```bash
docker build --network=host -t mail .
```

## docker-compose.yaml

```yaml
services:
mail:
  image: mail:latest
    pull_policy: never
    network_mode: host
```
