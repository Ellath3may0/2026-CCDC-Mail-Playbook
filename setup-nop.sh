#!/usr/bin/env bash
# nopCommerce 5.00.x on Rocky Linux 9, behind nginx (HTTPS, self-signed, HTTP->HTTPS redirect)
# Re-runnable: wipes the app dir and reinitialises the SQL Server database each run.
set -euo pipefail

# ---- config -----------------------------------------------------------------
NOP_VERSION="${NOP_VERSION:-5.00.1}"
NOP_DIR="/var/www/nopCommerce"
NOP_USER="nop"
NOP_PORT=5000
DOTNET_CHANNEL="10.0"

DB_HOST="172.20.240.120"
DB_NAME="ShellSurgeDB"
DB_USER="nopuser"
DB_PASS='Pa$$w0rd'

CERT_DIR="/etc/pki/nginx"
CERT_CN="$(hostname -f 2>/dev/null || hostname)"
# -----------------------------------------------------------------------------

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
log() { printf '\n[+] %s\n' "$*"; }

log "Base packages"
dnf -y install epel-release >/dev/null 2>&1 || true
dnf -y install nginx unzip curl openssl policycoreutils-python-utils firewalld

log ".NET ASP.NET Core runtime ${DOTNET_CHANNEL}"
if ! dnf -y install aspnetcore-runtime-10.0 2>/dev/null; then
  echo "Not in repos, using dotnet-install.sh"
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  bash /tmp/dotnet-install.sh --runtime aspnetcore --channel "$DOTNET_CHANNEL" --install-dir /usr/share/dotnet
  ln -sf /usr/share/dotnet/dotnet /usr/bin/dotnet
fi
dotnet --list-runtimes

log "sqlcmd (mssql-tools18)"
if ! command -v sqlcmd >/dev/null && [[ ! -x /opt/mssql-tools18/bin/sqlcmd ]]; then
  curl -fsSL https://packages.microsoft.com/config/rhel/9/prod.repo -o /etc/yum.repos.d/mssql-release.repo
  ACCEPT_EULA=Y dnf -y install mssql-tools18 unixODBC-devel
fi
SQLCMD="$(command -v sqlcmd || echo /opt/mssql-tools18/bin/sqlcmd)"

log "Checking SQL Server reachability"
timeout 5 bash -c "</dev/tcp/${DB_HOST}/1433" || { echo "Cannot reach ${DB_HOST}:1433"; exit 1; }

log "Stopping any existing service"
systemctl stop nopCommerce 2>/dev/null || true

log "Reinitialising database ${DB_NAME}"
export SQLCMDPASSWORD="$DB_PASS"
if ! "$SQLCMD" -S "$DB_HOST" -U "$DB_USER" -C -b -Q "
IF DB_ID(N'${DB_NAME}') IS NOT NULL BEGIN
  ALTER DATABASE [${DB_NAME}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
  DROP DATABASE [${DB_NAME}];
END;
CREATE DATABASE [${DB_NAME}];"; then
  echo "Drop/create denied, wiping all tables inside the existing DB instead"
  "$SQLCMD" -S "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -C -b -Q "
DECLARE @s nvarchar(max)=N'';
SELECT @s+=N'ALTER TABLE '+QUOTENAME(SCHEMA_NAME(schema_id))+N'.'+QUOTENAME(OBJECT_NAME(parent_object_id))+N' DROP CONSTRAINT '+QUOTENAME(name)+N';' FROM sys.foreign_keys;
SELECT @s+=N'DROP TABLE '+QUOTENAME(SCHEMA_NAME(schema_id))+N'.'+QUOTENAME(name)+N';' FROM sys.tables;
SELECT @s+=N'DROP VIEW '+QUOTENAME(SCHEMA_NAME(schema_id))+N'.'+QUOTENAME(name)+N';' FROM sys.views;
SELECT @s+=N'DROP PROCEDURE '+QUOTENAME(SCHEMA_NAME(schema_id))+N'.'+QUOTENAME(name)+N';' FROM sys.procedures;
EXEC(@s);"
fi
unset SQLCMDPASSWORD

log "Deploying nopCommerce ${NOP_VERSION}"
id "$NOP_USER" &>/dev/null || useradd --system --home-dir "$NOP_DIR" --shell /sbin/nologin "$NOP_USER"
rm -rf "$NOP_DIR"; mkdir -p "$NOP_DIR"
ZIP="/tmp/nopCommerce_${NOP_VERSION}.zip"
curl -fL "https://github.com/nopSolutions/nopCommerce/releases/download/release-${NOP_VERSION}/nopCommerce_${NOP_VERSION}_NoSource_linux_x64.zip" -o "$ZIP"
unzip -q "$ZIP" -d "$NOP_DIR"
mkdir -p "$NOP_DIR"/{bin,logs,App_Data}

# Tell nop it sits behind a reverse proxy so it sees the original https scheme
cat > "$NOP_DIR/App_Data/appsettings.json" <<'EOF'
{
  "HostingConfig": {
    "UseProxy": true,
    "ForwardedProtoHeaderName": "X-Forwarded-Proto",
    "ForwardedForHeaderName": "X-Forwarded-For"
  }
}
EOF
chown -R "$NOP_USER":"$NOP_USER" "$NOP_DIR"
chmod -R u+rwX,g-rwx,o-rwx "$NOP_DIR"

log "systemd unit (loopback only)"
cat > /etc/systemd/system/nopCommerce.service <<EOF
[Unit]
Description=nopCommerce
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=${NOP_DIR}
ExecStart=/usr/bin/dotnet ${NOP_DIR}/Nop.Web.dll
Restart=always
RestartSec=10
KillSignal=SIGINT
SyslogIdentifier=nopCommerce
User=${NOP_USER}
Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=ASPNETCORE_URLS=http://127.0.0.1:${NOP_PORT}
Environment=DOTNET_PRINT_TELEMETRY_MESSAGE=false
Environment=DOTNET_CLI_HOME=/tmp
Environment=DOTNET_ROOT=/usr/share/dotnet
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now nopCommerce

log "Self-signed certificate"
mkdir -p "$CERT_DIR"
IP_LIST="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9.]+$' | sed 's/^/IP:/' | paste -sd, -)"
SAN="DNS:${CERT_CN},DNS:localhost,IP:127.0.0.1${IP_LIST:+,${IP_LIST}}"
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 365 \
  -keyout "$CERT_DIR/nop.key" -out "$CERT_DIR/nop.crt" \
  -subj "/CN=${CERT_CN}" -addext "subjectAltName=${SAN}"
chmod 600 "$CERT_DIR/nop.key"; chmod 644 "$CERT_DIR/nop.crt"
restorecon -R "$CERT_DIR" 2>/dev/null || true

log "nginx config"
[[ -f /etc/nginx/nginx.conf.orig ]] || cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
cat > /etc/nginx/nginx.conf <<'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    sendfile on;
    server_tokens off;
    include /etc/nginx/conf.d/*.conf;
}
EOF
cat > /etc/nginx/conf.d/nopcommerce.conf <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    ssl_certificate     ${CERT_DIR}/nop.crt;
    ssl_certificate_key ${CERT_DIR}/nop.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    client_max_body_size 50m;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;

    location / {
        proxy_pass http://127.0.0.1:${NOP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection keep-alive;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 120s;
    }
}
EOF

log "SELinux + firewall"
setsebool -P httpd_can_network_connect 1 2>/dev/null || true
systemctl enable --now firewalld
firewall-cmd --permanent --add-service=http --add-service=https
firewall-cmd --reload

nginx -t
systemctl enable nginx
systemctl restart nginx

log "Smoke test"
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://127.0.0.1:${NOP_PORT}/" && break || sleep 2
done
echo "nop (loopback):  $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${NOP_PORT}/)"
echo "http redirect:   $(curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}' http://127.0.0.1/)"
echo "https via nginx: $(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/)"
ss -tlnp | grep -E ":(80|443|${NOP_PORT}) " || true

cat <<EOF

Done. Open https://${CERT_CN}/ (or the box IP) to run the nop install wizard:
  SQL Server: ${DB_HOST}   DB: ${DB_NAME}   Auth: SQL login ${DB_USER}
  Untick "Create database if it doesn't exist" (it's already created and empty).
EOF