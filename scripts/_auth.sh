# Sourced by the lab scripts: signs in once and makes every `curl` send the session token.
# Credentials: ASI_ADMIN_USER / ASI_ADMIN_PASSWORD from the environment, else from .env.
ENV_FILE=${ENV_FILE:-"$(dirname "${BASH_SOURCE[0]}")/../.env"}
env_value() { [ -f "$ENV_FILE" ] && sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1; }
ASI_ADMIN_USER=${ASI_ADMIN_USER:-$(env_value ASI_ADMIN_USER)}
ASI_ADMIN_USER=${ASI_ADMIN_USER:-admin}
ASI_ADMIN_PASSWORD=${ASI_ADMIN_PASSWORD:-$(env_value ASI_ADMIN_PASSWORD)}
[ -n "$ASI_ADMIN_PASSWORD" ] || { echo "set ASI_ADMIN_PASSWORD (in .env or the environment)" >&2; exit 1; }

ASI_TOKEN=$(python3 -c 'import json,sys; print(json.dumps({"username":sys.argv[1],"password":sys.argv[2]}))' \
    "$ASI_ADMIN_USER" "$ASI_ADMIN_PASSWORD" |
  command curl -sf "$API/auth/login" -H 'Content-Type: application/json' -d @- |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])') ||
  { echo "login to $API failed" >&2; exit 1; }

curl() { command curl -H "Authorization: Bearer $ASI_TOKEN" "$@"; }
