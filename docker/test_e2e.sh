#!/usr/bin/env sh

set -exo pipefail

> ${LOG_FILE_PATH}

cat <<EOF > /tmp/ws-expected.log
OPEN
SERVER->CLIENT: 30 (websocket)
CLIENT->SERVER: 7 (websocket)
SERVER->CLIENT: 7 (websocket)
CLOSE
EOF

echo "asdasd" | websocat --text ws://${ENDPOINT}

diff ${LOG_FILE_PATH} /tmp/ws-expected.log
