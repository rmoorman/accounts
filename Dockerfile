FROM centurylink/ca-certs

ADD bin/dex-worker-linux-amd64 /opt/dex/bin/dex-worker
ADD bin/dex-overlord-linux-amd64 /opt/dex/bin/dex-overlord
ADD bin/accounts-linux-amd64 /opt/dex/bin/accounts

ENV DEX_WORKER_HTML_ASSETS /opt/dex/html/
ADD static/html/* $DEX_WORKER_HTML_ASSETS

ENV DEX_WORKER_EMAIL_TEMPLATES /opt/dex/email/
ADD static/email/* $DEX_WORKER_EMAIL_TEMPLATES
ADD static/fixtures/emailer.json $DEX_WORKER_EMAIL_TEMPLATES/emailer.json
