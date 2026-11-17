"""HTTP entrypoints reaching injection sinks for the policy golden corpus."""

import subprocess

from flask import Flask, request

from .store import query_db, send_mail

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.check_output("ping -c1 " + host, shell=True)
    return "ok"


@app.route("/search")
def search():
    name = request.args.get("name")
    return query_db(name)


@app.route("/safe-report")
def safe_report():
    return query_db("weekly-report")


@app.route("/notify")
def notify():
    target = request.args.get("target")
    send_mail(target)
    return "queued"
