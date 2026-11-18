import sqlite3
import smtplib


def query_db(name: str):
    connection = sqlite3.connect("app.db")
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    return connection.execute(sql).fetchall()


def send_mail(address: str) -> None:
    client = smtplib.SMTP("localhost")
    client.sendmail("ops@example-corp.test", [address], "ping")
