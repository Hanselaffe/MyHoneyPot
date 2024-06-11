import datetime

LOG_FILE = "honeypot.log"

def log_attack(ip, data):
    with open(LOG_FILE, "a") as file:
        file.write(f"{datetime.datetime.now()} - IP: {ip}, Data: {data}\n")

def get_logs():
    with open(LOG_FILE, "r") as file:
        return file.readlines()
