from flask import Blueprint, render_template
from honeypot import logger

main = Blueprint('main', __name__)

@main.route('/')
def index():
    logs = logger.get_logs()
    return render_template('index.html', logs=logs)
