# Honeypot

A security system designed to detect, log, and analyze unauthorized access attempts. This honeypot is set up to listen on a specific port and log all incoming connections and data.

## HoneyPot

- [Description](#description)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)

## Description

This project is a Honeypot developed using Flask and Python. It logs unauthorized access attempts and provides a web interface to view the logs.

## Features

- **Logging of Unauthorized Access Attempts**: Logs IP addresses and data of incoming connections.
- **Web Interface**: Displays logged attacks in a user-friendly web interface.

## Prerequisites

Ensure the following packages are installed on your system:

- Python 3
- Pip
- Virtual Environment (optional but recommended)

## Installation

1. **Clone the repository**:
   ```sh
   git clone https://github.com/Hanselaffe/MyHoneyPot.git
   cd honeypot
   
2. **Create and activate a virtual environment (optional but recommended)**:
   ```sh
   virtualenv venv
   source venv/bin/activate
   
4. **Install the dependencies**:
   ```sh
   pip install -r requirements.txt


## Usage

1. **Start the Flask app**:
   ```sh
   python run.py

3. **Open your web browser and navigate to http://127.0.0.1:5000/**.

4. **View the logs of unauthorized access attempts.**

## Project Structure
  honeypot/
│
├── app/
│   ├── __init__.py
│   ├── routes.py
│   ├── static/
│   │   └── styles.css
│   └── templates/
│       └── index.html
│
├── honeypot/
│   ├── __init__.py
│   ├── honeypot.py
│   ├── logger.py
│
├── tests/
│   ├── __init__.py
│
├── run.py
└── requirements.txt

- app/: Contains the Flask application and routes.
- honeypot/: Contains the honeypot implementation and logging functionality.
- tests/: Placeholder for future tests.
- run.py: Starts the Flask application and honeypot server.
- requirements.txt: Lists the Python dependencies.
     


   



   
