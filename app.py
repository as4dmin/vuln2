from flask import Flask, request, jsonify, render_template, send_from_directory
from zapv2 import ZAPv2
from flask_sqlalchemy import SQLAlchemy
import os
import time
from flask_migrate import Migrate



app = Flask(__name__, static_folder='C:/Users/As4dmin/Music/templates')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zap_scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize ZAP API client
zap = ZAPv2(apikey='fnfg1cmalsl417hvkjcnjpoduf', proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})

# Database model
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Create tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # Open URL in ZAP
        zap.urlopen(url)
        time.sleep(2)

        # Start passive scan
        zap.pscan.enable_all_scanners()
        time.sleep(2)

        # Start active scan
        scan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(5)

        # Get alerts
        alerts = zap.core.alerts(baseurl=url)
        categorized_alerts = {
            'High': [],
            'Medium': [],
            'Low': [],
            'Informational': []
        }

        for alert in alerts:
            risk = alert['risk']
            if risk == 'High':
                categorized_alerts['High'].append(alert)
            elif risk == 'Medium':
                categorized_alerts['Medium'].append(alert)
            elif risk == 'Low':
                categorized_alerts['Low'].append(alert)
            else:
                categorized_alerts['Informational'].append(alert)

        # Save scan result to database
        scan_record = Scan(
            url=url,
            status="Completed",
            alerts=str(categorized_alerts)  # Store the categorized alerts as a string
        )
        db.session.add(scan_record)
        db.session.commit()

        return render_template('results.html', categorized_alerts=categorized_alerts)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/scans')
def scans():
    scan_records = Scan.query.all()
    return render_template('scans.html', scan_records=scan_records)

if __name__ == '__main__':
    app.run(debug=True)
