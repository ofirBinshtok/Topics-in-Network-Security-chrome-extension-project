from flask import Flask, render_template, request, jsonify
import requests

api_key = '2d4bdbc3b275e3c5d709a00fbdae114851cf26e8a48ea073e71d8c170ac2a27e'

app = Flask(__name__)

@app.route('/')
def index_html_file():
    return render_template('index.html')

# listens for POST requests. gets the URL from the form data sent by our JavaScript code.
@app.route('/check_phishing', methods=['POST'])
def check_phishing():
    url = request.form.get('url')
    positives_count =  scan_url(api_key, url)
    return jsonify({'positive detections for the scanned URL': positives_count}) #return the result as a JSON 

def scan_url(api_key, url):
    url_scan_endpoint = 'https://www.virustotal.com/vtapi/v2/url/scan'
    url_report_endpoint = 'https://www.virustotal.com/vtapi/v2/url/report'

    # Step 1: Submit URL for scanning
    params_scan = {'apikey': api_key, 'url': url}
    response_scan = requests.post(url_scan_endpoint, params=params_scan)

    # Get the scan result and resource for further report retrieval
    scan_result = response_scan.json()
    resource = scan_result.get('scan_id', '')

    # Step 2: Retrieve the scan report
    params_report = {'apikey': api_key, 'resource': resource}
    response_report = requests.get(url_report_endpoint, params=params_report)

    # Extract the scan result from the report
    scan_result = response_report.json().get('positives', 0)

    return scan_result

# Get URL input from the user
#url_to_check = input('Enter the URL you want to scan: ')

# Scan the URL and print the result
#positives = scan_url(api_key, url_to_check)
#if positives > 0:
#    print(f'The URL "{url_to_check}" is potentially malicious with {positives} positive detections.')
#else:
#    print(f'The URL "{url_to_check}" is likely safe.')

if __name__ == '__main__':
    app.run(debug=True)