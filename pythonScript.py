from flask import Flask, render_template, request, jsonify
import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse

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

# def is_valid(url):
#     try:
#         result = urlparse(url)
#         return all([result.scheme, result.netloc])
#     except ValueError:
#         return False
def is_valid(url):
    try:
        response = requests.head(url)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False
    
def scan_url(api_key, url):
    api_url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": url}
    headers = {
        "accept": "application/json",
        "x-apikey":api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
   
    try:
        response = requests.post(api_url, data=payload, headers=headers)
        data = response.json()
        id = data.get('data', {}).get('id', {})
        url_analysis = f'https://www.virustotal.com/api/v3/analyses/{id}'
        report= requests.get(url_analysis, headers=headers)
        stat = (report.json()).get('data', {}).get('attributes', {}).get('stats', {})
        malicious_count = stat.get('malicious', 0)
        print("malicious = ",malicious_count)
        if malicious_count>0:
            return 1
        else:   
            return 0
    except requests.exceptions.HTTPError as err:
        print(f"HTTP Error: {err}")
        print(response.text)
        return -2
   


if __name__ == '__main__':
    app.run(debug=True)