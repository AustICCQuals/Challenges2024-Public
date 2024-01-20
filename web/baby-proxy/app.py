from flask import Flask, render_template_string, request
import requests

app = Flask(__name__)

def response_filter(response):
    # prevent any sites from including templated strings
    bad_strings = [
        "{{",
        "}}",
        "{%",
        "%}"
    ]
    for bad_string in bad_strings:
        response = response.replace(bad_string, "")
    print("New response: ", response)
    return response

@app.route('/')
def index():
    index_html = open('index.html').read()
    return index_html

@app.route('/proxy', methods=['GET'])
def proxy():
    if request.args.get('url'):
        try:
            # make sure its a safe url
            print(request.args.get('url'))
            if not request.args.get('url').startswith('http'):
                return 'Bad url'
            # get the contents of the url
            res = requests.get(request.args.get('url'), allow_redirects=False, timeout=10)
            # render the contents of the url
            return render_template_string(response_filter(res.text))
        except:
            return "Error getting url"
    else:
        return "No url provided"
    
@app.route('/echo', methods=['GET'])
def echo():
    if request.args.get('data'):
        return request.args.get('data')
    else:
        return "echooooooooooooo"

if __name__ == "__main__":
    app.run(debug=False, port=3817)
