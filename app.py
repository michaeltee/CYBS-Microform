from flask import Flask
from flask import request
from flask import render_template
import requests
import cybersource
import json
import jwt
app = Flask(__name__)

# Specify CYBS MID to load from cybs.cfg.
# If you need one, go to cybersource.com/register.
cybs_mid = "YOUR_CYBS_MID"

@app.route('/')
def renderDebugRequest():
   cybs = cybersource.Flex(cybs_mid)
   url = "https://" + cybs.host + cybs.request_target
   r = requests.post(url=url, data=cybs.body, headers=cybs.build_signature())
   return render_template('request.html', 
            host=cybs.host, date=cybs.date, request_target=cybs.request_target, 
            digest=cybs.digest, merchant_id=cybs_mid, target_origin=cybs.target_origin, 
             key_id=cybs.key_id, secret=cybs.secret, response_json=r.json(),
             capture_context=r.json()['keyId'])

@app.route('/renderMicroform', methods=['GET', 'POST'])
def renderMicroform():
   cybs = cybersource.Flex(cybs_mid)
   url = "https://" + cybs.host + cybs.request_target
   r = requests.post(url=url, data=cybs.body, headers=cybs.build_signature())
   if request.method == 'POST':
      return render_template('microform.html', capture_context=request.form['capture_context'])
   else:
      return render_template('microform.html', capture_context=r.json()['keyId'])


@app.route('/response', methods=['GET', 'POST'])
def debugResponse():
   decoded_jwt = jwt.decode(request.form['transientToken'], verify=False)
   raw_jwt = request.form['transientToken']
   return render_template('response.html', 
      mf_jwt=raw_jwt, header=jwt.get_unverified_header(request.form['transientToken']), 
      payload=decoded_jwt, transient_token=decoded_jwt['jti'])

if __name__ == '__main__':
    app.run()