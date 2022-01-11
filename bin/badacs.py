from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.cli_common import getMergedConf
from splunk.rest import simpleRequest
from splunk.clilib.bundle_paths import make_splunkhome_path
import requests
import json
import logging

APP_NAME = "badacs"

logger = logging.getLogger(f"splunk.appserver.{APP_NAME}.req")

class req(PersistentServerConnectionApplication):
    
    def __init__(self, command_line, command_arg):
        PersistentServerConnectionApplication.__init__(self)

    def errorhandle(self, message, status=400):
        logger.error(f"app={APP_NAME} user={self.USER} status={status} message=\"{message}\"")
        return {'payload': message, 'status': status}

    def handle(self, in_string):
        args = json.loads(in_string)

        if args['method'] != "POST":
            return {'payload': {'message': "Service running."}, 'status': 200 }

        self.USER = args['session']['user']
        self.AUTHTOKEN = args['session']['authtoken']
        self.LOCAL_URI = args['server']['rest_uri']

        # Process Form
        form = {}
        for x in args['form']:
            form[x[0]] = x[1]

        if "a" not in form:
            logger.warn("Request was missing 'a' parameter")
            return {'payload': "Missing 'a' parameter", 'status': 200 }

        # Helpful crash for debugging
        if form['a'] == "crash":
            raise("restart")

        # Dump the args
        if form['a'] == "args":
            return {'payload': json.dumps(args, separators=(',', ':')), 'status': 200}

        # Dump the config
        if form['a'] == "config":
            c = getMergedConf(APP_NAME)
            del c['default']
            return {'payload': json.dumps(c, separators=(',', ':')), 'status': 200}

        

        # Add a new stack and get its base metadata
        if form['a'] == "addstack":
            for x in ['stack','token']: # Check required parameters
                if x not in form:
                    logger.warn(f"Request to 'addstack' was missing '{x}' parameter")
                    return {'payload': "Missing '{x}' parameter", 'status': 400}
            try:
                r = requests.get(f"https://admin.splunk.com/{form['stack']}/adminconfig/v2/status", headers={'Authorization':f"Bearer {form['token']}"})
                r.raise_for_status()
            except Exception as e:
                return errorhandle(f"Checking stack {form['stack']} threw the error '{e}'")
            try:
                _, resPassword = simpleRequest(f"/servicesNS/nobody/{APP_NAME}/storage/passwords", sessionKey=self.AUTHTOKEN, postargs={'name': form['stack'], 'password': form['token']}, method='POST', raiseAllErrors=True)
                _, resConfig = simpleRequest(f"/servicesNS/nobody/{APP_NAME}/configs/conf-badacs", sessionKey=self.AUTHTOKEN, postargs={'name': form['stack']}, method='POST', raiseAllErrors=True)
                return {'payload': 'true', 'status': 200}
            except Exception as e:
                return errorhandle(f"Failed to save stack {form['stack']}")

        if "stack" not in form:
            return self.errorhandle("Missing 'stack' parameter")
        else:
            try:
                _, resPasswords = simpleRequest(f"/servicesNS/nobody/{APP_NAME}/storage/passwords/{APP_NAME}%3A{stack}%3A?output_mode=json&count=1", sessionKey=self.AUTHTOKEN, method='GET', raiseAllErrors=True)
                token = json.loads(resPasswords)['entry'][0]['content']['clear_password']
            except Exception as e:
                return self.errorhandle(f"Couldn't retrieve auth token for {stack}")

        # ACS Endpoints
        if form['a'] == "get":
            for x in ['stack','endpoint']: # Check required parameters
                if x not in form:
                    return self.errorhandle(f"Request to 'get' was missing '{x}' parameter")
            
            try:
                r = requests.get(f"https://admin.splunk.com/{stack}/adminconfig/v2/{form['endpoint']}", headers={'Authorization':f"Bearer {token}"})
                r.raise_for_status()
                return {'payload': json.dumps(r.json(), separators=(',', ':')), 'status': 200}
            except Exception as e:
                return self.errorhandle(f"ACS get request for {stack}/adminconfig/v2/{form['endpoint']} returned {e}")

        if form['a'] == "change":
            for x in ['stack','endpoint','method','data']: # Check required parameters
                if x not in form:
                    return self.errorhandle(f"Request to 'patch' was missing '{x}' parameter")
            
            try:
                r = requests.request(form['method'], f"https://admin.splunk.com/{stack}/adminconfig/v2/{form['endpoint']}", headers={'Authorization':f"Bearer {token}", "Content-Type":"application/json"}, data=form['data'])
                r.raise_for_status()
                return {'payload': json.dumps(r.json(), separators=(',', ':')), 'status': 200}
            except Exception as e:
                return self.errorhandle(f"ACS patch request for {stack}/adminconfig/v2/{form['endpoint']} returned {e}")

        if form['a'] == "post":
            for x in ['stack','endpoint','data']: # Check required parameters
                if x not in form:
                    return self.errorhandle(f"Request to 'post' was missing '{x}' parameter")
            
            try:
                r = requests.post(f"https://admin.splunk.com/{stack}/adminconfig/v2/{form['endpoint']}", headers={'Authorization':f"Bearer {token}", "Content-Type":"application/json"}, data=form['data'])
                r.raise_for_status()
                return {'payload': json.dumps(r.json(), separators=(',', ':')), 'status': 200}
            except Exception as e:
                return self.errorhandle(f"ACS post request for {stack}/adminconfig/v2/{form['endpoint']} returned {e}")


        return {'payload': "No Action Requested", 'status': 400}
        #except Exception as ex:
        #    return {'payload': json.dumps(ex), 'status': 500}
