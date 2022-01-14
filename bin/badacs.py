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

    def errorhandle(self, message, error="", status=400):
        logger.error(f"app={APP_NAME} user={self.USER} status={status} message=\"{message}\" error=\"{error}\"")
        return {'payload': json.dumps({'message':message, 'error':str(error)}, separators=(',', ':')), 'status': status}

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
            return self.errorhandle("Missing 'a' parameter")

        # Helpful crash for debugging
        if form['a'] == "crash":
            raise(Exception("Force Restart"))

        try:
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
                for x in ['stack','token','shared']: # Check required parameters
                    if x not in form:
                        return self.errorhandle(f"Request to 'addstack' was missing '{x}' parameter")
                try:
                    r = requests.get(f"https://admin.splunk.com/{form['stack']}/adminconfig/v2/status", headers={'Authorization':f"Bearer {form['token']}"})
                    if r.status_code != 200:
                        try:
                            data = r.json()
                            message = data.get('message',r.text)
                        except Exception:
                            message = r.text
                        return self.errorhandle(message,r.reason,r.status_code)
                except Exception as e:
                    return self.errorhandle(f"Connecting to ACS failed",e)

                user_context = "nobody" if form['shared'] == "true" else self.USER
                sharing = "app" if form['shared'] == "true" else "user"
                logger.info(f"Adding {form['stack']} for user {user_context}")

                # Config
                try:
                    resp, _ = simpleRequest(f"{self.LOCAL_URI}/servicesNS/{user_context}/{APP_NAME}/configs/conf-{APP_NAME}", sessionKey=self.AUTHTOKEN, postargs={'name': form['stack']})
                    if resp.status not in [200,201,409]:
                        return self.errorhandle(f"Adding new stack '{form['stack']}' failed", resp.reason, resp.status)
                except Exception as e:
                    return self.errorhandle(f"POST request to {self.LOCAL_URI}/servicesNS/{user_context}/{APP_NAME}/configs/conf-{APP_NAME} failed", e)
                            
                
                # Password Storage
                try:
                    resp, _ = simpleRequest(f"{self.LOCAL_URI}/servicesNS/{user_context}/{APP_NAME}/storage/passwords", sessionKey=self.AUTHTOKEN, postargs={'realm': APP_NAME, 'name': form['stack'], 'password': form['token']})
                    if resp.status not in [200,201,409]:
                        return self.errorhandle(f"Adding token for  '{form['']}' failed", resp.reason, resp.status) 
                    if resp.status == 409:
                        resp, _ = simpleRequest(f"{self.LOCAL_URI}/servicesNS/{self.USER}/{APP_NAME}/storage/passwords/{APP_NAME}%3A{form['']}%3A?output_mode=json&count=1", sessionKey=self.AUTHTOKEN, postargs={'password': form['token']})
                        if resp.status not in [200,201]:
                            return self.errorhandle(f"Updating token for  '{form['']}' failed", resp.reason, resp.status) 
                except Exception as e:
                    return self.errorhandle(f"POST request to {self.LOCAL_URI}/servicesNS/{user_context}/{APP_NAME}/storage/passwords failed", e)  
                
                # Password ACL
                try:
                    resp, _ = simpleRequest(f"{self.LOCAL_URI}/servicesNS/{self.USER}/{APP_NAME}/storage/passwords/{APP_NAME}%3A{form['']}%3A/acl?output_mode=json", sessionKey=self.AUTHTOKEN, postargs={'owner': self.USER, 'sharing': sharing})
                    if resp.status not in [200,201]:
                        return self.errorhandle(f"Setting ACL sharing to {sharing} for token of '{form['']}' failed", resp.reason, resp.status) 
                except Exception as e:
                    return self.errorhandle(f"POST request to {self.LOCAL_URI}/servicesNS/{self.USER}/{APP_NAME}/storage/passwords/{APP_NAME}%3A{form['']}%3A/acl failed", e)    

                return {'payload': 'true', 'status': 200}

                #try:
                #    
                #    _, resPassword = simpleRequest(f"servicesNS/{user_context}/{APP_NAME}/storage/passwords", sessionKey=self.AUTHTOKEN, postargs={'realm': APP_NAME, 'name': form['stack'], 'password': form['token']}, raiseAllErrors=True)
                #    _, resConfig = simpleRequest(f"servicesNS/{user_context}/{APP_NAME}/configs/conf-badacs", sessionKey=self.AUTHTOKEN, postargs={'name': form['stack']}, raiseAllErrors=True)
                #    return {'payload': 'true', 'status': 200}
                #except Exception as e:
                #    return self.errorhandle(f"Failed to save stack {form['stack']}",e)

            if "stack" not in form:
                return self.errorhandle("Missing 'stack' parameter")
            else:
                try:
                    _, resPasswords = simpleRequest(f"servicesNS/{self.USER}/{APP_NAME}/storage/passwords/{APP_NAME}%3A{form['stack']}%3A?output_mode=json&count=1", sessionKey=self.AUTHTOKEN, raiseAllErrors=True)
                    token = json.loads(resPasswords)['entry'][0]['content']['clear_password']
                except Exception as e:
                    return self.errorhandle(f"Couldn't retrieve auth token for {form['stack']}",e)

            # ACS Endpoints
            if form['a'] == "get":
                for x in ['stack','endpoint']: # Check required parameters
                    if x not in form:
                        return self.errorhandle(f"Request to 'get' was missing '{x}' parameter")
                
                try:
                    r = requests.get(f"https://admin.splunk.com/{form['stack']}/adminconfig/v2/{form['endpoint']}", headers={'Authorization':f"Bearer {token}"})
                    if r.status_code != 200:
                        return self.errorhandle(r.json()['message'],r.reason,r.status_code)
                    return {'payload': r.text, 'status': 200}
                except Exception as e:
                    return self.errorhandle(f"ACS get failed for {form['stack']}/adminconfig/v2/{form['endpoint']}",e)

            if form['a'] == "change":
                for x in ['stack','endpoint','method','data']: # Check required parameters
                    if x not in form:
                        return self.errorhandle(f"Request to 'change' was missing '{x}' parameter")
                
                try:
                    r = requests.request(form['method'], f"https://admin.splunk.com/{form['stack']}/adminconfig/v2/{form['endpoint']}", headers={'Authorization':f"Bearer {token}", "Content-Type":"application/json"}, data=form['data'])
                    if r.status_code not in [200,201,202]:
                        return self.errorhandle(r.json()['message'],r.reason,r.status_code)
                    return {'payload': '"OK"', 'status': r.status_code}
                except Exception as e:
                    return self.errorhandle(f"ACS change failed for {form['stack']}/adminconfig/v2/{form['endpoint']}",e)



            return self.errorhandle("Invalid Action")
        except Exception as e:
            return self.errorhandle("Server Error",e,500)
