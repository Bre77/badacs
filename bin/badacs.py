from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.cli_common import getMergedConf
from splunk.rest import simpleRequest
from splunk.clilib.bundle_paths import make_splunkhome_path
import requests
import os
import json
import logging
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import aiohttp


APP_NAME = "badacs"
ATTR_BLACKLIST = ['eai:acl', 'eai:appName', 'eai:userName', 'maxDist', 'priority', 'sourcetype', 'termFrequencyWeightedDist']


logger = logging.getLogger(f"splunk.appserver.{APP_NAME}.req")

# Cached data
cached_servers = {}
cached_defaults = {}

class req(PersistentServerConnectionApplication):
    

    def __init__(self, command_line, command_arg):
        PersistentServerConnectionApplication.__init__(self)
        self.loop = asyncio.get_event_loop()

    def fixval(self,value):
        if type(value) is str:
            if value.lower() in ["true","1"]:
                return True
            if value.lower() in ["false","0"]:
                return False
        return value

    def gettoken(self,uri,token,server):
        _, resPasswords = simpleRequest(f"/servicesNS/nobody/{APP_NAME}/storage/passwords/%3A{server}%3A?output_mode=json&count=1", sessionKey=token, method='GET', raiseAllErrors=True)
        return json.loads(resPasswords)['entry'][0]['content']['clear_password']

    def errorhandle(self, message, status=400):
        logger.error(message)
        return {'payload': message, 'status': status}

    def handle(self, in_string):
        global cached_servers, cached_defaults
        #try:
        args = json.loads(in_string)

        if args['method'] != "POST":
            return {'payload': {'message': "Service running."}, 'status': 200 }

        output = {}

        USER = args['session']['user']
        AUTHTOKEN = args['session']['authtoken']
        LOCAL_URI = args['server']['rest_uri']

        
        # https://dev.lan:8089/
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
            for server in c:
                c[server]['acs'] = self.fixval(c[server]['acs'])
                c[server]['verify'] = self.fixval(c[server]['verify'])
            return {'payload': json.dumps(c, separators=(',', ':')), 'status': 200}
        
        # Get metadata for all configured servers
        if form['a'] == "getservers":
            output = {
                args['server']['hostname']: self.getserver(LOCAL_URI,AUTHTOKEN) 
            }
            for host in getMergedConf(APP_NAME):
                if host == "default":
                    continue
                token = self.gettoken(LOCAL_URI,AUTHTOKEN,host)
                output[host] = self.getserver(f"https://{host}:8089",token)
            cached_servers = output
            return {'payload': json.dumps(output, separators=(',', ':')), 'status': 200}

        if form['a'] == "getcachedservers":
            return {'payload': json.dumps(cached_servers, separators=(',', ':')), 'status': 200}

        # Add a new server and get its base metadata
        if form['a'] == "addserver":
            for x in ['server','token']: # Check required parameters
                if x not in form:
                    logger.warn(f"Request to 'addserver' was missing '{x}' parameter")
                    return {'payload': "Missing '{x}' parameter", 'status': 400}
            try:
                r = requests.get(f"https://admin.splunk.com/{form['server']}/adminconfig/v2/status", headers={'Authorization':f"Bearer {form['token']}"})
                r.raise_for_status()
            except Exception as e:
                return errorhandle(f"Adding new stack failed with error '{e}'")
            try:
                _, resPassword = simpleRequest(f"{LOCAL_URI}/servicesNS/nobody/{APP_NAME}/storage/passwords", sessionKey=AUTHTOKEN, postargs={'name': form['server'], 'password': form['token']}, method='POST', raiseAllErrors=True)
                _, resConfig = simpleRequest(f"{LOCAL_URI}/servicesNS/nobody/{APP_NAME}/configs/conf-badacs", sessionKey=AUTHTOKEN, postargs={'name': form['server']}, method='POST', raiseAllErrors=True)
                return {'payload': 'true', 'status': 200}
            except Exception as e:
                return {'payload': json.dumps(str(e), separators=(',', ':')), 'status': 400}

        # HELPER - Get Server Context
        if 'server' in form:
            # Validate "server"
            if form['server'] in [args['server']['hostname'],"local"]:
                uri = LOCAL_URI
                token = AUTHTOKEN
            else:
                uri = f"https://{form['server']}:8089"
                token = self.gettoken(LOCAL_URI,AUTHTOKEN,form['server'])
        else:
            logger.warn("Request was missing 'server' parameter")
            return {'payload': "Missing 'server' parameter", 'status': 400}

        # Get config of a single server
        if form['a'] == "getconf":
            for x in ['server','file','user','app']: # Check required parameters
                if x not in form:
                    logger.warn(f"Request to 'getconf' was missing '{x}' parameter")
                    return {'payload': "Missing '{x}' parameter", 'status': 400}
            serverResponse, resConfig = simpleRequest(f"{uri}/servicesNS/{form['user']}/{form['app']}/configs/conf-{form['file']}/{form.get('stanza','')}?output_mode=json&count=0", sessionKey=token, method='GET', raiseAllErrors=True)
            configs = json.loads(resConfig)['entry']
            return self.handleConf(configs)
        
        # Change a config and process the response
        if form['a'] == "setconf":
            for x in ['server','file','stanza','attr','value']: # Check required parameters
                if x not in form:
                    logger.warn(f"Request to 'setconf' was missing '{x}' parameter")
                    return {'payload': "Missing '{x}' parameter", 'status': 400}
            postargs = {form['attr']: form['value']}
            serverResponse, resConfig = simpleRequest(f"{uri}/servicesNS/{form['user']}/{form['app']}/configs/conf-{form['file']}/{form['stanza']}?output_mode=json", sessionKey=token, method='POST', raiseAllErrors=True, postargs=postargs)
            configs = json.loads(resConfig)['entry']

            return self.handleConf(configs)

        if form['a'] == "getfiles":
            if 'server' not in form:
                logger.warn(f"Request to 'getfiles' was missing 'server' parameter")
                return {'payload': "Missing 'server' parameter", 'status': 400}
            serverResponse, resConfig = simpleRequest(f"{uri}/services/properties?output_mode=json", sessionKey=token, method='GET', raiseAllErrors=True)
            output = [f['name'] for f in json.loads(resConfig)['entry']]
            return {'payload': json.dumps(output, separators=(',', ':')), 'status': 200}

        # ACS Endpoints
        if form['a'] == "get":
            for x in ['server','endpoint']: # Check required parameters
                if x not in form:
                    return self.errorhandle(f"Request to 'get' was missing '{x}' parameter")
            server = form['server'].split('.')[0]
            
            try:
                r = requests.get(f"https://admin.splunk.com/{server}/adminconfig/v2/{form['endpoint']}", headers={'Authorization':f"Bearer {token}"})
                r.raise_for_status()
                return {'payload': json.dumps(r.json(), separators=(',', ':')), 'status': 200}
            except Exception as e:
                return self.errorhandle(f"ACS get request for {server}/adminconfig/v2/{form['endpoint']} returned {e}")

        if form['a'] == "patch":
            for x in ['server','endpoint','data']: # Check required parameters
                if x not in form:
                    return self.errorhandle(f"Request to 'patch' was missing '{x}' parameter")
            server = form['server'].split('.')[0]
            
            try:
                r = requests.patch(f"https://admin.splunk.com/{server}/adminconfig/v2/{form['endpoint']}", headers={'Authorization':f"Bearer {token}", "Content-Type":"application/json"}, data=form['data'])
                r.raise_for_status()
                return {'payload': json.dumps(r.json(), separators=(',', ':')), 'status': 200}
            except Exception as e:
                return self.errorhandle(f"ACS patch request for {server}/adminconfig/v2/{form['endpoint']} returned {e}")

        if form['a'] == "post":
            for x in ['server','endpoint','data']: # Check required parameters
                if x not in form:
                    return self.errorhandle(f"Request to 'post' was missing '{x}' parameter")
            server = form['server'].split('.')[0]
            
            try:
                r = requests.post(f"https://admin.splunk.com/{server}/adminconfig/v2/{form['endpoint']}", headers={'Authorization':f"Bearer {token}", "Content-Type":"application/json"}, data=form['data'])
                r.raise_for_status()
                return {'payload': json.dumps(r.json(), separators=(',', ':')), 'status': 200}
            except Exception as e:
                return self.errorhandle(f"ACS post request for {server}/adminconfig/v2/{form['endpoint']} returned {e}")


        return {'payload': "No Action Requested", 'status': 400}
        #except Exception as ex:
        #    return {'payload': json.dumps(ex), 'status': 500}
