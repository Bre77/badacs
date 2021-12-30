from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.cli_common import getMergedConf
from splunk.rest import simpleRequest
import requests
import os, json
import logging
from distutils.util import strtobool
import urllib.parse

APP_NAME = "badacs"
ATTR_BLACKLIST = ['eai:acl', 'eai:appName', 'eai:userName', 'maxDist', 'priority', 'sourcetype', 'termFrequencyWeightedDist']

logger = logging.getLogger('splunk.appserver.badacs')
logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
#logger.setLevel(level)

#log_file_path = make_splunkhome_path(['var', 'log', 'splunk', 'badacs_rest.log'])
#file_handler = logging.handlers.RotatingFileHandler(log_file_path, maxBytes=25000000,backupCount=5)

#formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
#file_handler.setFormatter(formatter)
#logger.addHandler(file_handler)

class req(PersistentServerConnectionApplication):

    def __init__(self, command_line, command_arg):
        PersistentServerConnectionApplication.__init__(self)

    def fixval(self,value):
        if type(value) is str:
            if value.lower() in ["true","1"]:
                return True
            if value.lower() in ["false","0"]:
                return False
        return value


    def getserver(self,uri,token):
        _, resApps = simpleRequest(f"{uri}/services/apps/local?output_mode=json&count=0", sessionKey=token, method='GET', raiseAllErrors=True)
        _, resUsers = simpleRequest(f"{uri}/services/authentication/users?output_mode=json&count=0", sessionKey=token, method='GET', raiseAllErrors=True)
        return {
            "apps": [{"name": x['name'], "label":x['content'].get('label'), "visable":x['content'].get('visible'), "details":x['content'].get('details'), "version":x['content'].get('version')} for x in json.loads(resApps)['entry'] if not x['content']['disabled']],
            "users": [{"name": x['name'], "realname": x['content'].get('realname'), "defaultApp":x['content'].get('defaultApp')} for x in json.loads(resUsers)['entry']]
        }

    def gettoken(self,uri,token,server):
        _, resPasswords = simpleRequest(f"{uri}/servicesNS/admin/badacs/storage/passwords/%3A{server}%3A?output_mode=json&count=1", sessionKey=token, method='GET', raiseAllErrors=True)
        return json.loads(resPasswords)['entry'][0]['content']['clear_password']

    def handleConf(self,configs):
        try:
            serverResponse, resDefault = simpleRequest(f"{uri}/services/properties/{form['file']}/default?output_mode=json&count=0", sessionKey=token, method='GET', raiseAllErrors=False)
            defaults = {}
            for default in json.loads(resDefault)['entry']:
                defaults[default['name']] = self.fixval(default['content'])
        except Exception:
            defaults = {}

        output = {}

        for stanza in configs:
            app = stanza['acl']['app']
            if app not in output:
                output[app] = {}
            output[app][stanza['name']] = {
                'acl':{
                    'can_write':stanza['acl']['can_write'],
                    'owner':stanza['acl']['owner'],
                    'sharing':stanza['acl']['sharing']
                },
                'attr':{}
            } #'id':stanza['id'],
            for attr in stanza['content']:
                value = self.fixval(stanza['content'][attr])
                if attr in ATTR_BLACKLIST or (attr in defaults and value == defaults[attr]):
                    continue
                output[app][stanza['name']]['attr'][attr] = value
        return {'payload': json.dumps(output, separators=(',', ':')), 'status': 200}

    #def listservers(self,args,conf):
    #    output = {"local":{"uri": args['server']['rest_uri'], "token": AUTHTOKEN}}
    #    for stanza in conf:
    #        if stanza.startswith(f"{APP_NAME}://"):
    #            _, server = stanza.split("://")
    #            output[server] = {"uri": f"https://{server}:{conf[stanza]['port']}", "token": conf[stanza]['token']}
    #    return output

    def handle(self, in_string):
        
        #try:
        args = json.loads(in_string)

        if args['method'] != "POST":
            return {'payload': {'message': "Service running."}, 'status': 200 }

        CONF = getMergedConf(APP_NAME)
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
            return {'payload': {'message': "No action."}, 'status': 200 }

        

        # Helpful crash for debugging
        if form['a'] == "crash":
            throw("restart")

        # Dump the args
        if form['a'] == "args":
            return {'payload': json.dumps(args, separators=(',', ':')), 'status': 200}

        # Dump the config
        if form['a'] == "config":
            c = dict(CONF)
            del c['default']
            for stanza in c:
                c[stanza]['token'] = 'token' in c[stanza]
            return {'payload': json.dumps(c, separators=(',', ':')), 'status': 200}
        
        # Get metadata for all configured servers
        if form['a'] == "getservers":
            output = {
                args['server']['hostname']: self.getserver(LOCAL_URI,AUTHTOKEN) 
            }
            for host in CONF:
                if host == "default":
                    continue
                token = self.gettoken(LOCAL_URI,AUTHTOKEN,host)
                output[host] = self.getserver(f"https://{host}:8089",token)
            return {'payload': json.dumps(output, separators=(',', ':')), 'status': 200}

        # Add a new server and get its base metadata
        if form['a'] == "addserver" and form['server'] and form['token']:
            try:
                _, resPassword = simpleRequest(f"{LOCAL_URI}/servicesNS/nobody/badacs/storage/passwords", sessionKey=AUTHTOKEN, postargs={'name': form['server'], 'password': form['token']}, method='POST', raiseAllErrors=True)
                _, resConfig = simpleRequest(f"{LOCAL_URI}/servicesNS/nobody/badacs/configs/conf-badacs", sessionKey=AUTHTOKEN, postargs={'name': form['server'], 'acs': False}, method='POST', raiseAllErrors=True)
                output = json.loads(resConfig)['entry']
                return {'payload': json.dumps(output, separators=(',', ':')), 'status': 200}
            except Exception as e:
                return {'payload': json.dumps(str(e), separators=(',', ':')), 'status': 400}

        # HELPER - Get Server Context
        if 'server' in form:
            if form['server'] in [args['server']['hostname'],"local"]:
                uri = LOCAL_URI
                token = AUTHTOKEN
            else:
                uri = f"https://{form['server']}:8089"
                token = self.gettoken(LOCAL_URI,AUTHTOKEN,form['server'])

        # Get config of a single server
        if form['a'] == "getconf" and 'file' in form and 'server' in form and 'user' in form and 'app' in form:
            serverResponse, resConfig = simpleRequest(f"{uri}/servicesNS/{form['user']}/{form['app']}/configs/conf-{form['file']}/{form.get('stanza','')}?output_mode=json&count=0", sessionKey=token, method='GET', raiseAllErrors=True)
            configs = json.loads(resConfig)['entry']

            return self.handleConf(configs)
        
        # Change a config and process the response
        if form['a'] == "setconf" and form['file'] and form['server'] and form['stanza'] and form['attr'] and 'value' in form:
            postargs = {form['attr']: form['value']}
            serverResponse, resConfig = simpleRequest(f"{uri}/servicesNS/{form['user']}/{form['app']}/configs/conf-{form['file']}/{form['stanza']}?output_mode=json", sessionKey=token, method='POST', raiseAllErrors=True, postargs=postargs)
            configs = json.loads(resConfig)['entry']

            return self.handleConf(configs)

        if form['a'] == "getfiles" and form['server']:
            serverResponse, resConfig = simpleRequest(f"{uri}/services/properties?output_mode=json", sessionKey=token, method='GET', raiseAllErrors=True)
            output = [f['name'] for f in json.loads(resConfig)['entry']]
            return {'payload': json.dumps(output, separators=(',', ':')), 'status': 200}

        if form['a'] == "getnetwork" and form['server']:
            server = form['server'].split('.')[0]
            headers = {"Authorization": f"Bearer {token}"}
            output = {}
            for feature in ['search-api','hec','s2s','search-ui','idm-ui','idm-api']:
                try:
                    r = requests.get(f"https://admin.splunk.com/{server}/adminconfig/v2/access/{feature}/ipallowlists", headers=headers)
                    output[feature] = r.json()
                except Exception as e:
                    output[feature] = e
            try:
                r = requests.get(f"https://admin.splunk.com/{server}/adminconfig/v2/access/outbound-ports", headers=headers)
                output['outbound-ports'] = r.json()
            except Exception as e:
                output['outbound-ports'] = e
            
            return {'payload': json.dumps(output, separators=(',', ':')), 'status': 200}


        return {'payload': "No Action Requested", 'status': 400}
        #except Exception as ex:
        #    return {'payload': json.dumps(ex), 'status': 500}
