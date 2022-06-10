const REST_ENDPOINT = `/${window.$C.LOCALE}/splunkd/__raw/services/badacs?output_mode=json`
const CSRF = /splunkweb_csrf_token_\d+=(\d+)/.exec(document.cookie)[1]
const COLUMNS_MAX = 8
const DELIM = "\0"
const ACS_NETWORK_ENDPOINTS = {
    'search-api':'access/search-api/ipallowlists',
    'hec':'access/hec/ipallowlists',
    's2s':'access/s2s/ipallowlists',
    'search-ui':'access/search-ui/ipallowlists',
    'idm-ui':'access/idm-ui/ipallowlists',
    'idm-api':'access/idm-api/ipallowlists',
    
}
const ISORT = function(a,b){return a.localeCompare(b, undefined, {sensitivity: 'base'})}

Vue.prototype.localStorage = window.localStorage
Vue.use(KeenUI);

Vue.component('removable', {
    data: function(){
        return {
            loading: false
        }
    },
    props: ['action','args','value'],
    methods: {
        handler() {
            this.loading = true
            this.action(this.value, ...this.args).then(()=>{
                this.loading = false
            })
        }
    },
    template: `<div class="removable">{{value}} <ui-icon-button size="mini" type="secondary" icon="backspace" color="red" :loading="loading" @click="handler" title="Remove"></ui-icon-button></div>`
})

Vue.component('addable', {
    data: function(){
        return {
            value: "",
            loading: false,
            error: ""
        }
    },
    props: ['action','args','placeholder'],
    methods: {
        handler() {
            this.loading = true
            this.error = ""
            console.log(this.action)
            this.action(this.value, ...this.args).then(()=>{
                this.loading = false
                this.value = ""
            },reject=>{
                this.loading = false
                this.error = reject
            })
        }
    },
    template: `
    <div class="addable">
        <ui-textbox :placeholder="placeholder" v-model="value" :error="error" style="float:left;"></ui-textbox>
        <ui-icon-button size="mini" type="secondary" icon="add" color="green" :loading="loading" @click="handler" title="Add" style="float:left;"></ui-icon-button> {{error}}
    </div>
    `
})

Vue.component('saveable', {
    data: function(){
        return {
            loading: false,
            error: false,
            tooltip: ""
        }
    },
    props: ['action','args'],
    methods: {
        handler() {
            this.loading = true
            this.error = false
            this.tooltip = ""
            this.action(...this.args).then(()=>{
                this.loading = false
            },reject=>{
                this.loading = false
                this.error = true
                this.tooltip = reject.message
            })
        }
    },
    template: `<ui-icon-button icon="save" :color="error ? 'red' : 'primary'" :loading="loading" :tooltip="tooltip" @click="handler"></ui-icon-button>`
})

Vue.component('addport', {
    data: function(){
        return {
            reason: "",
            port: 0,
            subnets: "",
            loading: false,
            error: ""
        }
    },
    props: ['action','stack'],
    methods: {
        handler() {
            this.loading = true
            this.error = ""
            this.action(this.reason, this.port, this.subnets, this.stack).then(()=>{
                this.loading = false
                this.reason = ""
                this.port = 0
                this.subnets = ""
                this.error = ""
            },reject=>{
                this.loading = false
                this.error = reject
            })
        }
    },
    template: `
    <div class="addable flex">
        <ui-textbox class=".grow" v-model="reason">Reason</ui-textbox>
        <ui-textbox class=".grow" type="number" v-model:number="port" :min="1" :max="65535">Port</ui-textbox>
        <ui-textbox class=".grow" help="Comma seperated list of CIDR subnets" v-model="subnets" :error="error">Subnets</ui-textbox>
        <ui-icon-button size="mini" type="secondary" icon="add" color="green" :loading="loading" @click="handler" title="Add"></ui-icon-button>
    </div>
    `
})
const vue = new Vue({
    el: '#vue',
    data: {
        badrcm: null,
        context: {},
        config: {},
        setting_columns_option: "2",
        addstack_host: "",
        addstack_host_error: "",
        addstack_auth: "",
        addstack_auth_error: "",
        addstack_shared: true,
        valid_line: RegExp('^[^#=]+=[^=]+$'),
        SPLUNKD_PATH: `/${window.$C.LOCALE}/splunkd/__raw/servicesNS/${window.$C.USERNAME}`,
        acs_columns: Array.from({length:COLUMNS_MAX}, u => ({
            server: '',
            loading: 0,
        })),
        netin_data: {},
        netout_data: {},
        hec_data: {},
        idx_data: {},
        app_data: {},
        IDX_ICON: {'event':'article','metric':'analytics'},
        ACS_NETWORK_ENDPOINTS: ACS_NETWORK_ENDPOINTS
    },
    computed: {
        acs_servers_options(){
            return Object.keys(this.config)
        },
        setting_columns() {
            return Number(this.setting_columns_option)
        },
        setting_columns_options() {
            let start = 1
            let end = COLUMNS_MAX
            return [...Array(end-start+1).keys()].map(i => String(i + start));
        },
        active_columns(){
            return this.acs_columns.slice(0,this.setting_columns)
        },
        active_stacks(){
            return Array.from(new Set(this.active_columns.map(c => c.server).filter(c => c)))
        },
        idx_list(){
            return this.Aus(this.active_stacks.map(s => Object.keys(this.idx_data[s] || {})).flat())
        }
    },
    methods: {
        //
        // Add Server Tab
        //
        AddStack(){
            const values = {
                stack:this.addstack_host,
                token:this.addstack_auth,
                shared:this.addstack_shared
            }
            this.Request('addstack',values).then(resp => {
                console.log(resp)
                this.addstack_host = ""
                this.addstack_host_error = ""
                this.addstack_auth = ""
                this.addstack_auth_error = ""
                this.addstack_shared = true
                //return this.TabConfig() // Can likely do this locally
            },reject => {
                if(reject.cause == 401){
                    this.addstack_host_error = ""
                    this.addstack_auth_error = reject.message
                } else {
                    this.addstack_host_error = reject.message
                    this.addstack_auth_error = ""
                }
            })
        },
        //
        // NETIN Tab
        //
        NetInGet(c){
            console.log("NetInGet",c)
            if(!this.config.hasOwnProperty(c.server)) return Promise.resolve()
            if(!this.netin_data.hasOwnProperty(c.server)){
                this.$set(this.netin_data,c.server,{})
            }
            c.loading += 1
            return Promise.all(Object.entries(ACS_NETWORK_ENDPOINTS).map(z => {
                const [key,endpoint] = z
                if(this.netin_data[c.server].hasOwnProperty(key)) return Promise.resolve()
                return this.Request('get',{'stack':c.server,'endpoint':endpoint})
                .then(resp => {
                    this.$set(this.netin_data[c.server],key,resp.subnets)
                }, reject =>{
                    this.$set(this.netin_data[c.server],key,{})
                })
            }))
            .then(()=>{
                c.loading -= 1
            })
        },
        NetInRemove(value,stack,aspect,index){
            console.log("NetInRemove",value,stack,aspect)
            return this.Request('change',{'method':'DELETE', 'stack':stack, 'endpoint':ACS_NETWORK_ENDPOINTS[aspect], 'data':JSON.stringify({'subnets':[value]})}).then(()=>{
                this.$delete(this.netin_data[stack][aspect],index) //this.netin_data[stack][aspect].indexOf(value)
            },reject => {
                return Promise.reject(reject.message)
            })
        },
        NetInAdd(value,stack,aspect){
            console.log("NetInAdd",value,stack,aspect)
            return this.Request('change',{'method':'POST', 'stack':stack, 'endpoint':ACS_NETWORK_ENDPOINTS[aspect], 'data':JSON.stringify({'subnets':[value]})}).then(()=>{
                this.netin_data[stack][aspect].push(value)
            },reject => {
                return Promise.reject(reject.message)
            })
        },
        //
        // NETOUT Tab
        //
        NetOutGet(c){
            console.log("NetOutGet",c)
            if(!this.config.hasOwnProperty(c.server)) return Promise.resolve()
            if(!this.netout_data.hasOwnProperty(c.server)){
                this.$set(this.netout_data,c.server,{})
            }
            c.loading += 1
            return this.Request('get',{'stack':c.server,'endpoint':'access/outbound-ports'})
            .then(resp => {
                this.$set(this.netout_data,c.server,resp)
                c.loading -= 1
            }, reject => {
                this.$set(this.netout_data,c.server,[])
                c.loading -= 1
            })
        },
        NetOutRemove(value,stack,port,x,y){
            console.log("NetOutRemove",port,value,stack)
            return this.Request('change',{'method':'DELETE', 'stack':stack, 'endpoint':`access/outbound-ports/${port}`, 'data':JSON.stringify({'subnets':[value]})}).then(()=>{
                if(this.netout_data[stack][x].subnets.length > 1){
                    this.$delete(this.netout_data[stack][x].destinationRanges,u)
                } else {
                    this.$delete(this.netout_data[stack],x)
                }
            },reject => {
                return Promise.reject(reject.message)
            })
        },
        NetOutAdd(reason,port,subnets,stack){
            console.log("NetOutAdd",reason,port,subnets,stack)
            subnets = subnets.split(',').map(s => s.trim())
            const payload = {
                'outboundPorts': [{
                    'port': Number(port),
                    'subnets': subnets
                }],
                'reason': reason
            }
            return this.Request('change',{'method':'POST', 'stack':stack, 'endpoint':'access/outbound-ports', 'data':JSON.stringify(payload)}).then(()=>{
                this.netout_data[stack].push({
                    "destinationRanges": subnets,
                    "name": port,
                    "port": port
                })
            },reject => {
                return Promise.reject(reject.message)
            })
        },
        //
        // HEC
        //
        HecGet(c){
            if(!this.config.hasOwnProperty(c.server)) return Promise.resolve()
            if(this.hec_data.hasOwnProperty(c.server)) return Promise.resolve()

            c.loading += 1
            
            return Promise.all([ // HEC also needs the index list, so grab that first
                this.Request('get',{'stack':c.server,'endpoint':'inputs/http-event-collectors'}),
                this.IdxGet(c)
            ])
            .then(resp => {
                const data = resp[0]['http-event-collectors'].reduce((x,a)=>{
                    x[a.token] = a.spec
                    return x
                },{})
                this.$set(this.hec_data,c.server,data)
                c.loading -= 1
            }, reject => {
                this.$set(this.hec_data,c.server,null)
                c.loading -= 1
            })
        },
        HecAdd(token,stack){
            const payload = {
                'name': `New Token created by BADACS (${Math.floor(Math.random() * 1000)})`,
                'token': token == "" ? null : token
            }
            return this.Request('change',{'stack':stack, 'method':'POST', 'endpoint':'inputs/http-event-collectors', 'data':JSON.stringify(payload)}).then((resp)=>{
                console.log(data)
                this.$set(this.hec_data[stack],token,resp["http-event-collector"]["spec"])
            },reject => {
                return Promise.reject(reject.message)
            })
        },
        HecChange(stack,hec){
            return this.Request('change',{'stack':stack, 'method':'PUT', 'endpoint':`inputs/http-event-collectors/${hec.name}`, data: JSON.stringify(hec)})
        },
        //
        // Indexes
        //
        IdxGet(c){
            console.log("IdxGet",c)
            if(!this.config.hasOwnProperty(c.server)) return Promise.resolve()
            if(this.idx_data.hasOwnProperty(c.server)) return Promise.resolve()
            c.loading += 1
            
            return this.Request('get',{'stack':c.server,'endpoint':'indexes'})
            .then(resp => {
                console.log("good",resp)
                const data = resp.reduce((x,a)=>{
                    x[a.name] = a
                    return x
                },{})
                this.$set(this.idx_data,c.server,data)
                c.loading -= 1
            }, reject => {
                console.log("bad",reject)
                this.$set(this.idx_data,c.server,null)
                c.loading -= 1
            })
        },
        IdxAdd(name,stack){
            const payload = {
                'name': name,
                'datatype': 'event'
            }
            return this.Request('change',{'stack':stack, 'method':'POST', 'endpoint':'indexes', 'data':JSON.stringify(payload)}).then((resp)=>{
                console.log(resp)
                this.$set(this.idx_data[stack],name,resp)
            },reject => {
                return Promise.reject(reject.message)
            })
        },
        IdxChange(stack,idx){
            return this.Request('change',{'stack':stack, 'method':'PATCH', 'endpoint':`indexes/${idx.name}`, data: JSON.stringify({'searchableDays': idx.searchableDays, 'maxDataSizeMB': idx.maxDataSizeMB})})
        },
        //
        // Generic Helpers
        //
        Afus(a){ //Arrays Flat Unique Sorted 
            return Array.from(new Set(a.flat())).sort() // Remove .flat() eventually
        },
        Aus(a){ //Arrays Unique Sorted 
            return Array.from(new Set(a)).sort(ISORT)
        },
        Options(){
            return Array.from(new Set([...arguments].flat()))
        },
        Loading(e){
            console.log(e)
        },
        Request(action,data={}) {
            let form = new URLSearchParams()
            form.append('a', action)
            for (x in data){
                form.append(x, data[x])
            }

            console.log(form.toString())
            return fetch(REST_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-Splunk-Form-Key': CSRF,
                },
                body: form
            })
            .catch(e => {
                console.warn(e)
                this.$refs.errorbar.createSnackbar({
                    message: e.message
                });
                return Promise.reject({ cause: 'local', message: e.message });
            })
            .then(resp => {
                console.log(resp.status)
                json = resp.json().catch(e => {
                    console.warn(e)
                    return resp.text().catch(()=>{
                        return resp.reason
                    }).then(text => {
                        this.$refs.errorbar.createSnackbar({
                            message: text
                        });
                        return Promise.reject({ cause: 'parse', message: text });
                    })
                })
                if (resp.status <= 299) return json
                return json.then(data => {
                    console.warn(resp.status, data)
                    
                    this.$refs.errorbar.createSnackbar({
                        message: data.error ? `${data.message}. ${data.error}` : data.message
                    });
                    return Promise.reject({ cause: resp.status, message: data.message})
                })
            })
        },
        /*Request(action,data={}) {
            let form = new URLSearchParams()
            form.append('a', action)
            for (x in data){
                form.append(x, data[x])
            }
            console.log(form.toString())
            return fetch(`/${window.$C.LOCALE}/splunkd/__raw/services/badacs?output_mode=json`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-Splunk-Form-Key': CSRF,
                },
                body: form
            })
            .catch(e => {
                console.warn(e)
                return Promise.reject({ cause: 'local', message: e.message });
            })
            .then(resp => {
                console.log(resp.status)
                return resp.json().catch(e => {
                    console.error("JSON PARSE",e,resp)
                    return Promise.reject({ cause: 'parse', message: e.message });
                }).then(data=>{
                    console.log(resp.status)
                    if (resp.status >= 500){
                        console.error(resp.status, data.error, data.message)
                        return Promise.reject({ cause: resp.status, message: "There was a server error, please report this on GitHub", error: data.message})
                    } else if (resp.status >= 400){
                        console.warn(resp.status, data.error, data.message)
                        return Promise.reject({ cause: resp.status, message: data.message, error: data.error})
                    }
                    return data
                })
                
            })
        },*/
        GetChild(object, keys, def=false) {
            for (const key of keys){
                if (object.hasOwnProperty(key)){
                    object = object[key]
                } else return def
            }
            return object
        },
        TabChange(func){
            for (const c of this.acs_columns){
                if(c.server){
                    func(c)
                }
            }
        }
    },
    mounted() {
        if(localStorage.badacs_setting_columns){
            this.$set(this, 'setting_columns_option', localStorage.badacs_setting_columns)
        }
        this.Request('config').then(resp => {
            this.$set(this,'config',resp)
        },reject =>{
            console.error("FATAL ERROR - COULDNT GET CONFIG",reject)
        })

        // Check if BADRCM is installed
        fetch(`/${window.$C.LOCALE}/splunkd/__raw/services/badrcm`, {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-Splunk-Form-Key': CSRF,
            }
        }).catch(()=>{
            this.badrcm = false
        }).then(()=>{
            this.badrcm = true
        })
    },
    watch: {
        setting_columns_option(next,prev){
            localStorage.setItem('badacs_setting_columns', next)
        },
    }
})
