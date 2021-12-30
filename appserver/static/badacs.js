require([
	"splunkjs/mvc",
	"splunkjs/mvc/simplexml",
	"splunkjs/mvc/layoutview",
	"splunkjs/mvc/simplexml/dashboardview",
    "app/badacs/vue.min",
    "app/badacs/keen-ui.min",
], function(
	mvc,
	DashboardController,
	LayoutView,
	Dashboard,
    Vue,
    KeenUI,
) {
    Vue.prototype.localStorage = window.localStorage
    Vue.use(KeenUI);
    new Vue({
        el: '#vue',
        data: {
            config: {},
            servers: {},
            conf_data: {},
            conf_files: ['props', 'inputs', 'outputs', 'transforms', 'app', 'server', 'authentication', 'authorize', 'collections', 'commands', 'datamodels', 'eventtypes', 'fields', 'global-banner', 'health', 'indexes', 'limits', 'macros', 'passwords', 'savedsearches', 'serverclass', 'tags', 'web'],
            conf_setting_apps: [],
            conf_setting_files: ['props'],
            conf_setting_show: 'all',
            conf_columns: [{
                server: 'local',
                app: '-',
                user: 'nobody',
                loading: true
            }],
            newserver: {
                hosterror: '',
                autherror: '',
                host: "",
                auth: ""
            },
            line_valid: RegExp('^[^#=]+=[^=]+$')
        },
        computed: {
            conf_apps(){
                return ['-']
            }
        },
        methods: {
            Request(action,data={}) {
                let form = new URLSearchParams()
                form.append('a', action)
                for (x in data){
                    form.append(x, data[x])
                }
                return fetch('/en-GB/splunkd/__raw/services/badacs?output_mode=json', {
                    method: 'POST',
                    redirect: 'follow',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: form
                })
                .catch(e => {
                    console.warn(e)
                    return Promise.reject({ cause: 'host', message: e.message });
                })
                .then(resp => resp.json())
                .catch(e => {
                    console.warn(e)
                    return Promise.reject({ cause: 'parse', message: e.message });
                })
            },
            SafeObject(object, key) {
                if (!(key in object)) {
                    this.$set(object, key, {})
                }
                return object[key]
            },
            AddServer(){
                return
            }
        },
        mounted() {
            this.Request('config').then(resp => {
                console.log(resp)
                this.$set(this,'config',resp['config'])
            })
        },
        watch: {

        }
    })
})