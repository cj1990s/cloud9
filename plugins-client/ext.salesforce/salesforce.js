define(function(require, exports, module) {

var ext = require("core/ext");
var ide = require("core/ide");
var menus = require("ext/menus/menus");
var fs = require("ext/filesystem/filesystem");
var markup = require("text!ext/salesforce/salesforce.xml");
var Util = require("core/util");
//var sfhtml = require("text!ext/salesforce/salesforce.html");
var Save = require("ext/save/save");
var organization = require('ext/salesforce/SfdcOrganization');
var commands = require("ext/commands/commands");
//Just so I know where the test server is ran on computers I don't have it bookmarked
//http://ec2-23-22-63-218.compute-1.amazonaws.com:3131/

module.exports = ext.register("ext/salesforce/salesforce", {
    name    : "SalesForce",
    dev     : "SalesForce",
    alone   : true,
    type    : ext.GENERAL,
    markup  : markup,
    visible : true,
    nodes   : [],

    init: function(amlNode) {
        //innerSalesForce.$ext.innerHTML = sfhtml;
        organization.init(ide);
        
    },
    
    sendMessage : function(message) {
        var data = {
            command: "salesforce",
            msg: message
        };
        ide.send(data);
    },
    
    onMessage : function(e) {
        if (!e.message.type || e.message.type !== 'salesforce')
            return;

        console.log('------ Got a message from the server -----');
        console.log(e.message);
        if (e.message.subType && e.message.subType === 'authenticated') {
               var values = e.message.values;
               
               if (values) {
                   console.log(values);
                   organization.save(values);
                   sfdcInstanceUrl.setProperty('value', values.instanceUrl);
                   sfdcToken.setProperty('value', values.token);
               
                   sfdcStatus.$ext.innerHTML = "Authenticated";
               } else {
                   values = { token : '', instanceUrl : '' };
                   var error = e.message.error;
                   console.log(error);
                   sfdcStatus.$ext.innerHTML = "Error authenticating: "+error;
               }
               
        } else if (e.message.subType && e.message.subType === 'queryResults') {
            sfdcStatus.$ext.innerHTML = e.message.records;
            //I shouldn't get it from the UI element every time. I should get it fomr SfdcOrganizations
            this.createOrUpdateProjectDirectory(sfdcProjectName.value, e.message.records);
        } else if (e.message.subType && e.message.subType === 'compile') {
            if (this.currentEditor && e.message.error) {
               this.addErrorToEditor(e.message.error, this.currentEditor.acesession);
            }
        } else if (e.message.subType && e.message.subType === 'saved') {
            console.log('save finished: saving:'+this.saving+'; shouldSave:'+this.shouldSave);
            if (this.currentEditor && this.saving && !e.message.error) {
                console.log('Save successful');
                
                var _self = this;
                var page = this.currentEditor.$page;
                
                this.shouldSave = true;
                Save.quicksave(page, function() {
                    _self.shouldSave = false;
                    //stripws.enable();
                    //_self.setSaveButtonCaption(page);
                }, true);
            } else if (this.currentEditor && e.message.error) {
                this.addErrorToEditor(e.message.error, this.currentEditor.acesession);
            }
            //Need to remove the attribute otherwise Save will think it is saving
            var node = this.currentEditor.getNode();
            apf.xmldb.removeAttribute(node, "saving");
            this.saving = false;
        } else if (e.message.subType && e.message.subType === 'serverError') {
            //console.log('');
            console.log(error);
            errorWindow.show();
            var error = e.message.error;
            errorText.$ext.innerHTML = typeof error === 'string' ? error : error.message;
        } else if (e.message.subType && e.message.subType === 'finishedSyncing') {
            console.log('Finished syncing');
        }
    },

    addErrorToEditor : function(error, ace) {
         var line = 0;
        if (typeof error !== 'string') {
            if (error.name) {
                //If I need the name to get the class out of the tabs
            }
            if (error.extent || error.id) {
                //If I need the extent of id
            }
            if (error.line) {
                line = error.line;
            }
            if (error.problem) {
                error = error.problem;
            }
        }
        ace.setAnnotations([{
            row: line,
            column: 0, //can be undefined
            text: error,
            type: "error" // or "warning" or "info"
        }]);  
    },

    createOrUpdateProjectDirectory : function(name, classes) {
        console.log('Creating classes structure for '+name);
        fs.exists('cloud9/test', function(doesExist) {
            console.log(doesExist);
            /*
            fs.createFolder(name, null, false, function() {
                //console.log(classes);
                for (var i = 0; i < classes.length; i++) {
                    //console.log(classes[i]);
                    //var path = name+'/'+classes[i].Name;
                    //console.log(path);
                    fs.createFile(classes[i].Name);   
                }
            });
            */
        });
        fs.exists('test', function(doesExist) {
            console.log(doesExist);
        });
    },

    hook: function() {
        var _self = this;
        console.log('--------- Hook -----------');
        organization.hook(ide);
        ide.addEventListener("socketMessage", this.onMessage.bind(this));
        
        this.$onOpenFileFn = this.onOpenFile.bind(this);
        //this.$onCloseFileFn = this.onCloseFile.bind(this);
        //this.$onBeforeSaveWarning = this.onBeforeSaveWarning.bind(this);
        
        ide.addEventListener("afteropenfile", this.$onOpenFileFn);
        //ide.addEventListener("closefile", this.$onCloseFileFn);
        //ide.addEventListener("beforesavewarn", this.$onBeforeSaveWarning);
        
        ide.addEventListener('beforefilesave',  function(e) {
           // console.log('Before Save');
           // console.log(e.doc.getValue());
        //    console.log(e.doc.$page.caption);
//            if (doc.acesession && doc.acesession.getAnnotations()) {

            console.log('Before save: saving: '+_self.saving+'; shouldSave: '+_self.shouldSave);
            
            var doc = e.doc;
            if (_self.shouldSave) {
                return true;
            } else if (!_self.saving) { //Don't dave multiple times, especially with autosave
                var filename = doc.$page.caption;
                filename = filename.replace(/^\W*(\w*).*/, "$1");
                console.log('Saving ' + filename + '...');
                _self.saving = true;
                
                try {
                    //Errors are no longer valid, if we are going to save again
                    doc.acesession.clearAnnotations();
                    
                    //Need the UI to show the file is saving
                    var node = doc.getNode();
                    apf.xmldb.setAttribute(node, "saving", "1");
                    
                    var data = {
                        command: "salesforce",
                        type: 'save',
                        name : filename,//'MonitorAPIRequest', //TODO get the name from the file
                        body : e.doc.getValue()
                    };
                    ide.send(data);
                } catch (e) {
                    console.log('Error in before save handler!' + e);
                    _self.saving = false;
                }
            }
            return false;
        });
        menus.addItemByPath("Tools/~", new apf.divider());//, 1000000);
        menus.addItemByPath("Tools/SalesForce", new apf.item({}));
//            onclick: function() {
//                winSalesForce.show();
//                _self.loadOrganization();
//            }
//        }));//, 2000000);
        menus.addItemByPath("Tools/SalesForce/Organization Settings", new apf.item({
            onclick: function() {
                winSalesForce.show();
                _self.loadOrganization();
            }
        }));
        menus.addItemByPath("Tools/SalesForce/Refresh from server", new apf.item({
            onclick: function() {
                //winSalesForce.show();
                _self.syncClasses();
            }
        }));
        menus.addItemByPath("Tools/SalesForce/Search Methods", new apf.item({
            onclick: function() {
                searchMethods.show();
                _self.filterMethods();
            }
        }));
        
        
        commands.addCommand({
            name: "searchMethods",
            hint: "search apex methods in the project",
            bindKey: {mac: "Command-Shift-M", win: "Ctrl-Shift-M"},
            isAvailable : function(editor){
                return !!editor;
            },
            exec: function () {
                if (searchMethods.visible) {
                    searchMethods.close();
                } else {
                    searchMethods.show();
                    _self.filterMethods();
                }
            }
        });
        //, 2000000);
        
        //OrganizationSettings

        ext.initExtension(this);
    },
    
    methods : {},
    filterMethods : function(text) {
        //Get the methods
        
        //Genetate UI
        var ui = '<div id="classes">';
        for (var key in this.methods) {
            if (this.methods.hasOwnProperty(key)) {
                ui += '<div class="apexClass" style="padding: 5px"><b>'+key+'</b></div>';
                var ms = this.methods[key];
                for (var i = 0; i < ms.length; i++) {
                    ui += '<div class="method" style="padding: 5px; margin-left: 20px">'+ms[i]+'</div>';
                }
            }
        }
        ui += "</div>";
        methodOutput.$ext.innerHTML = ui;
    },
    
    docChangeTimeout: null,
    docChangeListeners: {},
    docBeforeSaveListeners: {},
    
    onOpenFile: function(data) {
        //console.log(data);
        if (!data || !data.doc)
            return;

        var self = this;
        var doc = data.doc;
        //console.log(doc);
        var page = doc.$page;
        //console.log(page);
        if (!page || !Util.pageIsCode(page)) {
            return;
        }

        // Add document change listeners to an array of functions so that we
        // can clean up on disable plugin.
        var path = Util.getDocPath(page);
        
        if (path && path.match(/\.st/)) {
            try {
                var st = JSON.parse(doc.getValue());
                var symbols = st.symbols;
                
                this.methods[st.name] = [];
                for (var i = 0; i < symbols.length; i++) {
                    var symbol = symbols[i];
                    if (symbol.kind === 'METHOD') {
                        this.methods[st.name].push(symbol.name);
                    }
                }
            } catch (e) {
                errorWindow.show();
                errorText.$ext.innerHTML = e;
            }
            return;
        }
        if (!path || !path.match(/\.apex$/)) {
            ext.enableExt("ext/language/language");
            ext.enableExt("ext/autosave/autosave");
            return;
        }

        ext.disableExt("ext/language/language");
        //ext.disableExt("ext/autosave/autosave");
        
        //doc.acesession.on('changeAnnotation', function() {
        //    return false;
        //});
        
        if (!this.docChangeListeners[path]) {
            this.docChangeListeners[path] = function(e) {
                self.onDocChange.call(self, e, doc);
            };
        }

        if (!Util.isNewPage(page)) {
            //console.log('Not a new page');
            //this.setSaveButtonCaption();
        }
        //console.log(doc.acedoc.eventRegistry.change[0]);
        (doc.acedoc || doc).addEventListener("change", this.docChangeListeners[path]);
        
    },
    
    onDocChange: function(e, doc) {
        var as = doc.acesession;
        /*
        console.log(as);
        //Test the annotations
        as.setAnnotations([{
            row: 1,
            column: 2, //can be undefined
            text: "Missing argument",
            type: "error" // or "warning" or "info"
        }]);
        */
        //Get the error from salesforce
        /*
        var data = {
            command: "salesforce",
            type: 'compile',
            name : 'MonitorAPIRequest',
            body : as.getValue()
        };
        ide.send(data);
        */
        this.currentEditor = doc;
        
        
        var page = doc.$page;
        if (page) {// && this.isAutoSaveEnabled && !Util.isNewPage(page)) {
            //console.log(page);
            /*
            clearTimeout(this.docChangeTimeout);
            this.docChangeTimeout = setTimeout(function(self) {
                self.setSaveButtonCaption();
                stripws.disable();
                self.save(page);
            }, CHANGE_TIMEOUT, this);
            */
        }
    },
    
    authenticateOrganization : function(values) {
        console.log('--------- Authenticate Organization -----------');
        sfdcStatus.$ext.innerHTML = "Authenticating...";
        
        /** TODO Call a server plugin to contact salesforce with the
         *      - ClientId
         *      - ClientSecret
         *      - RedirectUri //Need to surface this to the user
         *      - grant_type='password' (I can set this on the server side
         *      - username
         *      - password
         * 
         *  On call back, show auth token and instance url in the client code
        */
        
        var data = {
            command: "salesforce",
            type: 'authenticate',
            values : values
        };
        ide.send(data);
        

        
    },
    
    downloadLog : function() {
        var id = logId.value;
        console.log('Download Log : '+id);
        var data = {
            command: "salesforce",
            type: 'downloadLog',
            logId : id
            
            //values : values
        };
        ide.send(data);
    },

    syncClasses : function() {
        this.syncingProject = true;
         var data = {
            command: "salesforce",
            type: 'query',
            instance : sfdcInstanceUrl.value,
            token : sfdcToken.value//,
            
            //values : values
        };
        ide.send(data);
    },

    loadOrganization : function() {
        console.log('--------- Load into UI -----------');
        
        //TODO Need to change this to load any org settings into the given tab or row
        var orgs = organization.getAll();
        if (orgs.length == 2) {
            
            this.setOrgInUI(orgs[1]);
        }
    },
    
    /** Called from UI */
    saveOrganization : function() {
        var values = this.getOrgInUI();
        
        //If an org doesn't exist, create it. I should have a button to add an org and save an org...
        if (organization.has(values.name)) {
            organization.save(values);
        } else {
            organization.create(values);
        }
        
        //Authenticate when they save changes, but I could also add another button for it
        this.authenticateOrganization(values);
    },
    
    setOrgInUI : function(org) {
        sfdcProjectName.setProperty('value', org.getAttribute('name'));
        sfdcUserName.setProperty('value', org.getAttribute('username'));
        sfdcPassword.setProperty('value', org.getAttribute('password'));
        sfdcSecurityToken.setProperty('value', org.getAttribute('securityToken'));
        sfdcConsumerKey.setProperty('value', org.getAttribute('consumerKey'));
        sfdcConsumerSecret.setProperty('value', org.getAttribute('consumerSecret'));
        sfdcInstanceUrl.setProperty('value', org.getAttribute('instanceUrl'));
        sfdcToken.setProperty('value', org.getAttribute('token'));
    },
    
    getOrgInUI : function() {
        return {
            name : sfdcProjectName.value,
            username : sfdcUserName.value,
            password : sfdcPassword.value,
            securityToken : sfdcSecurityToken.value,
            consumerKey : sfdcConsumerKey.value,
            consumerSecret : sfdcConsumerSecret.value,
            instanceUrl : sfdcInstanceUrl.value,
            token : sfdcToken.value
        };
    },

    enable: function() {
        this.nodes.each(function(item) {
            item.enable();
        });
    },

    disable: function() {
        this.nodes.each(function(item) {
            item.disable();
        });
    },

    destroy: function() {
        this.nodes.each(function(item) {
            item.destroy(true, true);
        });
        this.nodes = [];
    }
});

});