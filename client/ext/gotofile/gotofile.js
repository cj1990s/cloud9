/**
 * Code Editor for the Cloud9 IDE
 *
 * @copyright 2010, Ajax.org B.V.
 * @license GPLv3 <http://www.gnu.org/licenses/gpl.txt>
 */

define(function(require, exports, module) {

var ide = require("core/ide");
var ext = require("core/ext");
var editors = require("ext/editors/editors");
var markup = require("text!ext/gotofile/gotofile.xml");

module.exports = ext.register("ext/gotofile/gotofile", {
    name    : "Go To File",
    dev     : "Ajax.org",
    alone   : true,
    offline : false,
    type    : ext.GENERAL,
    markup  : markup,
    offline : false,
    commands : {
        "refresh": {hint: "Reload Cloud9 IDE"},
        "gotofile": {hint: "search for a filename and jump to it"}
    },
    hotitems: {},

    dirty   : true,
    nodes   : [],

    hook : function(){
        var _self = this;

        this.nodes.push(
            mnuFile.insertBefore(new apf.item({
                caption : "Open...",
                onclick : function() {
                    _self.toggleDialog(1);
                }
            }), mnuFile.firstChild),

            ide.barTools.appendChild(new apf.button({
                id      : "btnOpen",
                icon    : "open.png",
                width   : 29,
                tooltip : "Open...",
                skin    : "c9-toolbarbutton",
                onclick : function() {
                    _self.toggleDialog(1);
                }
            })),
            
            this.model = new apf.model(),
            this.modelCache = new apf.model()
        );
                
        ide.addEventListener("init.ext/editors/editors", function(){
            _self.markupInsertionPoint = tabEditors;
            //tabEditors.appendChild(winGoToFile);
        });
        
        ide.addEventListener("extload", function(){
            _self.updateFileCache();
        });

        this.hotitems["gotofile"] = [this.nodes[0]];
    },

    init : function() {
        var _self = this;
        
        winGoToFile.addEventListener("prop.visible", function(e){
            if (e.value) {
                txtGoToFile.select();
                txtGoToFile.focus();
                _self.dirty = true;
            }
        });
        
        txtGoToFile.addEventListener("keydown", function(e){
            if (e.keyCode == 27)
                _self.toggleDialog(-1);
            
            else if (e.keyCode == 13){
                _self.openFile();

                ide.dispatchEvent("track_action", {type: "gotofile"});
                return false;
            }
            else if (e.keyCode == 38 && dgGoToFile.viewport.length) {
                if (dgGoToFile.selected == dgGoToFile.$cachedTraverseList[0])
                    return;
                
                var prev = dgGoToFile.getNextTraverseSelected(dgGoToFile.selected, false);
                if (prev) {
                    dgGoToFile.select(prev, e.ctrlKey, e.shiftKey);
                    dgGoToFile.focus();
                }
            }
            else if (e.keyCode == 40 && dgGoToFile.viewport.length) {
                var next = dgGoToFile.getNextTraverseSelected(dgGoToFile.selected);
                if (next) {
                    dgGoToFile.select(next, e.ctrlKey, e.shiftKey);
                    dgGoToFile.focus();
                }
            }
        });
        
        txtGoToFile.addEventListener("afterchange", function(e){
            _self.filter(txtGoToFile.value);
            
            if (_self.dirty && txtGoToFile.value.length > 0) {
                _self.dirty = false;
                _self.updateFileCache();
            }
        });
        
        dgGoToFile.addEventListener("keydown", function(e) {
            if (e.keyCode == 27)
                _self.toggleDialog(-1);
            else if (e.keyCode == 38 && !e.shiftKey) {
                if (this.selected == this.$cachedTraverseList[0])
                    txtGoToFile.focus();
            }
            else if (e.keyCode == 13) {
                _self.openFile();
                return false;
            }
            else if (apf.isCharacter(e.keyCode)) {
                txtGoToFile.focus();
            }
        }, true);

        apf.addListener(dgGoToFile.$ext, "mouseup", function(e) {
            _self.openFile();
        });
        
        winGoToFile.addEventListener("blur", function(e){
            if (winGoToFile.visible && !apf.isChildOf(winGoToFile, e.toElement))
                _self.toggleDialog(-1);
        });
        txtGoToFile.addEventListener("blur", function(e){
            if (self.winGoToFile && winGoToFile.visible 
              && !apf.isChildOf(winGoToFile, e.toElement))
                _self.toggleDialog(-1);
        });
        
        ide.addEventListener("closepopup", function(e){
            if (e.element != _self)
                _self.toggleDialog(-1, true);
        });
        
        this.nodes.push(winGoToFile);
    },
    
    updateFileCache : function(){
        var _self = this;

        //@todo create an allfiles plugin that plugins like gotofile can depend on
        davProject.report(ide.davPrefix, 'filesearch', {query: ""}, //@todo filelist needs some fixing
          function(data, state, extra){
            if (state == apf.ERROR) {
                if (data && data.indexOf("jsDAV_Exception_FileNotFound") > -1) {
                    return;
                }

                //@todo
                return;
            }
            if (state == apf.TIMEOUT)
                return; //@todo

            /**
             * Putting this in a worker won't help
             * An alternative solution would be to do this in parts of 10ms
             */
            var re = new RegExp("(\\.gz|\\.bzr|\\.cdv|\\.dep|\\.dot|\\.nib|\\.plst|_darcs|_sgbak|autom4te\\.cache|cover_db|_build|\\.tmp)$|\/(\\.git|\\.hg|\\.pc|\\.svn|blib|CVS|RCS|SCCS|\.DS_Store)(?:\/|$)");
            var pNode = data.firstChild;
            var node  = pNode.lastChild, lnode;
            var array = [], name;
            while (node) {
                if (re.test(name = node.firstChild.nodeValue)) {
                    node = (lnode = node).previousSibling;
                    pNode.removeChild(lnode);
                }
                else {
                    node = node.previousSibling;
                    array.push(name);
                }
            }

            _self.arrayCache = array;
            _self.modelCache.load(data);
            
            if (self.winGoToFile && winGoToFile.visible) {
                var search = _self.lastSearch;
                _self.lastSearch = null; //invalidate cache
                _self.filter(search);
            }
            else
                _self.model.load(_self.modelCache.data);
        });
    },
    
    /**
     * Searches through the dataset
     * 
     * @todo There is much more sorting we can do. This function is now fast
     *       enough to apply weighed searching. 
     * 
     */
    filter : function(keyword){
        var klen = keyword.length;
        
        if (!keyword)
            data = this.modelCache.data.cloneNode(true);
        else {
            var nodes, data;
            
            // Optimization reusing smaller result if possible
            if (keyword.indexOf(this.lastSearch) > -1)
                nodes = this.arrayCacheLastSearch;
            else
                nodes = this.arrayCache;
            
            var name, res = [], first = [], second = [], third = [], cache = [];
            for (var i = 0, l = nodes.length, j, k, q; i < l; i++) {
                name = nodes[i];
                
                // We only add items that have the keyword in it's path
                if ((j = name.lastIndexOf(keyword)) > -1) {
                    
                    cache.push(name);
                    
                    // We prioritize ones that have the name in the filename
                    if (klen > 1 && j > (q = name.lastIndexOf("/"))) {
                        k = name.lastIndexOf("/" + keyword);
                        
                        if (k > -1) {
                            // We give first prio to full filename matches
                            if (name.length == klen + 1 + k) {
                                first.push(name);
                                continue;
                            }
                            
                            // Then to matches from the start of the filename
                            else if (k == q) {
                                second.push(name);
                                continue;
                            }
                            
                            // Then anywhere in the filename
                            else {
                                third.push(name);
                                continue;
                            }
                        }
                    }
                    
                    // Then the rest
                    res.push(name);
                }
            }

            var start = "<d:href>";
            var end   = "</d:href>";
            var glue  = end + start;
            var results = cache.length 
                ? (first.length ? start + first.join(glue) + end : "")
                  + (second.length ? start + second.join(glue) + end : "")
                  + (third.length ? start + third.join(glue) + end : "")
                  + (res.length ? start + res.join(glue) + end : "")
                : "";
            data = apf.getXml("<d:multistatus  xmlns:d='DAV:'><d:response>"
                + results + "</d:response></d:multistatus>");

            this.arrayCacheLastSearch = cache;
        }
        
        this.lastSearch = keyword;
        
        this.model.load(data);
        
        // See if there are open files that match the search results
        // and the first if in the displayed results
        
        var pages = tabEditors.getPages(), hash = {};
        for (var i = pages.length - 1; i >= 0; i--) {
            hash[pages[i].id] = true;
        }
        
        var nodes = dgGoToFile.getTraverseNodes();
        for (var i = Math.max(dgGoToFile.viewport.limit - 3, nodes.length - 1); i >= 0; i--) {
            if (hash[ide.davPrefix + nodes[i].firstChild.nodeValue]) {
                dgGoToFile.select(nodes[i]);
                return;
            }
        }
        
        dgGoToFile.select(dgGoToFile.getFirstTraverseNode());
    },
    
    openFile: function(){
        var nodes = dgGoToFile.getSelection();
        
        if (nodes.length == 0)
            return false;
            
        _self.toggleDialog(-1);
        
        //txtGoToFile.change("");
        
        for (var i = 0; i < nodes.length; i++) {
            var path = ide.davPrefix.replace(/[\/]+$/, "") + "/" 
                + apf.getTextNode(nodes[i]).nodeValue.replace(/^[\/]+/, "");
            editors.showFile(path, 0, 0);
            ide.dispatchEvent("track_action", {type: "fileopen"});
        }
    },
    
    refresh : function(){
        location.reload();
    },

    gotofile : function(){
        this.toggleDialog();
        return false;
    },

    toggleDialog: function(force, noanim) {
        ext.initExtension(this);

        if (!force && !winGoToFile.visible || force > 0) {
            if (winGoToFile.visible)
                return;
            
            ide.dispatchEvent("closepopup", {element: this});
            
            winGoToFile.show();
            apf.setOpacity(winGoToFile.$ext, 1);
        }
        else if (self.winGoToFile && winGoToFile.visible) {
            if (!noanim) {
                winGoToFile.visible = false;
                
                //Animate
                apf.tween.single(winGoToFile, {
                    type     : "fade",
                    from     : 1,
                    to       : 0,
                    steps    : 5,
                    interval : 0,
                    control  : (this.control = {}),
                    onfinish : function(){
                        winGoToFile.visible = true;
                        winGoToFile.hide();
                    }
                });
            }
            else {
                winGoToFile.hide();
            }
        }

        return false;
    },

    enable : function(){
        this.nodes.each(function(item){
            if (item.enable)
                item.enable();
        });
    },

    disable : function(){
        this.nodes.each(function(item){
            if (item.disable)
                item.disable();
        });
    },

    destroy : function(){
        this.nodes.each(function(item){
            item.destroy(true, true);
        });
        winGoToFile.destroy(true, true);
        this.nodes = [];
    }
});

});