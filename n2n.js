
module.exports = function(RED) {
    "use strict";

    var passPhrase = "";
    //passPhrase = "bananaisnotaverystrongpassword";
    var algorithm = "aes-256-cbc-hmac-sha256";

    var dgram = require('dgram');
    var msgpack = require('msgpack-lite');
    var crypto = require('crypto');
    var os = require("os");
    //console.log(crypto.getCiphers())

    function sizes(cipher) {
        for (let nkey = 1, niv = 0;;) {
            try {
                crypto.createCipheriv(cipher, '.'.repeat(nkey), '.'.repeat(niv));
                return [nkey, niv];
            } catch (e) {
                if (/invalid iv length/i.test(e.message)) { niv += 1; }
                else if (/invalid key length/i.test(e.message)) { nkey += 1; }
                else { throw e; }
            }
        }
    }

    function computeKey(cipher, passphrase) {
        let [nkey, niv] = sizes(cipher);
        for (let key = '', iv = '', p = '';;) {
            const h = crypto.createHash('md5');
            h.update(p, 'hex');
            h.update(passphrase);
            p = h.digest('hex');
            let n, i = 0;
            n = Math.min(p.length-i, 2*nkey);
            nkey -= n/2;
            key += p.slice(i, i+n);
            i += n;
            n = Math.min(p.length-i, 2*niv);
            niv -= n/2;
            iv += p.slice(i, i+n);
            i += n;
            if (nkey+niv === 0) { return [key, iv]; }
        }
    }

    var key;
    if (passPhrase !== "") {
        let [key, iv] = computeKey(algorithm, passPhrase);
        key = key.slice(0, 32);
        iv = iv.slice(0, 16);
    }

    var sock = null;
    var links = {};
    var requests = {};
    var rates = {};
    var wants = [];
    var wantrates = [];
    var lno = 0;
    var port = 61880;
    var addr = "225.0.18.80";
    var ignore = false;                 // ignore our own messages
    var host = os.hostname();
    var tick = 20 * 1000;               // say hello every... milliseconds
    var agelimit = tick * 3 / 1000;     // check for not seen after 3 x check interval
    var viz = false;                    // gather data for visualisations

    var initSock = function(node) {
        node.log("You may need to unblock your firewall for this node to work...");
        node.log("e.g.  iptables -I INPUT 1 -p udp --dport 61880 -j ACCEPT");
        //console.log(os.networkInterfaces());
        if (node.iface) {
            //console.log(os.networkInterfaces());
            if (os.networkInterfaces().hasOwnProperty(node.iface)) {
                var osif = os.networkInterfaces()[node.iface];
                node.ifip = undefined;
                for (var i in osif) {
                    if (osif[i].family === "IPv4") {
                        node.ifip = os.networkInterfaces()[node.iface][i].address;
                    }
                }
                if (node.ifip !== undefined) { node.log("Using " + node.iface + " : " + node.ifip); }
                else { node.warn("Interface " + node.iface + " is not using IPV4"); }
            } else {
                node.warn("Interface " + node.iface + " not online/available.");
            }
        }
        if (node.ifip === undefined) { node.ifip = null; }
        if (sock === null) {
            node.status({fill:"grey",shape:"dot",text:"Master"});
            sock = dgram.createSocket('udp4');  // only use ipv4 for now
            sock.setMaxListeners(0);            // Allow loads of listeners just in case
            if (node.bcast) { node.ifip = "255.255.255.255";}
            sock.bind(port, node.ifip, function() {        // have to bind before you can enable broadcast...
                sock.setBroadcast(true);        // turn on broadcast
                if (!node.bcast) {
                    try {
                        sock.addMembership(addr, node.ifip);  // Add to the multicast group
                        sock.setMulticastTTL(4);              // set TTL to 4
                        //sock.setMulticastLoopback(true);      // turn on loopback
                    } catch (e) {
                        if (e.errno == "EINVAL") {
                            node.error("Bad Multicast Address");
                        } else if (e.errno == "ENODEV") {
                            node.warn("No network device available");
                        } else {
                            node.error("Error :" + e.errno);
                        }
                        sock.close();
                        sock = null;
                        node.tsock = setTimeout(function() { initSock(node); }, tick);
                    }
                }
            });

            sock.on("listening", function() {
                node.log('RDY ' + addr + ":" + port);
                if (sock) {
                    if (ignore === true) {
                        node.log("Loopback off");             // turn off loopback
                        sock.setMulticastLoopback(false);
                    } else {
                        node.log("Loopback on");             // turn on loopback
                        sock.setMulticastLoopback(true);
                    }
                } else { node.log("socket not valid"); }
            });

            sock.on("error", function(err) {
                if ((err.code == "EACCES") && (port < 1024)) {
                    node.error("UDP access error, you may need root access for ports below 1024");
                } else if (err.code == "EADDRINUSE") {
                    node.error("UDP access error, Port " + port + " already in use");
                } else {
                    node.error("UDP error : " + err.code);
                }
                sock.close();
                sock = null;
                node.tsock = setTimeout(function() { initSock(node); }, tick);
            });

            sock.on('message', function(message, remote) {
                if (key) {
                    //decode
                    console.log("KK",key.length,iv.length,typeof message,message.length,message.toString('hex'));
                    var decipher = crypto.createDecipheriv(algorithm, key, iv);
                    message = Buffer.concat([decipher.update(message) , decipher.final()]);
                    console.log(message.length, message.toString('hex'));
                }
                //var data = JSON.parse(message.toString()); // for use without msgpack
                try {
                    var data = msgpack.decode(message);
                    if (data.hasOwnProperty("w")) {     // it's a hello message as it has "wants"
                        links[remote.address] = data;
                        links[remote.address].lastseen = Date.now();
                        if (!data.hasOwnProperty("l")) { links[remote.address].l = 60; }
                        if (!data.hasOwnProperty("r")) { links[remote.address].r = 0; }
                        requests[data.h] = data.w;
                        rates[data.h] = data.r;
                        lno = Object.keys(links).length;
                        if (RED.settings.verbose) { console.log("R-HLO " + JSON.stringify(data)); }
                        //if (RED.settings.verbose) { console.log("R-HLO " + data.h + " " + data.w + " " + data.r + " " + data.l); }
                        if (viz) { RED.settings.functionGlobalContext.discoOut = links; }
                    }
                    else {
                        if (RED.settings.verbose) { console.log("R-DAT",data); }
                    }
                }
                catch (e) {
                    if (RED.settings.verbose) { console.log("R-BAD", e); }
                }
            });

            // Send Hello Message
            // h = host = hostname of requesting device
            // w = wants = topics wanted by the requesting device
            // l = agelimit = how many seconds before you can call me dead...
            // r = rate = no of seconds between messages you send me
            var sendHello = function() {
                if (wants.length > 0) {  // Only ask for stuff is we need it. (can still send to others)
                    //var message = new Buffer(JSON.stringify({ h:host, w:wants, l:agelimit})); // for use without msgpack
                    var message = msgpack.encode({h:host, w:wants, r:wantrates, l:agelimit});
                    if (key) {
                        //encode (also add to msg send)
                        //console.log(message.length, message.toString('hex'));
                        var cipher = crypto.createCipheriv(algorithm, key, iv);
                        message = Buffer.concat([cipher.update(message),cipher.final()]);
                        //console.log(message.length, message.toString('hex'));
                    }
                    sock.send(message, 0, message.length, port, addr, function(err, bytes) {
                        if (err) { node.error("ANE " + err); }
                        else { if (RED.settings.verbose) { console.log("T-ANN " + JSON.stringify({h:host, w:wants, r:wantrates, l:agelimit})); } }
                        message = null;
                    });
                }
            }

            var hoop = function(t) {
                node.hout = setTimeout(function() {
                    if (sock) { sendHello(); }
                    hoop(tick);   // so we can adjust this on the fly
                }, t);
            }
            hoop(2000); // kick off announcements fairly quick

        } else {
            node.warn("Socket not open");
        }

        var cleanUp = function() {
            // Remove links not seen within agelimit - limit is set by requesting end
            for (var n in links) {
                //console.log("S-TTL "+links[n].h+" "+parseInt(((links[n].lastseen + (links[n].l * 1000)) - Date.now())/1000));
                if (Date.now() > (links[n].lastseen + (links[n].l * 1000))) {
                    if (RED.settings.verbose) { console.log("S-BYE " + links[n].h + " " + links[n].w); }
                    //node.status({text:"l:"+links[n].h});
                    delete requests[links[n].h];
                    delete rates[links[n].h]
                    delete links[n];
                    lno = Object.keys(links).length;
                    if (viz) { RED.settings.functionGlobalContext.discoOut = links; }
                    //node.status({fill:(lno === 0 ? "blue" : "yellow"), shape:"dot", text:lno+" link"+(lno === 1 ? "" : "s")});
                }
            }
        }

        var loop = function(t) {
            node.tout = setTimeout(function() {
                cleanUp();
                loop(tick);   // we can adjust this on the fly
            }, t);
        }
        loop(tick); // kick off after "tick" secs

        node.on("close", function(done) {
            node.status({});
            if (node.tout) { clearTimeout(node.tout); }
            if (node.hout) { clearTimeout(node.hout); }
            if (node.tsock) { clearTimeout(node.tsock); }
            if (sock) {
                try {
                    sock.close();
                    sock = null;
                    node.log("discovery stopped");
                    done();
                } catch (err) {
                    sock = null;
                    node.error(err);
                    done();
                }
            }
            wants = [];
            wantrates = [];
        });
    }


    function N2nInNode(n) {
        RED.nodes.createNode(this, n);
        this.iface = n.iface || null;
        this.want = n.topic;
        this.rate = Number(n.rate || 0);
        this.bcast = n.bcast || false;
        wants.push(this.want);
        wantrates.push(this.rate);
        if (n.ignore === false) { ignore = false; }
        var node = this;
        var got = {};
        var linksin = {};
        //var useKey = "bananaflimflam";

        node.log("ASK [ " + node.want + " ]");

        setTimeout(function() {
            if (sock === null) { initSock(node); }  // create socket if out node not already done so

            sock.on('message', function(message, remote) {
                if (key) {
                    //decode
                    var decipher = crypto.createDecipheriv(algorithm, key, iv);
                    message = Buffer.concat([decipher.update(message) , decipher.final()]);
                    //console.log(message.length, message.toString('hex'));
                }
                //var data = JSON.parse(message.toString()); // for use without msgpack
                try {
                    var data = msgpack.decode(message);
                    //if (RED.settings.verbose) { console.log("R-DAT", data); }
                    if (data.hasOwnProperty("w")) {     // it's a hello message as it has "wants" - so ignore it
                    }
                    else {  // Anything else is a real message...
                        //console.log(data.t,w,node.wants[w]);
                        var re = new RegExp(node.want);
                        if (re.test(data.t)) { // And it's for me
                            if (!linksin.hasOwnProperty(remote.address)) {
                                linksin[remote.address] = {};
                                linksin[remote.address].h = data.h;
                                node.links = Object.keys(linksin).length;
                                got[data.h] = got[data.h] || {};
                                if (viz) {
                                    RED.settings.functionGlobalContext.discoIn = linksin;
                                    node.status({text:"+:"+data.h});
                                }
                            }
                            linksin[remote.address].lastseen = Date.now();

                            //if (RED.settings.verbose) { console.log("R-GOT " + data.h + " " + data.t + " " + JSON.stringify(data.p)); }
                            if (Date.now() >= (got[data.h][data.t] || 0) + (node.rate * 1000)) {
                                try { data.p = JSON.parse(data.p); }
                                catch(e) {}
                                node.send({payload:data.p, topic:data.t, host:data.h, hostip:remote.address}); // maybe ? hostip:remote.address
                                got[data.h][data.t] = Date.now();
                                node.status({fill:(node.links === 0 ? "blue" : "yellow"), shape:"dot", text:node.links + " source" + (node.links === 1 ? "" : "s")});
                            } else {
                                node.status({fill:(node.links === 0 ? "blue" : "yellow"), shape:"ring", text:node.links + " source" + (node.links === 1 ? "" : "s")});
                                if (RED.settings.verbose) { console.log("R-TOO SOON for RX", data.h, data.t, parseInt((got[data.h][data.t] + (node.rate * 1000) - Date.now()) / 1000) + "s"); }
                            }
                        }
                        //else {
                        //    if (RED.settings.verbose) { console.log("R-SAW " + util.inspect(data, {depth:10})); }
                        //}
                    }
                }
                catch (e) {
                    if (RED.settings.verbose) { console.log("R-BAD", e); }
                }
            });
        }, 500);

        var cleanup = function(evt) {
            // Remove incoming links not seen for a while (set by agelimit = 3*20s)
            for (var m in linksin) {
                if (linksin.hasOwnProperty(m)) {
                    //console.log("R-TTL "+linksin[m].h+" "+parseInt(linksin[m].lastseen + agelimit));
                    if (Date.now() > (linksin[m].lastseen + (agelimit * 1000))) {
                        if (RED.settings.verbose) { console.log("R-BYE " + m + " : " + linksin[m].h); }
                        delete got[linksin[m].h];
                        delete linksin[m];
                        if (viz) {
                            RED.settings.functionGlobalContext.discoIn = linksin;
                            node.status({text:"-:"+linksin[m].h});
                        }
                        node.links = Object.keys(linksin).length;
                        node.status({fill:(node.links === 0 ? "blue" : "yellow"), shape:"dot", text:node.links+" source"+(node.links === 1 ? "" : "s")});
                    }
                }
            }
        };

        var loopc = function(t) {
            node.toutc = setTimeout(function() {
                cleanup();
                loopc(tick);   // we can adjust this on the fly
            }, t);
        }
        loopc(tick); // kick off after "tick" secs

        node.on("close", function() {
            if (node.toutc) { clearTimeout(node.toutc); }
            node.status({});
        });

    }
    RED.nodes.registerType("n2n in", N2nInNode);


    function N2nOutNode(n) {
        RED.nodes.createNode(this, n);
        this.iface = n.iface || null;
        this.bcast = n.bcast || false;
        var node = this;
        var sent = {};
        //var useKey = "bananaflimflam";

        // Delay start to allow any in nodes to start first (seems to work better that way)
        //setTimeout(function() {
        if (sock === null) { initSock(node); }  // create socket if in node not already done so
        //}, 500);

        // Send Data messages to other links here
        // h = host = hostname of requesting device
        // t = topic = topics of message
        // p = payload = content on message
        node.on("input", function(msg) {
            if (msg.hasOwnProperty("want")) {
                wants.push(msg.want);
                node.log("ASK2 [ " + msg.want + " ]");
            }
            lno = Object.keys(links).length;
            if (msg.hasOwnProperty("payload") && (lno > 0) && sock) {    // only try to send if we have a link to someone and socket exists
                if (!msg.hasOwnProperty("topic")) { msg.topic = "public"; } // set a default topic if one doesn't exist
                if (msg.topic.length === 0) { msg.topic = "public"; } // set a default topic if one doesn't exist
                //if (RED.settings.verbose) { console.log("T-REQS",requests); }
                //console.log("T-RATS",rates);
                loopt:
                for (var r in requests) {
                    if (requests.hasOwnProperty(r)) {
                        for (var x in requests[r]) {
                            if (requests[r].hasOwnProperty(x)) {
                                var re = new RegExp(requests[r][x]);
                                if (re.test(msg.topic)) {
                                    //var message = new Buffer(JSON.stringify({ h:host, t:msg.topic, p:msg.payload })); // for use without msgpack
                                    var message = msgpack.encode({ h:host, t:msg.topic, p:msg.payload });
                                    if (key) {
                                        //encoder
                                        //console.log(message.length, message.toString('hex'));
                                        var cipher = crypto.createCipheriv(algorithm, key, iv);
                                        message = Buffer.concat([cipher.update(message),cipher.final()]);
                                        console.log("T",message.length, message.toString('hex'));
                                    }
                                    var rate = 9999999;
                                    for (var key in rates) {
                                        if (rates.hasOwnProperty(key) && rates[key].hasOwnProperty(x)) {
                                            if (rates[key][x] < rate) { rate = rates[key][x]; }
                                        }
                                    }
                                    if (rate === 9999999) { rate = 0; }
                                    //if (RED.settings.verbose) { console.log("RATE ",rate); }
                                    if (Date.now() >= (sent[msg.topic] || 0) + rate*1000) {
                                        sock.send(message, 0, message.length, port, addr, function(err, bytes) {
                                            if (err) { node.error("MER " + err); }
                                            //else { if (RED.settings.verbose) { console.log("T-MSG " + msg.topic + " : " + msg.payload.toString()); } }
                                            message = null;
                                        });
                                        sent[msg.topic] = Date.now();
                                        node.status({fill:"yellow", shape:"dot", text:lno + " : " + message.length + " bytes"});
                                    } else {
                                        node.status({fill:"yellow", shape:"ring", text:lno + " : " + message.length + " bytes"});
                                        if (RED.settings.verbose) { console.log("T-TOO SOON for TX", msg.topic, parseInt((sent[msg.topic] + rate - Date.now()) / 1000) + "s"); }
                                    }
                                    break loopt;
                                }
                                else {
                                    //node.status({});
                                }
                            }
                        }
                    }
                }
            }
        });

        node.on("close", function() {
            node.status({});
        });

    }
    RED.nodes.registerType("n2n out", N2nOutNode);

    RED.httpAdmin.get("/mcastinterfaces", RED.auth.needsPermission('n2n.read'), function(req,res) {
        var osif = os.networkInterfaces();
        var ports = [];
        for (var key in osif) {
            if (osif.hasOwnProperty(key)) {
                if (key.indexOf("lo") === -1) {
                    ports.push(key);
                }
            }
        }
        res.json(ports);
    });
}
