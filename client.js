"use strict"
const colors = require('colors');
const process = require('process');
const config = require('./config.json');
const crypto = require('crypto');
const DESCrypto = require('./DESCrypto.js');

const ecdh = crypto.createECDH('secp521r1');
ecdh.generateKeys();

var DESKEY = "";
var RSAPubKey = "";
var socket = new require('ws')('ws://' + config.server_ip + ':' + config.server_port);

socket.on('open', function open() {
    console.log(colors.green("Websocket opened."));
    socket.send(JSON.stringify({ code: 100 }));
});

socket.on('message', function(data) {
    var incomingMessage = JSON.parse(data.toString('utf8'));
    switch (incomingMessage.code) {
        case 100:
            //获取服务器公钥
            RSAPubKey = new Buffer(incomingMessage.RSAPubKey, 'base64').toString('utf8');
            //获取客户端ECDH的PublicKey
            var ECDHClientPublicKey = ecdh.getPublicKey();
            //将客户端的ECDHClientPublicKey用RSA公钥加密
            socket.send(JSON.stringify({ code: 101, PublicKey: crypto.publicEncrypt(RSAPubKey, ECDHClientPublicKey).toString('base64'), timestamp: new Date().getTime() }));
            console.log(colors.green("Sended ECDHClientPublicKey: ") + ECDHClientPublicKey.toString('base64'));
            break;
        case 101:
            //解密服务器ECDH的PublicKey
            var ECDHServerPublicKey = crypto.publicDecrypt(RSAPubKey, new Buffer(incomingMessage.PublicKey, 'base64')).toString("base64");
            console.log(colors.green('Recive a ECDHServerPublicKey from server: ') + ECDHServerPublicKey);
            DESKEY = ecdh.computeSecret(ECDHServerPublicKey, 'base64', 'base64'); //获取DESKEY
            console.log(colors.green('Generator DESKEY: ') + DESKEY);
            socket.send(DESCrypto.Cipher({ code: 10, msg: "hello server", DESKEY: DESKEY }, DESKEY));
            break;
        case 102:
            var MessageDecipher = DESCrypto.Decipher(incomingMessage.data, DESKEY);
            var hash = MessageDecipher[1].hash;
            var data = MessageDecipher[0];
            if (crypto.createHash('sha512').update(JSON.stringify(data)).digest('base64') == hash) {
                console.log(colors.green("Verify hash success."));
                if (data.DESKEY == DESKEY) {
                    console.log(colors.green("Verify DESKEY success."));
                    switch (data.code) {
                        case 10:
                            console.log(colors.green("MSG from server: ") + data.msg);
                            // socket.send(MessageCipherfun({ code: 10, msg: "hello server", DESKEY: DESKEY }));
                            break;
                    }
                } else {
                    console.log(colors.green("Verify DESKEY success."));
                }
            } else {
                console.log(colors.green("Verify hash success."));
            }
            break;
    }
});

socket.on('close', function open() {
    console.log(colors.red("Websocket closed."));
    process.abort();
});
socket.on('error', function open() {
    console.log(colors.red("Websocket server error."));
});