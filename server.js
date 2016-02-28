"use strict";
const fs = require('fs');
const crypto = require('crypto');
const colors = require('colors');
const config = require('./config.json');
const DESCrypto = require('./DESCrypto.js');

const ecdh = crypto.createECDH('secp521r1');
ecdh.generateKeys();

const WebSocketServer = new require('ws').Server({ port: config.server_port });

const RSAPublicKey = fs.readFileSync('PublicKey.crt', 'base64');
const RSAPrivateKey = fs.readFileSync('PrivateKey.crt', 'utf8');

var DESKEY = "";

WebSocketServer.on('connection', function connection(socket) {
  socket.on('message', function incoming(data) {
    var incomingMessage = JSON.parse(data.toString('utf8'));
    switch (incomingMessage.code) {
    case 100:
      socket.send(JSON.stringify({ code: 100, RSAPubKey: RSAPublicKey })); //将公钥发送给客户端
      break;
    case 101:
      //解密客户端用RSA公钥加密的ECDH客户端公钥
      var ECDHClientPubKey = crypto.privateDecrypt(RSAPrivateKey, new Buffer(incomingMessage.PublicKey, 'base64')).toString("base64");
      console.log(colors.green("Receive ECDHClientPubKey from client: ") + ECDHClientPubKey);
      //获取服务器端ECDH的公钥
      var ECDHServerPublicKey = ecdh.getPublicKey();
      //将服务器端的ECDHServerPublicKey用RSA私钥加密
      socket.send(JSON.stringify({ code: 101, PublicKey: crypto.privateEncrypt(RSAPrivateKey, ECDHServerPublicKey).toString('base64') }));
      console.log(colors.green("Sended ECDHServerPublicKey: ") + ECDHServerPublicKey.toString('base64'));
      //获取到生成的DESKEY
      DESKEY = ecdh.computeSecret(ECDHClientPubKey, 'base64', 'base64');
      console.log(colors.green("Generator DESKEY: ") + DESKEY);
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
            console.log(colors.green("MSG from client: ") + data.msg);
            socket.send(DESCrypto.Cipher({ code: 10, msg: "hello client", DESKEY: DESKEY }, DESKEY));
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
  socket.on('close', function close() {
    console.log(colors.red('A client disconnected.'));
    console.log(colors.green("Online clients: ") + WebSocketServer.clients.length);
  });
});
