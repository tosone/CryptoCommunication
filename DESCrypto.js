"use strict"
const crypto = require('crypto');

module.exports.Decipher = function(data, DESKEY) {
    var decipher = crypto.createDecipher('des', new Buffer(DESKEY, 'base64'));
    var decipherTxt = decipher.update(data, 'base64', 'utf8');
    decipherTxt += decipher.final('utf8');
    return JSON.parse(decipherTxt.toString('utf8'));
}

module.exports.Cipher = function(json, DESKEY) {
    var cipher = crypto.createCipher('des', new Buffer(DESKEY, 'base64'));
    var json_temp = [];
    json_temp.push(json);
    json_temp.push({ hash: crypto.createHash('sha512').update(JSON.stringify(json_temp[0])).digest('base64') })
    var crypted = cipher.update(JSON.stringify(json_temp), 'utf8', 'base64');
    crypted += cipher.final('base64');
    return JSON.stringify({ code: 102, data: crypted, timestamp: new Date().getTime() });
}
