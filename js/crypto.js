/* crypto utils (c) anuraguniyal@gmail.com */

var CryptoX = (function(){

    var method_names = ['get_totp', 'get_hotp'];
    var registered_providers = {
    }
    var the_object = {}
    
    the_object.provider = function(provider_name){
        provider_name = provider_name || 'cryptojs'
        return registered_providers[provider_name]
    }
    
    the_object.providers = function(){
        var providers = [];
        for(o in registered_providers){
            providers.push(registered_providers[o]);
        }
        return providers
    }
    
    the_object.register = function(provider){
        registered_providers[provider.name] = provider
    }
    
    return the_object;
})();

function dec2hex(s) { return (s < 15.5 ? '0' : '') + Math.round(s).toString(16); }
function hex2dec(s) { return parseInt(s, 16); }
function base32tohex(base32) {
    var base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var bits = "";
    var hex = "";

    for (var i = 0; i < base32.length; i++) {
        var val = base32chars.indexOf(base32.charAt(i).toUpperCase());
        bits += leftpad(val.toString(2), 5, '0');
    }

    for (var i = 0; i+4 <= bits.length; i+=4) {
        var chunk = bits.substr(i, 4);
        hex = hex + parseInt(chunk, 2).toString(16) ;
    }
    return hex;

}

function leftpad(str, len, pad) {
    if (len + 1 >= str.length) {
        str = Array(len + 1 - str.length).join(pad) + str;
    }
    return str;
}
    
var CryptoCryptoJS = (function(){

    var get_totp = function(secret){
        var time = Math.round(new Date().getTime() / 1000.0);
        interval = Math.floor(time / 30);
        return get_hotp(secret, interval)
    }
    
    
    var get_hotp = function(secret, interval){
        /*
        secret is a base32 string
        intervals_no is a number
        */
        secret = base32.decode(secret)
        // we don't pass secret as cryptojs parse it using utf8
        secret_words = CryptoJS.enc.Latin1.parse(secret);
        //convert intervals_no to hex
        interval = leftpad(dec2hex(interval), 16, '0');
        // convert hex to words
        interval = CryptoJS.enc.Hex.parse(interval)
        var hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA1, secret_words  );
        hmac.update(interval);
        var hash = hmac.finalize();
        // hex is a hexadecimal representation
        // so every two char make a byte of 20 byte hmac
        var hex = hash.toString(CryptoJS.enc.Hex)

        // offset if lower part of byte[19]
        var offset = hex2dec(hex[hex.length-1]); 
        // otp is first 31 bytes of bytes[offset:offset+4]
        var otp = hex2dec(hex.substr(offset * 2, 8)) & 0x7fffffff;

        otp = otp % 1000000
        
        return otp;
    }
    
    return {
        name: 'cryptojs',
        get_totp: get_totp,
        get_hotp: get_hotp
    }
    
})();
CryptoX.register(CryptoCryptoJS);

var CryptoJSSHA = (function(){

    var get_totp = function(secret){
        var time = Math.round(new Date().getTime() / 1000.0);
        interval = Math.floor(time / 30);
        return get_hotp(secret, interval)
    }
    
    var get_hotp = function(secret, interval){
        var key = base32tohex(secret);
        var time = leftpad(dec2hex(interval), 16, '0');
  
        // external library for SHA functionality
        var hmacObj = new jsSHA(time, "HEX");
        var hmac = hmacObj.getHMAC(key, "HEX", "SHA-1", "HEX");

        if (hmac != 'KEY MUST BE IN BYTE INCREMENTS') {
                var offset = hex2dec(hmac.substring(hmac.length - 1));
        }

        var otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) + '';

        return (otp).substr(otp.length - 6, 6).toString();
    }
    
    return {
        name: 'jssha',
        get_totp: get_totp,
        get_hotp: get_hotp
    }
    
})();

CryptoX.register(CryptoJSSHA);