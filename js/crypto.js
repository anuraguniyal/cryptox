/* crypto utils (c) anuraguniyal@gmail.com */

var CryptoX = (function(){

    var registered_providers = {
    }
    var the_object = {}

    the_object.method = function(method_name){
        return function(){
            var providers = the_object.providers(method_name)
            var results = []
            for(var i=0;i<providers.length;i++){
                var provider = providers[i]
                var error = null;
                try{
                    var result = provider[method_name].apply(provider, arguments);
                }catch(e){
                    error = e
                }
                results.push([provider, result, error])
            }
            return results
        }
    }

    the_object.provider = function(provider_name){
        provider_name = provider_name || 'cryptojs'
        return registered_providers[provider_name]
    }

    the_object.providers = function(func_name){
        var providers = [];
        for(o in registered_providers){
            var provider = registered_providers[o]
            if(!provider[func_name]) continue
            providers.push(provider);
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

    var aes_decrypt = function(data, secret){
        var d = CryptoJS.AES.decrypt(data, secret).toString(CryptoJS.enc.Utf8);

        /* long winded way if openssl decryption is not supported
        var data = CryptoJS.enc.Base64.parse(data).toString()
        var salt = data.substring(16, 32)
        var enc = data.substring(32, data.length);

        var derivedParams = CryptoJS.kdf.OpenSSL.execute(secret, 256/32, 128/32, CryptoJS.enc.Hex.parse(salt));
        var cipherParams = CryptoJS.lib.CipherParams.create({ciphertext: CryptoJS.enc.Hex.parse(enc)});
        var decrypted = CryptoJS.AES.decrypt(cipherParams, derivedParams.key, {iv: derivedParams.iv});
        d = decrypted.toString(CryptoJS.enc.Utf8));
        */

        return d
    }

    var sha256 = function(text){
        return CryptoJS.SHA256(text).toString(CryptoJS.enc.Hex);
    }

    return {
        name: 'cryptojs',
        get_totp: get_totp,
        get_hotp: get_hotp,
        aes_decrypt: aes_decrypt,
        sha256: sha256
    }

})();
CryptoX.register(CryptoCryptoJS);

var CryptoSJCL = (function(){

    // enable cbc
    sjcl.beware["CBC mode is dangerous because it doesn't protect message integrity."]()

    var aes_decrypt = function(data, secret){

        var data = CryptoJS.enc.Base64.parse(data).toString()
        var salt = data.substring(16, 32)
        var enc = data.substring(32, data.length);

        // this line may also be replaced by sjcl see https://www.reddit.com/r/javascript/comments/3luxl8/aes_decryption_with_sjcl_problem_xpost_rcrypto/gt
        var derivedParams = CryptoJS.kdf.OpenSSL.execute(secret, 256/32, 128/32, CryptoJS.enc.Hex.parse(salt));

        ciphertext = sjcl.codec.hex.toBits(enc)
        key = sjcl.codec.hex.toBits(derivedParams.key.toString())
        iv = sjcl.codec.hex.toBits(derivedParams.iv.toString())
        aes = new sjcl.cipher.aes(key);
        d = sjcl.mode.cbc.decrypt(aes, ciphertext, iv, [], 64)
        d = sjcl.codec.utf8String.fromBits(d)
        return d
    }

    return {
        name: 'sjcl',
        aes_decrypt: aes_decrypt
    }

})();
CryptoX.register(CryptoSJCL);


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
