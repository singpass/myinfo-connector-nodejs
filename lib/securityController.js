const _ = require('lodash');
const crypto = require('crypto');
const qs = require('querystring');
const constant = require('../common/constant');
const jose = require('node-jose');

/**
 * Sort JSON
 * 
 * This is a utility method to sort the keys in a JSON
 * 
 * @param {JSON} json - Object requried for sorting
 * @returns {JSON} - Sorted Object
 */
function sortJSON(json) {
  if (_.isNil(json)) {
    return json;
  }

  var newJSON = {};
  var keys = Object.keys(json);
  keys.sort();

  for (var key in keys) {
    newJSON[keys[key]] = json[keys[key]];
  }

  return newJSON;
}

/**
 * Generate SHA256 with RSA Header
 * 
 * This method will take in the required parameters and create the Signature required for the header
 * 
 * @param {string} url - API URL
 * @param {JSON} params - JSON object of params sent, key/value pair.
 * @param {string} method - API method type, eg GET, POST...
 * @param {string} strContentType - Content Type of HTTPS request
 * @param {string} authType - Auth level, eg SANDBOX, TEST, PROD
 * @param {string} appId - API ClientId
 * @param {File} keyCertContent - Private Key Certificate content
 * @param {string} clientSecret - API Client Secret
 * @returns {string} - Signed Header
 */
function generateSHA256withRSAHeader(url, params, method, strContentType, appId, keyCertContent, clientSecret) {
  var nonceValue = crypto.randomBytes(20).toString("hex");
  var timestamp = (new Date).getTime();

  // A) Construct the Authorisation Token Parameters
  var defaultAuthHeaders = {
    "app_id": appId, // App ID assigned to your application
    "nonce": nonceValue, // secure random number
    "signature_method": "RS256",
    "timestamp": timestamp // Unix epoch time
  };

  // Remove params unless Content-Type is "application/x-www-form-urlencoded"
  if (method === "POST" && strContentType !== "application/x-www-form-urlencoded") {
    params = {};
  }



  // B) Forming the Base String 
  // Base String is a representation of the entire request (ensures message integrity)

  // B-i) Normalize request parameters
  var baseParams = sortJSON(_.merge(defaultAuthHeaders, params));
  var baseParamsStr = qs.stringify(baseParams);
  baseParamsStr = qs.unescape(baseParamsStr);

  // B-ii) concatenate request elements (HTTP method + url + base string parameters)
  var baseString = method.toUpperCase() + "&" + url + "&" + baseParamsStr;



  // C) Signing Base String to get Digital Signature
  var signWith = {
    key: (keyCertContent)
  }; // Provides private key

  if (!_.isUndefined(clientSecret) && !_.isEmpty(clientSecret)) _.set(signWith, "passphrase", clientSecret);

  // Load pem file containing the x509 cert & private key & sign the base string with it to produce the Digital Signature
  var signature = crypto.createSign('RSA-SHA256')
    .update(baseString)
    .sign(signWith, 'base64');



  // D) Assembling the Authorization Header
  var strAuthHeader = "PKI_SIGN timestamp=\"" + timestamp +
    "\",nonce=\"" + nonceValue +
    "\",app_id=\"" + appId +
    "\",signature_method=\"RS256\"" +
    ",signature=\"" + signature +
    "\"";

  return strAuthHeader;
}

/**
 * Generate Authorization Header
 * 
 * This method helps to generate the authorization header and sign it 
 * using the private key. This is required to be used for both Token and Person API
 * 
 * @param {string} url - API URL
 * @param {JSON} params - JSON object of params sent, key/value pair.
 * @param {string} method - API method type, eg GET, POST...
 * @param {string} strContentType - Content Type of HTTPS request
 * @param {string} authType - Auth level, eg SANDBOX, TEST, PROD
 * @param {string} appId - API ClientId
 * @param {File} keyCertContent - Private Key Certificate content
 * @param {string} clientSecret - API Client Secret
 * @returns {string} - Signed Header
 */
exports.generateAuthorizationHeader = function (url, params, method, strContentType, authType, appId, keyCertContent, clientSecret) {

  if (authType === constant.ENVIRONMENT.PROD || authType === constant.ENVIRONMENT.TEST) {
    // Only when auth type is PROD / TEST then call generateSHA256withRSAHeader
    return generateSHA256withRSAHeader(url, params, method, strContentType, appId, keyCertContent, clientSecret);
  }
  else {
    return "";
  }

};

/**
 * Verify JWS
 * 
 * This method takes in a JSON Web Signature and will check against 
 * the public key for its validity and to retrieve the decoded data.
 * This verification is required for the decoding of the access token and 
 * response from Person API
 * 
 * @param {File} publicKey - Public Cert string, PEM format
 * @param {string} compactJWS - Data in JWS compact serialization Format
 * @returns {Promise} - Promise that resolve decoded data
 */
exports.verifyJWS = function (publicKey, compactJWS) {
  return new Promise(function (resolve, reject) {
    let keystore = jose.JWK.createKeyStore();

    keystore.add(publicKey, "pem")
      .then(jwsKey => {
        return jose.JWS.createVerify(jwsKey)
          .verify(compactJWS);
      })
      .then(result => {
        var payload = JSON.parse(Buffer.from(result.payload).toString());
        resolve(payload);
      })
      .catch(error => {
        reject(error);
      });
  });
}

/**
 * Decyption JWE
 * 
 * This method takes in a JSON Web Encrypted object and will decrypt it using the
 * private key. This is required to decrypt the data from Person API
 * 
 * @param {File} pemPrivateKey - Private Key string, PEM format
 * @param {string} compactJWE - Data in compact serialization format - header.encryptedKey.iv.ciphertext.tag
 * @returns {Promise} - Promise that resolve decrypted data
 */
exports.decryptJWE = function (pemPrivateKey, compactJWE) {
  return new Promise((resolve, reject) => {

    var jweParts = compactJWE.split("."); // header.encryptedKey.iv.ciphertext.tag
    let keystore = jose.JWK.createKeyStore();
    if (jweParts.length != 5) {
      reject({ "error": constant.INVALID_DATA_OR_SIGNATURE });
    }

    keystore.add(pemPrivateKey, "pem")
      .then(key => {
        // Formulate data into structure for decryption
        var data = {
          "type": "compact",
          "protected": jweParts[0],
          "encrypted_key": jweParts[1],
          "iv": jweParts[2],
          "ciphertext": jweParts[3],
          "tag": jweParts[4],
          "header": JSON.parse(jose.util.base64url.decode(jweParts[0]).toString())
        };
        // Decrypting
        return jose.JWE.createDecrypt(key).decrypt(data);
      })
      .then(result => {
        // Success! Resolving promise
        resolve(JSON.parse(result.payload.toString()));
      })
      .catch(error => {
        reject(error);
      });
  });
};

