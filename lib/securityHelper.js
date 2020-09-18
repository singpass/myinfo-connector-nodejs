//import statements
const pem = require('pem');
const fs = require('fs');
var log4js = require('log4js');
var logger = log4js.getLogger('MyInfoNodeJSConnector');
const CONFIG = require('../common/config');
logger.level = CONFIG.DEBUG_LEVEL;

const _ = require('lodash');
const crypto = require('crypto');
const qs = require('querystring');
const constant = require('../common/constant');
const jose = require('node-jose');

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
module.exports.generateAuthorizationHeader = (apiURL, params, httpMethod, strContentType, authType, appId, myinfoPrivateKey, clientSecret) => {
  var nonceValue = crypto.randomBytes(20).toString("hex");
  var timestamp = (new Date).getTime();
  if (authType === constant.ENVIRONMENT.PROD || authType === constant.ENVIRONMENT.TEST) {
    // Only when auth type is PROD / TEST
    var baseString = generateBaseString(httpMethod, apiURL, appId, params, strContentType, nonceValue, timestamp);
    var signature = generateSignature(baseString, myinfoPrivateKey, clientSecret);
    var strAuthHeader = "PKI_SIGN timestamp=\"" + timestamp +
      "\",nonce=\"" + nonceValue +
      "\",app_id=\"" + appId +
      "\",signature_method=\"RS256\"" +
      ",signature=\"" + signature +
      "\"";
    return strAuthHeader;
  }
  else {
    return "";
  }
}

module.exports.getPayload = (compactJWE, pemPrivateKey) => {
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
}

module.exports.verifyToken = (decryptedPayload, pubKey) => {
  return new Promise(function (resolve, reject) {
    let keystore = jose.JWK.createKeyStore();

    keystore.add(pubKey, "pem")
      .then(jwsKey => {
        return jose.JWS.createVerify(jwsKey)
          .verify(decryptedPayload);
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
module.exports.verifyJWS = (publicKey, compactJWS) => {
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
module.exports.decryptJWE = (pemPrivateKey, compactJWE) => {
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

/**
 * Get Private Key
 * 
 * This methods will decrypt P12 Certificate and retrieve the Private key with the passphrase
 * 
 * @param {File} secureCert - P12 file with client private key
 * @param {string} passphrase - Passphrase required to decrypt the passphrase
 * @returns {Promise} - Returns certificate and private key from p12
 */
module.exports.decryptPrivateKey = (secureCert, passphrase) => {
  const p12 = fs.readFileSync(secureCert);
  return new Promise((resolve, reject) => {
    pem.readPkcs12(p12, { p12Password: passphrase },
      (error, cert) => {
        if (error) {
          logger.error('decryptPrivateKey - Error: ', error);
          reject(error);
        }
        else {
          let result = {
            "cert": cert.cert,
            "key": cert.key
          }
          resolve(result);
        }
      });
  })
}

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

function generateBaseString(httpMethod, apiURL, appId, params, strContentType, nonceValue, timestamp) {
  // Construct the Authorisation Token Parameters
  var defaultAuthHeaders = {
    "app_id": appId, // App ID assigned to your application
    "nonce": nonceValue, // secure random number
    "signature_method": "RS256",
    "timestamp": timestamp // Unix epoch time
  };

  // Remove params unless Content-Type is "application/x-www-form-urlencoded"
  if (httpMethod === "POST" && strContentType !== "application/x-www-form-urlencoded") {
    params = {};
  }

  // Normalize request parameters
  var baseParams = sortJSON(_.merge(defaultAuthHeaders, params));
  var baseParamsStr = qs.stringify(baseParams);
  baseParamsStr = qs.unescape(baseParamsStr);

  // concatenate request elements (HTTP method + url + base string parameters)
  var baseString = httpMethod.toUpperCase() + "&" + apiURL + "&" + baseParamsStr;

  return baseString;
}

function generateSignature(baseString, myinfoPrivateKey, clientSecret) {
  var signWith = {
    key: (myinfoPrivateKey)
  }; // Provides private key

  if (!_.isUndefined(clientSecret) && !_.isEmpty(clientSecret)) _.set(signWith, "passphrase", clientSecret);

  // Load pem file containing the x509 cert & private key & sign the base string with it to produce the Digital Signature
  var signature = crypto.createSign('RSA-SHA256')
    .update(baseString)
    .sign(signWith, 'base64');

  return signature;
}