var CONFIG = require('./common/config');
var constant = require('./common/constant');
var fs = require('fs');
var log4js = require('log4js');
var logger = log4js.getLogger('MyInfoNodeJSConnector');
var isInitialized = false;

var getPersonController;
var privateKeyController;
var securityController;

// ####################
// Exporting the Module
// ####################

/**
 * MyInfoLibrary Constructor
 * 
 * This is a constructor to validate and initialize all the config variables
 * 
 * @param {{MYINFO_SIGNATURE_CERT_PUBLIC_CERT : string, 
 * CLIENT_SECURE_CERT: string, 
 * CLIENT_SECURE_CERT_PASSPHRASE : string, 
 * CLIENT_ID: string,
 * CLIENT_SECRET :string ,
 * REDIRECT_URL : string,
 * ATTRIBUTES : string,
 * ENVIRONMENT : string, 
 * TOKEN_URL : string, 
 * PERSON_URL : string,
 * USE_PROXY : string, 
 * PROXY_TOKEN_URL : string, 
 * PROXY_PERSON_URL : string
 * }} config
 */
function MyInfoLibrary(config) {

  try {

    if (config.DEBUG_LEVEL) {
      CONFIG.DEBUG_LEVEL = config.DEBUG_LEVEL;
      logger.level = CONFIG.DEBUG_LEVEL;
    }

    if (!config.MYINFO_SIGNATURE_CERT_PUBLIC_CERT) {
      throw (constant.ERROR_CONFIGURATION_PUBLIC_CERT_NOT_FOUND);
    } else {
      CONFIG.MYINFO_SIGNATURE_CERT_PUBLIC_CERT = fs.readFileSync(config.MYINFO_SIGNATURE_CERT_PUBLIC_CERT, 'utf8');
    }

    if (!config.CLIENT_ID) {
      throw (constant.ERROR_CONFIGURATION_CLIENT_ID_NOT_FOUND);
    } else {
      CONFIG.CLIENT_ID = config.CLIENT_ID;
    }

    if (!config.CLIENT_SECRET) {
      throw (constant.ERROR_CONFIGURATION_CLIENT_SECRET_NOT_FOUND);
    } else {
      CONFIG.CLIENT_SECRET = config.CLIENT_SECRET;
    }

    if (!config.REDIRECT_URL) {
      throw (constant.ERROR_CONFIGURATION_REDIRECT_URL_NOT_FOUND);
    } else {
      CONFIG.REDIRECT_URL = config.REDIRECT_URL;
    }

    if (!config.CLIENT_SECURE_CERT) {
      throw (constant.ERROR_CONFIGURATION_CLIENT_SECURE_CERT_NOT_FOUND);
    } else {
      CONFIG.CLIENT_SECURE_CERT = config.CLIENT_SECURE_CERT;
    }

    if (!config.CLIENT_SECURE_CERT_PASSPHRASE) {
      throw (constant.ERROR_CONFIGURATION_CLIENT_SECURE_CERT_PASSPHRASE_NOT_FOUND);
    } else {
      CONFIG.CLIENT_SECURE_CERT_PASSPHRASE = config.CLIENT_SECURE_CERT_PASSPHRASE;
    }

    if (!config.ENVIRONMENT) {
      throw (constant.ERROR_CONFIGURATION_ENVIRONMENT_NOT_FOUND);
    } else {
      CONFIG.ENVIRONMENT = config.ENVIRONMENT;
    }

    if (!config.TOKEN_URL) {
      throw (constant.ERROR_CONFIGURATION_TOKEN_URL_NOT_FOUND);
    } else {
      CONFIG.TOKEN_URL = config.TOKEN_URL;
    }

    if (!config.PERSON_URL) {
      throw (constant.ERROR_CONFIGURATION_PERSON_URL_NOT_FOUND);
    } else {
      CONFIG.PERSON_URL = config.PERSON_URL;
    }

    if (!config.ATTRIBUTES) {
      throw (constant.ERROR_CONFIGURATION_ATTRIBUTES_NOT_FOUND);
    } else {
      CONFIG.ATTRIBUTES = config.ATTRIBUTES;
    }


    if (config.USE_PROXY === 'Y') {
      CONFIG.USE_PROXY = 'Y';
      if (!config.PROXY_TOKEN_URL) {
        throw (constant.ERROR_CONFIGURATION_PROXY_TOKEN_URL_NOT_FOUND);
      } else {
        CONFIG.PROXY_TOKEN_URL = config.PROXY_TOKEN_URL;
      }
      if (!config.PROXY_PERSON_URL) {
        throw (constant.ERROR_CONFIGURATION_PROXY_PERSON_URL_NOT_FOUND);
      } else {
        CONFIG.PROXY_PERSON_URL = config.PROXY_PERSON_URL;
      }
    }

    isInitialized = true;
    getPersonController = require('./lib/getPersonController.js');
    privateKeyController = require('./lib/privateKeyController');
    securityController = require('./lib/securityController');

  } catch (error) {
    logger.error('Error (Library Init): ', error);
  }

}

/**
 * Get Access Token from MyInfo Token API
 * 
 * This method calls the Token API and obtain an "access token", 
 * which can be used to call the Person API for the actual data.
 * Your application needs to provide a valid "authorisation code" 
 * from the authorise API in exchange for the "access token".
 * 
 * @param {string} authCode - Authorization Code from Authorise API
 * @param {string} state - Identifier that represents the user's session with the client, provided earlier during the authorise API call.
 * @returns {Promise} - Returns the Access Token
 */
MyInfoLibrary.prototype.getAccessToken = function (authCode, state) {
  if (!isInitialized) {
    throw (constant.ERROR_UNKNOWN_NOT_INIT);
  }

  return getPersonController.getAccessToken(authCode, state);
}

/**
 * Get Person Data from MyInfo Person API
 * 
 * This method calls the Person API and returns a JSON response with the
 * personal data that was requested. Your application needs to provide a
 * valid "access token" in exchange for the JSON data. Once your application
 * receives this JSON data, you can use this data to populate the online
 * form on your application.
 * 
 * @param {string} accessToken - Access token from Token API
 * @param {string} txnNo - Transaction ID from requesting digital services for cross referencing.
 * @returns {Promise} Returns the Person Data (Payload decrypted + Signature validated)
 */
MyInfoLibrary.prototype.getPersonData = function (accessToken, txnNo) {
  if (!isInitialized) {
    throw (constant.ERROR_UNKNOWN_NOT_INIT);
  }
  return getPersonController.getPersonData(accessToken, txnNo);
}


/**
 * Get MyInfo Person Data (MyInfo Token + Person API)
 * 
 * This method takes in all the required variables, invoke the following APIs. 
 * - Get Access Token (Token API) - to get Access Token by using the Auth Code
 * - Get Person Data (Person API) - to get Person Data by using the Access Token
 * 
 * @param {string} authCode - Authorization Code from Authorise API
 * @param {string} state - Identifier that represents the user's session with the client, provided earlier during the authorise API call.
 * @param {string} txnNo - Transaction ID from requesting digital services for cross referencing.
 * @returns {Promise} - Returns the Person Data (Payload decrypted + Signature validated)
 */
MyInfoLibrary.prototype.getMyInfoPersonData = function (code, state, txnNo) {
  if (!isInitialized) {
    throw (constant.ERROR_UNKNOWN_NOT_INIT);
  }
  // checking if the state provided is not undefined.
  return this.getAccessToken(code, state)
    .then(createTokenResult => {
      let accessToken = JSON.parse(createTokenResult).access_token;
      return this.getPersonData(accessToken, txnNo);
    })
    .catch(error => {
      return Promise.reject(error);
    })
}

/**
 * Get Private Key
 * 
 * This methods will decrypt P12 Certificate and retrieve the Private key with the passphrase
 * 
 * @param {File} secureCert - P12 file with client private key
 * @param {string} passphrase - Passphrase required to decrypt the passphrase
 * @returns {Promise} - Certificate and private key from p12
 */
MyInfoLibrary.prototype.decryptPrivateKey = function (secureCert, passphrase) {
  if (!isInitialized) {
    throw (constant.ERROR_UNKNOWN_NOT_INIT);
  }
  return privateKeyController.decryptPrivateKey(secureCert, passphrase);
}

/**
 * Verify JWS
 * 
 * This method takes in a JSON Web Signature and will check against 
 * the public key for its validity and to retrieve the decoded data.
 * This verification is required for the decoding of the access token and 
 * response from Person API
 * 
 * @param {File} publicKey - PEM file public key
 * @param {string} compactJWS - Data in JWS compact serialization Format
 * @returns {Promise} - decoded data
 */
MyInfoLibrary.prototype.verifyJWS = function (publicKey, compactJWS) {
  if (!isInitialized) {
    throw (constant.ERROR_UNKNOWN_NOT_INIT);
  }
  return securityController.verifyJWS(publicKey, compactJWS);
}

/**
 * Decyption JWE
 * 
 * This method takes in a JSON Web Encrypted object and will decrypt it using the
 * private key. This is required to decrypt the data from Person API
 * 
 * @param {File} pemPrivateKey - Private Key string, PEM format
 * @param {string} compactJWE - data in compact serialization format - header.encryptedKey.iv.ciphertext.tag
 * @returns {Promise} -  Decrypted data
 */
MyInfoLibrary.prototype.decryptJWE = function (pemPrivateKey, compactJWE) {
  if (!isInitialized) {
    throw (constant.ERROR_UNKNOWN_NOT_INIT);
  }
  return securityController.decryptJWE(pemPrivateKey, compactJWE);
}

/**
 * Generate Authorization Header
 * 
 * This method helps to generate the authorization header and sign it 
 * using the private key. This is required to be used for both Token and Person API
 * 
 * @param {string} url - API URL
 * @param {string} params - JSON object of params sent, key/value pair.
 * @param {string} method - API method type, eg GET, POST...
 * @param {string} strContentType - Content Type of HTTPS request
 * @param {string} authType - Auth level, eg SANDBOX, TEST, PROD
 * @param {string} appId - API ClientId
 * @param {File} keyCertContent - Private Key Certificate content
 * @param {string} clientSecret - API Client Secret
 * @returns {string} - Authorized Header
 */
MyInfoLibrary.prototype.generateAuthorizationHeader = function (url, params, method, strContentType, authType, appId, keyCertContent, clientSecret) {
  if (!isInitialized) {
    throw (constant.ERROR_UNKNOWN_NOT_INIT);
  }
  return securityController.generateAuthorizationHeader(url, params, method, strContentType, authType, appId, keyCertContent, clientSecret);
}

module.exports = MyInfoLibrary;