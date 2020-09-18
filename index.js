const fs = require('fs');
const querystring = require('querystring');
const constant = require('./common/constant')
const urlParser = require('url');
const requestHandler = require('./lib/requestHandler.js');
const CONFIG = require('./common/config');

var log4js = require('log4js');
var logger = log4js.getLogger('MyInfoNodeJSConnector');
// ####################
logger.level = CONFIG.DEBUG_LEVEL;
// Exporting the Module
// ####################

/**
 * MyInfoConnector Constructor
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
 * }}
 */
class MyInfoConnector {

  #isInitialized = false;
  #securityHelper;

  constructor(config) {
    try {
      this.#load(config);
      this.#isInitialized = true;
      this.securityHelper = require('./lib/securityHelper');
    } catch (error) {
      logger.error('Error (Library Init): ', error);
      this.#isInitialized = false;
      throw error;
    }
  }

  #load = function (config) {
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
  getMyInfoPersonData = function (authCode, state, txnNo) {
    if (!this.#isInitialized) {
      throw (constant.ERROR_UNKNOWN_NOT_INIT);
    }
    // checking if the state provided is not undefined.
    return this.getAccessToken(authCode, state)
      .then(createTokenResult => {
        let accessToken = JSON.parse(createTokenResult).access_token;
        return this.getPersonData(accessToken, txnNo);
      })
      .catch(error => {
        return Promise.reject(error);
      })
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
  getAccessToken = function (authCode, state) {
    if (!this.#isInitialized) {
      throw (constant.ERROR_UNKNOWN_NOT_INIT);
    }
    return new Promise((resolve, reject) => {
      this.securityHelper.decryptPrivateKey(CONFIG.CLIENT_SECURE_CERT, CONFIG.CLIENT_SECURE_CERT_PASSPHRASE)
        .then(result => {
          logger.debug('Client Private Key: ', CONFIG.CLIENT_SECURE_CERT);
          let certificate = result;
          let privateKey = (certificate.key);
          return this.#callTokenAPI(authCode, privateKey, state);
        })
        .then(tokenResult => {
          let token = tokenResult.msg;
          logger.debug('Access Token: ', token);
          resolve(token);
        })
        .catch(error => {
          logger.error('getAccessToken - Error: ', error);
          reject(error);
        });
    })
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
  getPersonData = function (accessToken, txnNo) {
    if (!this.#isInitialized) {
      throw (constant.ERROR_UNKNOWN_NOT_INIT);
    }
    return new Promise((resolve, reject) => {
      this.securityHelper.decryptPrivateKey(CONFIG.CLIENT_SECURE_CERT, CONFIG.CLIENT_SECURE_CERT_PASSPHRASE)
        .then(result => {
          logger.debug('Client Private Key: ', CONFIG.CLIENT_SECURE_CERT);
          let privateKey = (result.key);
          return this.#getPersonDataWithKey(accessToken, txnNo, privateKey);
        })
        .then(callPersonRequestResult => {
          logger.debug('Person Data: ', callPersonRequestResult);
          resolve(callPersonRequestResult);
        })
        .catch(error => {
          logger.error('getPersonData - Error: ', error);
          reject(error);
        })
    })
  }

  /**
   * Call (Access) Token API
   * 
   * This method will generate the Authorization Header
   * and call the Token API to retrieve access Token
   * 
   * @param {string} authCode - Authorization Code from Authorise API
   * @param {File} privateKey - The Client Private Key in PEM format
   * @param {string} state - Identifier that represents the user's session with the client, provided earlier during the authorise API call.
   * @returns {Promise} - Returns the Access Token
   */
  #callTokenAPI = function (authCode, privateKey, state) {

    let cacheCtl = "no-cache";
    let contentType = "application/x-www-form-urlencoded";
    let method = constant.HTTP_METHOD.POST;

    // assemble params for Token API
    let strParams = "grant_type=authorization_code" +
      "&code=" + authCode +
      "&redirect_uri=" + CONFIG.REDIRECT_URL +
      "&client_id=" + CONFIG.CLIENT_ID +
      "&client_secret=" + CONFIG.CLIENT_SECRET;

    if (state) {
      strParams += "&state=" + state;
    }

    let params = querystring.parse(strParams);

    // assemble headers for Token API
    let strHeaders = "Content-Type=" + contentType + "&Cache-Control=" + cacheCtl;
    let headers = querystring.parse(strHeaders);

    // Add Authorisation headers for connecting to API Gateway
    let authHeaders = null;
    if (CONFIG.ENVIRONMENT === constant.ENVIRONMENT.SANDBOX) {
      // No headers
    } else if (CONFIG.ENVIRONMENT === constant.ENVIRONMENT.PROD || CONFIG.ENVIRONMENT === constant.ENVIRONMENT.TEST) {
      authHeaders = this.securityHelper.generateAuthorizationHeader(
        CONFIG.TOKEN_URL,
        params,
        method,
        contentType,
        CONFIG.ENVIRONMENT,
        CONFIG.CLIENT_ID,
        privateKey,
        CONFIG.CLIENT_SECRET,
        state
      );
    } else {
      return Promise.reject("Unknown Auth Level");
    }

    if (authHeaders) {
      headers['Authorization'] = authHeaders;
    }

    logger.info('Authorization Header for MyInfo Token API: ', JSON.stringify(headers));

    // invoke Token API
    let tokenURL = (CONFIG.USE_PROXY && CONFIG.USE_PROXY == 'Y') ? CONFIG.PROXY_TOKEN_URL : CONFIG.TOKEN_URL;
    let parsedTokenUrl = urlParser.parse(tokenURL);
    let tokenDomain = parsedTokenUrl.hostname;
    let tokenRequestPath = parsedTokenUrl.path;

    return requestHandler.getHttpsResponse(tokenDomain, tokenRequestPath, headers, method, params);
  };

  /**
   * Call Person API
   * 
   * This method will generate the Authorization Header and 
   * and call the Person API to get the encrypted Person Data
   * 
   * @param {string} sub - The retrieved uinfin or uuid sub from the decoded token
   * @param {string} accessToken - The Access token from Token API that has been verified and decoded from Token API 
   * @param {string} txnNo - Transaction ID from requesting digital services for cross referencing.
   * @param {File} privateKey - The Client Private Key in PEM format
   * 
   * @returns {Promise} Returns result from calling Person API
   */
   #callPersonAPI = function (sub, accessToken, txnNo, privateKey) {

    let urlLink = CONFIG.PERSON_URL + "/" + sub;
    let cacheCtl = "no-cache";
    let method = constant.HTTP_METHOD.GET;

    // assemble params for Person API
    let strParams = "client_id=" + CONFIG.CLIENT_ID +
      "&attributes=" + CONFIG.ATTRIBUTES;

    if (txnNo) {
      strParams += "&txnNo=" + txnNo;
    }

    let params = querystring.parse(strParams);

    // assemble headers for Person API
    let strHeaders = "Cache-Control=" + cacheCtl;
    let headers = querystring.parse(strHeaders);

    // Add Authorisation headers for connecting to API Gateway
    let authHeaders = null;
    if (CONFIG.ENVIRONMENT === constant.ENVIRONMENT.SANDBOX) {
      // No headers
    } else if (CONFIG.ENVIRONMENT === constant.ENVIRONMENT.PROD || CONFIG.ENVIRONMENT === constant.ENVIRONMENT.TEST) {
      authHeaders = this.securityHelper.generateAuthorizationHeader(
        urlLink,
        params,
        method,
        "", // no content type needed for GET
        CONFIG.ENVIRONMENT,
        CONFIG.CLIENT_ID,
        privateKey,
        CONFIG.CLIENT_SECRET,
        txnNo
      );
    } else {
      logger.error(ERROR_UNKNOWN_AUTH_LEVEL);
      return Promise.reject(ERROR_UNKNOWN_AUTH_LEVEL);
    }

    // NOTE: include access token in Authorization header as "Bearer " (with space behind)
    if (authHeaders) {
      headers['Authorization'] = authHeaders + ",Bearer " + accessToken;
    } else {
      headers['Authorization'] = "Bearer " + accessToken;
    }

    logger.info('Authorization Header for MyInfo Person API: ', JSON.stringify(headers));

    // invoke person API
    let personURL = (CONFIG.USE_PROXY && CONFIG.USE_PROXY == 'Y') ? CONFIG.PROXY_PERSON_URL : CONFIG.PERSON_URL;
    let parsedUrl = urlParser.parse(personURL);
    let domain = parsedUrl.hostname;
    let requestPath = parsedUrl.path + "/" + sub + "?" + strParams;

    //invoking https to do GET call
    return requestHandler.getHttpsResponse(domain, requestPath, headers, method, null);
  };

  /**
   * Get Person Data
   * 
   * This method will take in the accessToken from Token API and decode it 
   * to get the sub(eg either uinfin or uuid). It will call the Person API using the token and sub.
   * It will verify the Person API data's signature and decrypt the result.
   * 
   * @param {string} accessToken - The token that has been verified from Token API 
   * @param {string} txnNo - Transaction ID from requesting digital services for cross referencing.
   * @param {File} privateKey - The Client Private Key in PEM format
   * 
   * @returns {Promise} Returns decrypted result from calling Person API
   */
  #getPersonDataWithKey = function (accessToken, txnNo, privateKey) {
    return new Promise((resolve, reject) => {
      this.securityHelper.verifyJWS(CONFIG.MYINFO_SIGNATURE_CERT_PUBLIC_CERT, accessToken)
        .then(decodedToken => {
          logger.debug('Decoded Access Token (from MyInfo Token API): ', decodedToken);
          if (!decodedToken) {
            logger.error('Error: ', constant.INVALID_TOKEN);
            return Promise.reject(constant.INVALID_TOKEN);
          }
          let uinfin = decodedToken.sub;
          if (!uinfin) {
            logger.error('Error: ', constant.UINFIN_NOT_FOUND);
            return Promise.reject(constant.UINFIN_NOT_FOUND);
          }
          return this.#callPersonAPI(uinfin, accessToken, txnNo, privateKey);
        })
        .then(personRes => {
          if (personRes && personRes.msg) {
            let msg = personRes.msg;
            if (CONFIG.ENVIRONMENT === constant.ENVIRONMENT.SANDBOX) {
              let result = JSON.parse(msg.toString());
              return Promise.resolve(result);
            } else {
              logger.debug('MyInfo PersonAPI Response (JWE+JWS): ', msg);
              return this.securityHelper.decryptJWE(privateKey, msg);
            }
          } else {
            logger.error('Error: ', constant.ERROR);
            return Promise.reject(constant.ERROR);
          }
        })
        .then(decryptResponse => {
          if (CONFIG.ENVIRONMENT === constant.ENVIRONMENT.SANDBOX) {
            return Promise.resolve(decryptResponse);
          } else {
            if (!decryptResponse) {
              logger.error('Error: ', constant.INVALID_DATA_OR_SIGNATURE);
              return Promise.reject(constant.INVALID_DATA_OR_SIGNATURE);
            } else {
              logger.debug('Decrypted JWE: ', decryptResponse);
              return this.securityHelper.verifyJWS(CONFIG.MYINFO_SIGNATURE_CERT_PUBLIC_CERT, decryptResponse);
            }
          }
        })
        .then(decodedData => {
          if (CONFIG.ENVIRONMENT === constant.ENVIRONMENT.SANDBOX) {
            logger.debug('Person Data (Plain): ', decodedData);
            resolve(decodedData);
          } else {
            if (!decodedData) {
              logger.error('Error: ', constant.INVALID_DATA_OR_SIGNATURE);
              return Promise.reject(constant.INVALID_DATA_OR_SIGNATURE);
            }
            // successful. return data back to frontend
            logger.debug('Person Data (JWE Decrypted + JWS Verified): ', decodedData);
            resolve(decodedData);
          }
        })
        .catch(error => {
          reject(error);
        })

    })
  }
}
module.exports = MyInfoConnector;