
# MyInfo Connector NodeJS

[![Known Vulnerabilities](https://snyk.io/test/github/singpass/myinfo-connector-nodejs/badge.svg)](https://snyk.io/test/github/singpass/myinfo-connector-nodejs)

MyInfo Connector NodeJS aims to simplify consumer's integration effort with MyInfo by providing an easy to use Javascript library to integrate into your application.


## Contents

- [1. Installation](#installation)
    - [1.1. Using npm](#install)
    - [1.2. OpenSSL Installation](#openssl)
- [2. Usage](#usage)
    - [2.1. Sample Code](#sample)
    - [2.2. Process Environment file (Config)](#config)    
- [3. Individual Methods](#helper)
    - [3.1. Get MyInfo Person Data](#getMyInfoPersonData)
    - [3.2. Get Access Token](#getAccessToken)
    - [3.3. Get Person Data](#getPersonData)
- [Change Logs](./CHANGELOG.md)




## <a name="installation"></a>1. Installation

### <a name="install"></a>1.1. Using npm:

``` 
$ npm install myinfo-connector-nodejs 
```

### <a name="openssl"></a>1.2 [For Windows only] - OpenSSL Installation (_skip this step if you have OpenSSL installed_)

For windows user, you are required to install the OpenSSL library in your computer in order to use myinfo-connector-nodejs library. Please refer to the OpenSSL installation guide [here](https://public.cloud.myinfo.gov.sg/docs/OpenSSL_installation_guide.pdf). 


## <a name="usage"></a>2. Usage

### <a name="sample"></a>2.1. Sample Code

```
var MyInfoConnector = require('myinfo-connector-nodejs'); //Call constructor to initialize library and pass in the configurations.

let connector = new MyInfoConnector(config.MYINFO_CONNECTOR_CONFIG); // MYINFO_CONNECTOR_CONFIG is the Process Environment file (in JSON format), please refer to Process Environment file in 2.2


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

connector.getMyInfoPersonData(authCode, state, txnNo)
.then(data => {
    return data; // Person Data
})
.catch(error => {
    throw error;
});

```

    
### <a name="config"></a>2.2. Process Environment file
You are required to create an environment file (in JSON format) with the following process environments for this library. You may look at the sample Process Environment file [HERE](https://github.com/singpass/verify-demo-app/blob/master/your-vms-server/config/config.js). 

| Required Properties | Description |
| -------- | ----------- |
| CLIENT_SECURE_CERT_PASSPHRASE | Password of your private key. |
| CLIENT_SECURE_CERT | Alias of the your application private key in P12 format. [Example](https://github.com/singpass/myinfo-demo-app/tree/master/cert)|
| MYINFO_SIGNATURE_CERT_PUBLIC_CERT | Alias of the MyInfo public certificate in PEM format. |
| CLIENT_ID | Unique ID provided upon approval of your application to use MyInfo. (e.g. _STG2-MYINFO-SELF-TEST_) |
| CLIENT_SECRET | Secret key provided upon approval of your application to use MyInfo. (e.g. _44d953c796cccebcec9bdc826852857ab412fbe2_) |
| REDIRECT_URL | The callback URL specified when invoking the authorise call. For our sample application, it is http://localhost:3001/callback |
| ATTRIBUTES | Comma separated list of attributes requested. Possible attributes are listed in the Person object definition in the API specifications. (e.g. _name,mobileno_) |
| ENVIRONMENT | The environment your application is configured. This can be <ul><li>`SANDBOX`</li><li>`TEST`</li><li>`PROD`</li></ul>|
| TOKEN_URL | Specify the TOKEN API URL for MyInfo. The API is available in three environments:<ul><li>SANDBOX: https://sandbox.api.myinfo.gov.sg/com/v3/token</li><li>TEST: https://test.api.myinfo.gov.sg/com/v3/token</li><li>PROD: https://api.myinfo.gov.sg/com/v3/token</li></ul> |
| PERSON_URL | Specify the PERSON API URL for MyInfo. The API is available in three environments: <ul><li>SANDBOX: https://sandbox.api.myinfo.gov.sg/com/v3/person</li><li>TEST: https://test.api.myinfo.gov.sg/com/v3/person</li><li>PROD: https://api.myinfo.gov.sg/com/v3/person</li></ul>|
| USE_PROXY <br>_(OPTIONAL)_ | Indicate the use of proxy url. It can be either `Y` or `N`.|
| PROXY_TOKEN_URL <br>_(OPTIONAL)_ | _(REQUIRED if `USE_PROXY` is `Y`)_ <br> If you are using a proxy url, specify the proxy URL for TOKEN API here. |
| PROXY_PERSON_URL <br>_(OPTIONAL)_ | _(REQUIRED if `USE_PROXY` is `Y`)_ <br> If you are using a proxy url, specify the proxy URL for PERSON API here.|
| DEBUG_LEVEL <br>_(OPTIONAL)_ | _(OPTIONAL: if empty will be defaulted to no logs)_ <br> Configuration to set logging level for debugging within the library.  <table><tr><th>Mode</th><th>Description</th></tr><tr><td>`error`</td><td>Log out all the errors returned from the library</td></tr><tr><td>`info`</td><td>Log urls called, authorization headers and errors from the library</td></tr><tr><td>`debug`</td><td>Full logs from the library, i.e (errors, urls, authorization headers, API response)</td></tr></table> IMPORTANT NOTE: `debug` mode **should never be turned on in production**



## <a name="helper"></a>3. Individual Method

Under the hood, MyInfo Connector NodeJS makes use of **SecurityHelper** and you may use the class as util methods to meet your application needs.

### <a name="getMyInfoPersonData"></a>3.1. Get MyInfo Person Data
This method takes in all the required parameters to get MyInfo Person Data.

```
var MyInfoConnector = require('myinfo-connector-nodejs'); //Call constructor to initialize library and pass in the configurations.

let connector = new MyInfoConnector(config.MYINFO_CONNECTOR_CONFIG); // MYINFO_CONNECTOR_CONFIG is the Process Environment file (in JSON format), please refer to Process Environment file in 2.2

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
  getMyInfoPersonData = function (authCode, state, txnNo)
```

### <a name="getAccessToken"></a>3.2. Get Access Token
This method takes in all the authCode and state and returns the access token.

```
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
  getAccessToken = function (authCode, state)
```

### <a name="getPersonData"></a>3.3. Get Person Data
This method takes in the accessToken and txnNo and returns the person data.

```
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
  getPersonData = function (accessToken, txnNo)
```

## Reporting Issue

You may contact our [support](mailto:support@myinfo.gov.sg?subject=[MyInfoLib-NodeJs]%20Issue%20) for any other technical issues, and we will respond to you within 5 working days.