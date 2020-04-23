
# MyInfo NodeJS Connector

MyInfo NodeJS Connector aims to simplify consumer's integration effort with MyInfo by providing an easy to use Javascript library to integrate into your application.


## Contents

- [1. Installation](#installation)
- [2. Usage](#usage)
    - [2.1. Sample Code](#sample)
    - [2.2. Process Environment file (Config)](#config)    
- [3. Individual Helper Method](#helper)    
    - [3.1. Assembling Authorization Header](#authheader)
    - [3.2. Decrypt Data (JWE)](#jwe)
    - [3.3. Verify Signature (JWS)](#jws)
- [Change Logs](./CHANGELOG.md)




## <a name="installation"></a>1. Installation

### 1.1. Using npm:

``` 
$ npm install myinfolibrarynodejs 
```


## <a name="usage"></a>2. Usage

### <a name="sample"></a>2.1. Sample Code

```
var myInfoConnector = require('myinfo-connector-nodejs'); //Call constructor to initialize library and pass in the configurations.
let myinfoLib = new myInfoConnector(MYINFO_LIBRARY_CONFIG); // MYINFO_LIBRARY_CONFIG is the Process Environment file (in JSON format), please refer to Process Environment file in 2.2

/**
 * Call Token API + Person API
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

myinfoLib.callTokenAndPersonAPI(authCode, state, txnNo)
.then(data => {
    return data; // Person Data
})
.catch(error => {
    throw error;
});

```

    
### <a name="config"></a>2.2. Process Environment file
You are required to create an environment file (in JSON format) with the following process environments for this library. You may look at the sample Process Environment file [here](https://github.com/cheesiangcs/sg-verify-demo-app-v2/blob/master/your-vms-server/config/config.js). 

| Required Properties | Description |
| -------- | ----------- |
| CLIENT_SECURE_CERT_PASSPHRASE | Password of the private key. |
| CLIENT_SECURE_CERT | Alias of the application private key in P12 format. |
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



## <a name="helper"></a>3. Individual Helper Method

Under the hood, myInfoLibrary makes use of **SecurityController** and you may use the class as util methods to meet your application needs.

### <a name="authheader"></a>3.1. Assembling Authorization Header
This method takes in all the required parameters into a treemap and assemble the header.

```
var myInfoConnector = require('myInfoConnector')
let myinfoLib = new myInfoConnector(MYINFO_LIBRARY_CONFIG);
...
..
.
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

myinfoLib.generateAuthorizationHeader(url, params, method, strContentType, authType, appId, keyCertContent, privateKey);
```

### <a name="jwe"></a>3.2. Decrypt Data (JWE)
This method takes in the payload and the private key to decrypt the payload.
```
/**
 * Decyption JWE
 * 
 * This method takes in a JSON Web Encrypted object and will decrypt it using the
 * private key. This is required to decrypt the data from Person API
 * 
 * @param {File} pemPrivateKey - Private Key string, PEM format
 * @param {string} compactJWE - data in compact serialization format - header.encryptedKey.ivciphertext.tag
 * @returns {Promise} -  Decrypted data
*/

myinfoLib.decryptJWE(pemPrivateKey, compactJWE);
```

### <a name="jws"></a>3.3. Verify Signature (JWS)
This method takes in the JSON Web Signature and the public key for verification.
```
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

myinfoLib.verifyJWS(publicKey, compactJWS);
```



## Reporting Issue

You may contact our [support](mailto:support@myinfo.gov.sg?subject=[MyInfoLib-NodeJs]%20Issue%20) for any other technical issues, and we will respond to you within 5 working days.