# Zoho API OAuth Client - PHP SDK

[![Latest Version on Packagist](https://img.shields.io/packagist/v/weble/zohoclient.svg?style=flat-square)](https://packagist.org/packages/weble/zohoclient)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/weble/zohoclient/run-tests?label=tests&style=flat-square)](https://github.com/weble/zohoclient/actions?query=workflow%3Arun-tests)
[![Total Downloads](https://img.shields.io/packagist/dt/weble/zohoclient.svg?style=flat-square)](https://packagist.org/packages/weble/zohoclient)

This Library is a SDK in PHP that simplifies the usage of the Zoho Apis, providing a simple client to deal
with the OAuth2 implementation, as described here: [https://www.zoho.com/accounts/protocol/oauth.html](https://www.zoho.com/accounts/protocol/oauth.html)

The library aims to provide you with a streamlined way to generate the access_token you need to call 
any zoho api you need.

## Installation

```
composer require weble/zohoclient 
```

## Example Usages (Offline Mode)

### Retrieve the url to authenticate against ZOHO and retrieve the access Token / Refresh Token for the first time
```php
require_once './vendor/autoload.php';

$client = new \Weble\ZohoClient\OAuthClient('{CLIENT_ID}', '{CLIENT_SECRET}', '{REGION}', '{REDIRECTURL}');
$client->offlineMode(); // this needs to be set if you want to be able to refresh the token
$client->promptForConsent(); // Optional setting: Prompts for user consent each time your app tries to access user credentials.

// Get the url
$client->setScopes([]); // Set the zoho scopes you need, see https://www.zoho.com/crm/developer/docs/api/v2/scopes.html
$url = $client->getAuthorizationUrl();
$state = $client->getState(); // Get the state for security, and save it (usually in session)

redirect($url); // Do your redirection as you prefer

// Wait for the user to redirect...

// In the redirection page, check for the state you got before and that you should've stored
if ($state !== $_GET['state']) {
    throw new \Exception('Someone is tampering with the oauth2 request');
}

// Try to get an access token (using the authorization code grant)
try {
    $client->setGrantCode($_GET['code']);
    
    // if you set the offline mode, you can also get the refresh token here (and store it)
    $refreshToken = $client->getRefreshToken();
    
    // get the access token (and store it probably)
    $token = $client->getAccessToken();
    
} catch (\Exception $e) {
    // handle your exceptions
}
```

## Example Usage (Online Mode)
```php
require_once './vendor/autoload.php';

$client = new \Weble\ZohoClient\OAuthClient('{CLIENT_ID}', '{CLIENT_SECRET}');
$client->setRegion(\Weble\ZohoClient\Enums\Region::us());
$client->setRedirectUri('{REDIRECT_URI_OF_YOUR_APP}');
$client->onlineMode();

$authUrl = $client->getGrantCodeConsentUrl();

// Redirect your user to the $authUrl

// When you get redirected back to your REDIRECT_URI_OF_YOUR_APP
$code = $_GET['code']; // or \Weble\ZohoClient\OAuthClient::parseGrantTokenFromUrl($url);
$client->setGrantCode($code);

// Done!
$accessToken = $client->getAccessToken();

// Check if it's expired
$isExpired = $client->accessTokenExpired();

```


## Modes
Zoho OAuth v2 provides two main ways to obtain an access token:

### 1) Online
This is the "standard" way used when you need to ask you zoho users to authenticate with their zoho account, and then
call the apis on their behalf (ie: as if they were logged in an where quering the apis). This is usually done to login as them
and automate some kind of process through the apis, or when you just need a quick access to their profile, for example
to login / get their name / get their profile.

The Online mode is the easiest to implement, but generates an access token that expires, usually after 1 hour, so it can't be stored
or renewed without a refresh token, that you won't get with this method. After the token expire, you will need to ask
your users to login again.

### 2) Offline
This one is preferred when you need to autonomously renew the access token yourself. Used in all the "machine to machine"
communication, and it's the best way when you are using the apis to, for example, sync with a 3rd party application, 
like your ERP or Ecommerce website.

The offline mode generates both an access token and a refresh token, than you **need** to store locally, and use it to refresh
the access token when it expires.

The library deals with the refresh process automatically, so you don't need to worry about that.
    
## Contributing

Finding bugs, sending pull requests or improving the docs - any contribution is welcome and highly appreciated

## Versioning

Semantic Versioning Specification (SemVer) is used.

## Copyright and License

Copyright Weble Srl under the MIT license.
