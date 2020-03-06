# Zoho API OAuth Client - PHP SDK

This Library is a SDK in PHP that simplifies the usage of the Zoho Apis, providing a simple client to deal
with the OAuth2 implementation, as described here: [https://www.zoho.com/accounts/protocol/oauth.html](https://www.zoho.com/accounts/protocol/oauth.html)

The library aims to provide you with a streamlined way to generate the access_token you need to call 
any zoho api you need.

## Installation

```
composer require weble/zohoclient 
```

## Example Usage (Offline Mode)
```php
require_once './vendor/autoload.php';

$client = new \Weble\ZohoClient\OAuthClient('{CLIENT_ID}', '{CLIENT_SECRET}');
$client->setRefreshToken('{REFRESH_TOKEN}');
$client->setRegion(\Weble\ZohoClient\Enums\Region::us());
$client->offlineMode();

// Done!
$accessToken = $client->getAccessToken();

// Check if it's expired
$isExpired = $client->accessTokenExpired();

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
