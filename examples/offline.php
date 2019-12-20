<?php

$root = dirname(__DIR__);
require_once $root.'/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable($root);
$dotenv->load();

$client = new \Weble\ZohoClient\OAuthClient(getenv('CLIENT_ID_OFFLINE'), getenv('CLIENT_SECRET_OFFLINE'));
$client->setRedirectUri(getenv('REDIRECT_URI_OFFLINE'));
$client->offlineMode();
$client->useCache(new \Cache\Adapter\PHPArray\ArrayCachePool());
$client->setRegion(getenv('REGION'));

$code = $_REQUEST['code'] ?? false;

if ($code) {
    try {
        $client->setGrantCode($code)->generateTokens();
        $refreshToken = $client->getRefreshToken();
        $accessToken = $client->getAccessToken();
    } catch (\Weble\ZohoClient\Exception\ApiError $e) {
        var_dump($e);
    }

    ?>
    <div>
        <strong>Access Token</strong> <?php echo $accessToken; ?>
    </div>
    <div>
        <strong>Refresh Token</strong> <?php echo $client->getRefreshToken(); ?>
    </div>
    <?php
} else {
    ?>
    <div>
        <a href="<?php echo $client->getGrantCodeConsentUrl(); ?>">
            Authorize Zoho for Offline Usage
        </a>( <?php echo $client->getGrantCodeConsentUrl(); ?> )

    </div>
    <?php
}
