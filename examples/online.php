<?php

$root = dirname(__DIR__);
require_once $root.'/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable($root);
$dotenv->load();

$client = new \Weble\ZohoClient\OAuthClient(getenv('CLIENT_ID'), getenv('CLIENT_SECRET'));
$client->setRedirectUri(getenv('REDIRECT_URI'));
$client->onlineMode();
$client->useCache(new \Cache\Adapter\PHPArray\ArrayCachePool());

$client->setRegion(getenv('REGION'));

$code = $_REQUEST['code'] ?? false;

if ($code) {
    try {
        $client->setGrantCode($code);
        $accessToken = $client->getAccessToken();
    } catch (\Weble\ZohoClient\Exception\ApiError $e) {
        var_dump($e);
    }

    ?>
    <div>
        <strong>Access Token</strong> <?php echo $accessToken; ?>
    </div>

    <?php
} else {
    ?>
    <div>
        <a href="<?php echo $client->getGrantCodeConsentUrl(); ?>">
            Authorize Zoho for Online Usage
        </a>( <?php echo $client->getGrantCodeConsentUrl(); ?> )

    </div>
    <?php
}
