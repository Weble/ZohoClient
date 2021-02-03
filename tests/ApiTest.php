<?php

namespace Webleit\ZohoCrmApi\Test;

use Cache\Adapter\Filesystem\FilesystemCachePool;
use League\Flysystem\Adapter\Local;
use League\Flysystem\Filesystem;
use PHPUnit\Framework\TestCase;
use stdClass;
use Weble\ZohoClient\Enums\Region;
use Weble\ZohoClient\OAuthClient;

class ApiTest extends TestCase
{
    /**
     * @var OAuthClient
     */
    protected static $client;

    /**
     * setup
     */
    public static function setUpBeforeClass(): void
    {
        $auth = self::loadAuth();

        $client = self::createClient($auth);

        self::$client = $client;
    }

    protected static function createClient($auth): OAuthClient
    {
        $filesystemAdapter = new Local(__DIR__ . '/temp');
        $filesystem = new Filesystem($filesystemAdapter);
        $pool = new FilesystemCachePool($filesystem);

        $client = new OAuthClient($auth->client_id, $auth->client_secret);
        $client->setAccessToken($auth->access_token ?? uniqid());
        $client->setRefreshToken($auth->refresh_token);
        $client->setGrantCode($auth->grant_code);
        $client->setRegion($auth->region);
        $client->offlineMode();
        $client->useCache($pool);
        $client->setRedirectUri($auth->redirect_uri);

        return $client;
    }

    protected static function loadAuth(): stdClass
    {
        $authFile = __DIR__ . '/config.example.json';
        if (file_exists(__DIR__ . '/config.json')) {
            $authFile = __DIR__ . '/config.json';
        }

        $auth = json_decode(file_get_contents($authFile));

        $envConfig = $_SERVER['OAUTH_CONFIG'] ?? $_ENV['OAUTH_CONFIG'] ?? null;
        var_dump($envConfig);
        if ($envConfig) {
            $auth = json_decode(file_get_contents($authFile));
        }

        $region = Region::US;
        if ($auth->region) {
            $region = $auth->region;
        }

        $auth->region = $region;

        return $auth;
    }

    /**
     * @test
     */
    public function canGenerateAuthUrl()
    {
        $url = self::$client->getAuthorizationUrl();
        $this->assertIsString($url);

        echo $url;
    }

    /**
     * @test
     */
    public function canRefreshAccessToken()
    {
        $accessToken = self::$client->refreshAccessToken();
        $this->assertTrue(strlen($accessToken) > 0);
    }

    /**
     * @test
     */
    public function canCacheAccessToken()
    {
        $accessToken = self::$client->refreshAccessToken();
        $this->assertTrue(strlen($accessToken) > 0);

        $auth = self::loadAuth();

        // Recreate the client so it's not locally stored
        self::createClient($auth);

        $this->assertTrue(strlen($accessToken) > 0);
    }
}
