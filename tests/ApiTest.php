<?php

namespace Webleit\ZohoCrmApi\Test;

use PHPUnit\Framework\TestCase;
use Weble\ZohoClient\Enums\Region;
use Weble\ZohoClient\OAuthClient;
use League\Flysystem\Adapter\Local;
use League\Flysystem\Filesystem;
use Cache\Adapter\Filesystem\FilesystemCachePool;

class ApiTest extends TestCase
{
    /**
     * @var OAuthClient
     */
    protected static $client;

    /**
     * setup
     */
    public static function setUpBeforeClass()
    {

        $authFile = __DIR__ . '/config.example.json';
        if (file_exists(__DIR__ . '/config.json')) {
            $authFile = __DIR__ . '/config.json';
        }

        $auth = json_decode(file_get_contents($authFile));
        $region = Region::us();
        if ($auth->region) {
            $region = Region::make($auth->region);
        }

        $filesystemAdapter = new Local(sys_get_temp_dir());
        $filesystem        = new Filesystem($filesystemAdapter);
        $pool = new FilesystemCachePool($filesystem);

        $client = new OAuthClient($auth->client_id, $auth->client_secret);
        $client->setRefreshToken($auth->refresh_token);
        $client->setGrantCode($auth->grant_code);
        $client->setRegion($region);
        $client->offlineMode();
        $client->useCache($pool);

        self::$client = $client;
    }

    /**
     * @test
     */
    public function hasAccessToken()
    {
        $accessToken = self::$client->getAccessToken();
        $this->assertTrue(strlen($accessToken) > 0);
    }

    /**
     * @test
     */
    public function canGenerateAccessToken()
    {
        $accessToken = self::$client->refreshAccessToken();
        $this->assertTrue(strlen($accessToken) > 0);
    }
}
