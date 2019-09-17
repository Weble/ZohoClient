<?php

namespace Webleit\ZohoCrmApi\Test;

use PHPUnit\Framework\TestCase;
use Weble\ZohoClient\OAuthClient;


/**
 * Class ClassNameGeneratorTest
 * @package Webleit\ZohoBooksApi\Test
 */
class ApiTest extends TestCase
{
    /**
     * @var OAuthClient
     */
    protected static $client;
    /**
     * setup
     */
    public static function setUpBeforeClass ()
    {

        $authFile = __DIR__ . '/config.example.json';
        if (file_exists(__DIR__ . '/config.json')) {
            $authFile = __DIR__ . '/config.json';
        }

        $auth = json_decode(file_get_contents($authFile));

        $client = new OAuthClient($auth->client_id, $auth->client_secret);
        $client->setRefreshToken($auth->refresh_token);

        self::$client = $client;
    }

    /**
     * @test
     */
    public function hasAccessToken ()
    {
        $accessToken = self::$client->getAccessToken();
        $this->assertTrue(strlen($accessToken) > 0);
    }
}