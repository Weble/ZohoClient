<?php

namespace Webleit\ZohoCrmApi\Test;

use Asad\OAuth2\Client\Provider\ZohoUser;
use Cache\Adapter\PHPArray\ArrayCachePool;
use GuzzleHttp\Psr7\Uri;
use PHPUnit\Framework\TestCase;
use stdClass;
use Weble\ZohoClient\Enums\Region;
use Weble\ZohoClient\OAuthClient;

class ApiTest extends TestCase
{
    private string $cachePrefix = 'testing_';
    protected OAuthClient $client;

    /**
     * Used for Persistent in-memory storage
     * @var array<string,mixed[]> $cache
     */
    protected static array $cache = [];

    protected static function loadAuth(): stdClass
    {
        $authFile = __DIR__ . '/config.example.json';
        if (file_exists(__DIR__ . '/config.json')) {
            $authFile = __DIR__ . '/config.json';
        }

        $contents = file_get_contents($authFile);
        if (!$contents) {
            return new stdClass();
        }

        $auth = json_decode($contents, null, 512, JSON_THROW_ON_ERROR);

        $envConfig = $_SERVER['OAUTH_CONFIG'] ?? $_ENV['OAUTH_CONFIG'] ?? null;
        if ($envConfig) {

            $auth = json_decode($envConfig, null, 512, JSON_THROW_ON_ERROR);
        }

        /** @var stdClass $auth */
        $region = Region::US;
        if ($auth->region) {
            $region = (string) $auth->region;
        }

        $auth->region = $region;

        return $auth;
    }

    /**
     * setup
     */
    protected function setUp(): void
    {
        $auth = self::loadAuth();

        $pool = new ArrayCachePool(null, self::$cache);

        $this->client = new OAuthClient($auth->client_id, $auth->client_secret);
        $this->client->setRefreshToken($auth->refresh_token);
        $this->client->setRegion($auth->region);
        $this->client->offlineMode();
        $this->client->useCache($pool);
        $this->client->setRedirectUri($auth->redirect_uri);
        $this->client->setCachePrefix($this->cachePrefix);
    }

    /**
     * @test
     */
    public function canGenerateAuthUrl(): void
    {
        $url = $this->client->getAuthorizationUrl();
        $this->assertIsString($url);
        $state = $this->client->getState();
        $this->assertIsString($state);
    }

    /**
     * @test
     */
    public function canParseGrantTokenFromUrl(): void
    {
        $uri = new Uri('https://test.domain?code=test');
        $code = OAuthClient::parseGrantTokenFromUrl($uri);
        $this->assertEquals('test', $code);
    }

    /**
     * @test
     */
    public function canGetAccessToken(): void
    {
        //Get Token
        $firstToken = $this->client->getAccessToken();
        $this->assertIsString($firstToken);
        //check cache
        $this->assertArrayHasKey($this->cachePrefix . 'access_token', self::$cache);
        $this->assertEquals($firstToken, self::$cache[$this->cachePrefix . 'access_token'][0]);
        $check = $this->client->accessTokenExpired();
        $this->assertFalse($check);

        //Refresh Token
        $secondToken = $this->client->refreshAccessToken();
        $this->assertIsString($secondToken);
        //check cache
        $this->assertArrayHasKey($this->cachePrefix . 'access_token', self::$cache);
        $this->assertEquals($secondToken, self::$cache[$this->cachePrefix . 'access_token'][0]);
        $check = $this->client->accessTokenExpired();
        $this->assertFalse($check);

        //Assert token is different
        $this->assertEquals($secondToken, $this->client->getAccessToken());
        $this->assertNotEquals($firstToken, $secondToken);

        //Make sure the token expires in an hour like Zoho tells us
        $hourFromNow = (new \DateTime())->add(new \DateInterval("PT1H"))->format('U');
        $accessToken = $this->client->getAccessTokenObject();
        $this->assertLessThanOrEqual($hourFromNow, $accessToken->getExpires());
    }

    /**
     * @test
     */
    public function canUseCache(): void
    {
        $firstToken = $this->client->getAccessToken();
        $secondToken = $this->client->getAccessToken();
        $this->assertEquals($firstToken, $secondToken);
    }


    /**
     * @test
     */
    public function canGetResourceOwner(): void
    {
        $owner = $this->client->getResourceOwner();
        $this->assertInstanceOf(ZohoUser::class, $owner);
    }

    /**
     * @test
     */
    public function canSwitchOnline(): void
    {
        $this->client->onlineMode();
        $this->assertTrue($this->client->isOnline());
        $this->assertFalse($this->client->isOffline());
    }

    /**
     * @test
     */
    public function canGetRegion(): void
    {
        $this->assertEquals('us', $this->client->getRegion());
    }
}
