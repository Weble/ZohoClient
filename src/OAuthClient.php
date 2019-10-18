<?php

namespace Weble\ZohoClient;

use Psr\Cache;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\UriInterface;
use Weble\ZohoClient\Exception\ApiError;
use Weble\ZohoClient\Exception\GrantCodeNotSetException;

/**
 * Class OAuthClient
 * @see https://github.com/opsway/zohobooks-api
 * @package Webleit\ZohoBooksApi
 */
class OAuthClient
{
    const OAUTH_GRANT_URL_US = "https://accounts.zoho.com/oauth/v2/auth";
    const OAUTH_GRANT_URL_EU = "https://accounts.zoho.eu/oauth/v2/auth";
    const OAUTH_GRANT_URL_CN = "https://accounts.zoho.cn/oauth/v2/auth";

    const OAUTH_API_URL_US = "https://accounts.zoho.com/oauth/v2/token";
    const OAUTH_API_URL_EU = "https://accounts.zoho.eu/oauth/v2/token";
    const OAUTH_API_URL_CN = "https://accounts.zoho.cn/oauth/v2/token";

    const DC_US = 'com';
    const DC_EU = 'eu';
    const DC_CN = 'cn';
    const DC_IN = 'in';

    /**
     * @var string
     */
    protected $dc = self::DC_US;

    /**
     * @var \GuzzleHttp\Client
     */
    protected $client;

    /**
     * @var string
     */
    protected $grantCode;

    /**
     * @var string
     */
    protected $clientSecret;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $accessToken = '';

    /**
     * @var \DateTime
     */
    protected $accessTokenExpiration;

    /**
     * @var string
     */
    protected $refreshToken = '';

    /**
     * @var Cache\CacheItemPoolInterface
     */
    protected $cache;

    /**
     * Client constructor.
     *
     * @param $clientId
     * @param $clientSecret
     * @param $grantCode
     */
    public function __construct($clientId, $clientSecret, $refreshToken = null)
    {
        $this->client = new \GuzzleHttp\Client();

        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;

        if ($refreshToken) {
            $this->setRefreshToken($refreshToken);
        }
    }

    /**
     * @return string
     */
    public function getOAuthApiUrl()
    {
        switch ($this->dc) {
            case self::DC_CN:
                return self::OAUTH_API_URL_CN;
                break;
            case self::DC_EU:
                return self::OAUTH_API_URL_EU;
                break;
            case self::DC_US:
            default:
                return self::OAUTH_API_URL_US;
                break;
        }
    }

    /**
     * @return string
     */
    public function getOAuthGrantUrl()
    {
        switch ($this->dc) {
            case self::DC_CN:
                return self::OAUTH_GRANT_URL_CN;
                break;
            case self::DC_EU:
                return self::OAUTH_GRANT_URL_EU;
                break;
            case self::DC_US:
            default:
                return self::OAUTH_GRANT_URL_US;
                break;
        }
    }

    /**
     * @param  string  $grantCode
     *
     * @return $this
     */
    public function setGrantCode(string $grantCode)
    {
        $this->grantCode = $grantCode;
        return $this;
    }

    /**
     * @param  Cache\CacheItemPoolInterface  $cacheItemPool
     *
     * @return $this
     */
    public function useCache(Cache\CacheItemPoolInterface $cacheItemPool)
    {
        $this->cache = $cacheItemPool;
        return $this;
    }

    /**
     * @return \GuzzleHttp\Client
     */
    public function getHttpClient(): \GuzzleHttp\Client
    {
        return $this->client;
    }

    /**
     * @return mixed
     * @throws ApiError
     * @throws GrantCodeNotSetException
     */
    public function getAccessToken()
    {
        if ($this->accessTokenExpired()) {
            return $this->generateAccessToken();
        }

        if ($this->accessToken) {
            return $this->accessToken;
        }

        if (!$this->cache) {
            return $this->generateAccessToken();
        }

        try {
            $cachedAccessToken = $this->cache->getItem('zoho_crm_access_token');

            $value = $cachedAccessToken->get();
            if ($value) {
                return $value;
            }

            return $this->generateAccessToken();

        } catch (InvalidArgumentException $e) {
            return $this->generateAccessToken();
        }
    }

    /**
     * @return bool
     * @throws \Exception
     */
    public function accessTokenExpired(): bool
    {
        if (!$this->accessTokenExpiration) {
            return false;
        }

        return ($this->accessTokenExpiration < new \DateTime());
    }

    /**
     * @return mixed
     * @throws ApiError
     * @throws GrantCodeNotSetException
     */
    public function generateAccessToken()
    {
        $response = $this->client->post($this->getOAuthApiUrl(), [
            'query' => [
                'refresh_token' => $this->getRefreshToken(),
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'grant_type' => 'refresh_token'
            ]
        ]);

        $data = json_decode($response->getBody());

        if (!isset($data->access_token)) {
            throw new ApiError(@$data->error);
        }

        $this->setAccessToken($data->access_token, $data->expires_in_sec);

        return $data->access_token;
    }

    /**
     * @return mixed|string
     * @throws ApiError
     * @throws GrantCodeNotSetException
     */
    public function getRefreshToken()
    {
        if ($this->refreshToken) {
            return $this->refreshToken;
        }

        if (!$this->cache) {
            return $this->generateRefreshToken();
        }

        try {
            $cachedAccessToken = $this->cache->getItem('zoho_crm_refresh_token');

            $value = $cachedAccessToken->get();
            if ($value) {
                return $value;
            }

            $accessToken = $this->generateRefreshToken();
            $cachedAccessToken->set($accessToken);
            $cachedAccessToken->expiresAfter(60 * 59);
            $this->cache->save($cachedAccessToken);

            return $accessToken;

        } catch (InvalidArgumentException $e) {
            return $this->generateRefreshToken();
        }
    }

    /**
     * @param $token
     * @param  int  $expiresInSeconds
     *
     * @return $this|mixed
     */
    public function setAccessToken($token, $expiresInSeconds = 3600)
    {
        $this->accessToken = $token;
        $this->accessTokenExpiration = (new \DateTime())->add(new \DateInterval('PT'.$expiresInSeconds.'S'));

        if (!$this->cache) {
            return $this;
        }

        try {
            $cachedToken = $this->cache->getItem('zoho_crm_access_token');

            $cachedToken->set($token);
            $cachedToken->expiresAfter($expiresInSeconds);
            $this->cache->save($cachedToken);

            return $this;

        } catch (InvalidArgumentException $e) {
            return $this;
        }
    }

    /**
     * @param $token
     * @param  int  $expiresInSeconds
     *
     * @return $this|mixed
     */
    public function setRefreshToken($token, $expiresInSeconds = 3600)
    {
        $this->refreshToken = $token;

        if (!$this->cache) {
            return $this;
        }

        try {
            $cachedToken = $this->cache->getItem('zoho_crm_refresh_token');

            $cachedToken->set($token);
            $cachedToken->expiresAfter($expiresInSeconds);
            $this->cache->save($cachedToken);

            return $this;

        } catch (InvalidArgumentException $e) {
            return $this;
        }
    }


    /**
     * @return string
     * @throws ApiError
     * @throws GrantCodeNotSetException
     */
    protected function generateRefreshToken()
    {
        if (!$this->grantCode) {
            throw new GrantCodeNotSetException('You need to pass a grant code to use the Api. To generate a grant code visit '.$this->getGrantCodeConsentUrl());
        }

        $response = $this->client->post($this->getOAuthApiUrl(), [
            'query' => [
                'code' => $this->grantCode,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'state' => 'testing',
                'grant_type' => 'authorization_code',
                'scope' => 'ZohoCRM.users.all,ZohoCRM.settings.all,ZohoCRM.modules.all,ZohoCRM.org.all'
            ]
        ]);

        $data = json_decode($response->getBody());

        if (!isset($data->refresh_token)) {
            throw new ApiError(@$data->error);
        }

        $this->setAccessToken($data->access_token, $data->expires_in_sec);
        $this->setRefreshToken($data->refresh_token, $data->expires_in_sec);

        return $data->refresh_token;
    }

    /**
     * @param $redirectUri
     *
     * @return string
     */
    public function getGrantCodeConsentUrl($redirectUri)
    {
        return $this->getOAuthGrantUrl().'?'.http_build_query([
                'client_id' => $this->clientId,
                'state' => 'testing',
                'redirect_uri' => $redirectUri,
                'response_type' => 'code',
                'access_type' => 'offline',
                'scope' => 'ZohoCRM.users.all,ZohoCRM.settings.all,ZohoCRM.modules.all,ZohoCRM.org.all'
            ]);
    }

    /**
     * @param  UriInterface  $uri
     *
     * @return string|null
     */
    public static function parseGrantTokenFromUrl(UriInterface $uri)
    {
        $query = $uri->getQuery();
        $data = explode('&', $query);

        foreach ($data as &$d) {
            $d = explode("=", $d);
        }

        if (isset($data['code'])) {
            return $data['code'];
        }

        return null;
    }


    public function euRegion()
    {
        $this->dc = OAuthClient::DC_EU;

        return $this;
    }

    public function inRegion()
    {
        $this->dc = OAuthClient::DC_IN;

        return $this;
    }

    public function usRegion()
    {
        $this->dc = OAuthClient::DC_US;
        return $this;
    }

    public function cnRegion()
    {
        $this->dc = OAuthClient::DC_CN;
        return $this;
    }
}