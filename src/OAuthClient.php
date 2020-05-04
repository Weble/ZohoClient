<?php

namespace Weble\ZohoClient;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use Psr\Cache;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\UriInterface;
use Weble\ZohoClient\Enums\Region;
use Weble\ZohoClient\Exception\AccessDeniedException;
use Weble\ZohoClient\Exception\ApiError;
use Weble\ZohoClient\Exception\CannotGenerateAccessToken;
use Weble\ZohoClient\Exception\CannotGenerateRefreshToken;
use Weble\ZohoClient\Exception\GrantCodeNotSetException;
use Weble\ZohoClient\Exception\InvalidGrantCodeException;
use Weble\ZohoClient\Exception\RefreshTokenNotSet;

class OAuthClient
{
    const ZOHO_CLIENT_API_URL = 'https://accounts.zoho';
    const ZOHO_CLIENT_API_PATH = '/oauth/v2';

    /** @var Region */
    protected $region;
    /** @var Client */
    protected $client;
    /** @var string|null */
    protected $grantCode;
    /** @var string|null */
    protected $redirectUri;
    /** @var array<string> */
    protected $scopes = ['AaaServer.profile.READ'];
    /** @var bool */
    protected $offlineMode = false;
    /** @var string */
    protected $state = 'test';
    /** @var string */
    protected $clientSecret;
    /** @var string */
    protected $clientId;
    /** @var string|null */
    protected $accessToken;
    /** @var \DateTime|null */
    protected $accessTokenExpiration;
    /** @var string|null */
    protected $refreshToken;
    /** @var Cache\CacheItemPoolInterface|null */
    protected $cache;

    public function __construct(string $clientId, string $clientSecret)
    {
        $this->client = new Client();
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;

        $this->region = Region::us();
    }

    public static function parseGrantTokenFromUrl(UriInterface $uri): ?string
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

    public function getRegion(): Region
    {
        return $this->region;
    }

    public function setRegion(Region $region): self
    {
        $this->region = $region;

        return $this;
    }

    public function setGrantCode(string $grantCode): self
    {
        $this->grantCode = $grantCode;

        return $this;
    }

    public function setState(string $state): self
    {
        $this->state = $state;

        return $this;
    }

    public function setScopes(array $scopes): self
    {
        $this->scopes = $scopes;

        return $this;
    }

    public function onlineMode(): self
    {
        $this->offlineMode = false;

        return $this;
    }

    public function isOffline(): bool
    {
        return $this->offlineMode;
    }

    public function isOnline(): bool
    {
        return ! $this->offlineMode;
    }

    public function setRedirectUri(string $redirectUri): self
    {
        $this->redirectUri = $redirectUri;

        return $this;
    }

    public function useCache(Cache\CacheItemPoolInterface $cacheItemPool): self
    {
        $this->cache = $cacheItemPool;

        return $this;
    }

    public function getHttpClient(): Client
    {
        return $this->client;
    }

    /**
     * @throws ApiError
     * @throws CannotGenerateAccessToken
     * @throws CannotGenerateRefreshToken
     * @throws GrantCodeNotSetException
     * @throws RefreshTokenNotSet
     */
    public function getAccessToken(): string
    {
        if ($this->accessTokenExpired() && $this->refreshToken && $this->offlineMode) {
            return $this->refreshAccessToken();
        }

        if ($this->accessToken) {
            return $this->accessToken;
        }

        if (! $this->cache) {
            $this->generateTokens();

            if (! $this->accessToken) {
                throw new CannotGenerateAccessToken();
            }

            return $this->accessToken;
        }

        try {
            $cachedAccessToken = $this->cache->getItem('zoho_crm_access_token');

            $value = $cachedAccessToken->get();
            if ($value) {
                return $value;
            }

            $this->generateTokens();

            if (! $this->accessToken) {
                throw new CannotGenerateAccessToken();
            }

            return $this->accessToken;
        } catch (InvalidArgumentException $e) {
            $this->generateTokens();

            if (! $this->accessToken) {
                throw new CannotGenerateAccessToken();
            }

            return $this->accessToken;
        }
    }

    public function setAccessToken(string $token, int $expiresInSeconds = 3600): self
    {
        $this->accessToken = $token;
        $this->accessTokenExpiration = (new \DateTime())->add(new \DateInterval('PT' . $expiresInSeconds . 'S'));

        if ($this->cache === null) {
            return $this;
        }

        try {
            $cachedToken = $this->cache->getItem('zoho_crm_access_token');

            $cachedToken->set($token);
            $cachedToken->expiresAfter($expiresInSeconds);
            $this->cache->save($cachedToken);
        } catch (InvalidArgumentException $e) {
        }

        return $this;
    }

    public function accessTokenExpired(): bool
    {
        if (! $this->accessTokenExpiration) {
            return false;
        }

        return ($this->accessTokenExpiration < new \DateTime());
    }

    /**
     * @throws AccessDeniedException
     * @throws ApiError
     * @throws CannotGenerateRefreshToken
     * @throws GrantCodeNotSetException
     * @throws InvalidGrantCodeException
     * @throws RefreshTokenNotSet
     */
    public function refreshAccessToken(): string
    {
        if (! $this->hasRefreshToken()) {
            try {
                if ($this->generateTokens()->hasAccessToken()) {
                    return $this->accessToken;
                }
            } catch (GrantCodeNotSetException $e) {
                throw new RefreshTokenNotSet();
            }
        }

        $response = $this->client->post($this->getOAuthApiUrl(), [
            'query' => [
                'refresh_token' => $this->getRefreshToken(),
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'grant_type' => 'refresh_token',
            ],
        ]);

        $data = json_decode($response->getBody());

        if (! isset($data->access_token)) {
            if (isset($data->error) && $data->error === 'access_denied') {
                throw new AccessDeniedException();
            }

            throw new ApiError($data->error ?? 'Generic Error');
        }

        $this->setAccessToken($data->access_token, $data->expires_in_sec ?? ($data->expires_in ?? 3600));

        return $data->access_token;
    }

    public function hasRefreshToken(): bool
    {
        return strlen($this->refreshToken) > 0;
    }

    public function hasAccessToken(): bool
    {
        return strlen($this->accessToken) > 0;
    }

    /**
     * @throws AccessDeniedException
     * @throws ApiError
     * @throws GrantCodeNotSetException
     * @throws InvalidGrantCodeException
     */
    public function generateTokens(): self
    {
        if ($this->hasRefreshToken() && $this->offlineMode === true) {
            try {
                $this->refreshAccessToken();

                return $this;
            } catch (CannotGenerateRefreshToken $e) {
            } catch (RefreshTokenNotSet $e) {
            }
        }

        if (! $this->grantCode) {
            throw new GrantCodeNotSetException();
        }

        try {
            $response = $this->client->post($this->getOAuthApiUrl(), [
                'query' => [
                    'code' => $this->grantCode,
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'state' => $this->state,
                    'grant_type' => 'authorization_code',
                    'scope' => implode(",", $this->scopes),
                    'redirect_uri' => $this->redirectUri,
                ],
            ]);
        } catch (ClientException $e) {
            $body = $e->getResponse()->getBody()->getContents();

            throw new ApiError($body, $e->getCode());
        }

        $data = json_decode($response->getBody());

        if (isset($data->error)) {
            throw new InvalidGrantCodeException();
        }

        $this->setAccessToken($data->access_token ?? '', $data->expires_in_sec ?? $data->expires_in ?? 3600);

        if (isset($data->refresh_token)) {
            $this->setRefreshToken($data->refresh_token);
        }

        return $this;
    }

    public function getOAuthApiUrl(): string
    {
        return $this->getBaseUrl() . '/token';
    }

    public function getBaseUrl(): string
    {
        return self::ZOHO_CLIENT_API_URL . $this->region->getValue() . self::ZOHO_CLIENT_API_PATH;
    }

    /**
     * @throws ApiError
     * @throws CannotGenerateRefreshToken
     * @throws GrantCodeNotSetException
     */
    public function getRefreshToken(): string
    {
        if ($this->refreshToken) {
            return $this->refreshToken;
        }

        if ($this->cache === null) {
            $this->generateTokens();

            if (! $this->refreshToken) {
                throw new ApiError('Cannot generate a refresh Token');
            }
        }

        try {
            $cachedRefreshToken = $this->cache->getItem('zoho_crm_refresh_token');

            $value = $cachedRefreshToken->get();
            if ($value) {
                return $value;
            }

            $this->generateTokens();

            if (! $this->refreshToken) {
                throw new CannotGenerateRefreshToken();
            }

            return $this->refreshToken;
        } catch (InvalidArgumentException $e) {
            return $this->generateTokens()->getRefreshToken();
        }
    }

    public function setRefreshToken(string $token): self
    {
        $this->refreshToken = $token;

        if (! $this->cache) {
            return $this;
        }

        try {
            $cachedToken = $this->cache->getItem('zoho_crm_refresh_token');

            $cachedToken->set($token);
            $this->cache->save($cachedToken);
        } catch (InvalidArgumentException $e) {
        }

        return $this;
    }

    /**
     * @return Region[]
     */
    public function availableRegions(): array
    {
        return Region::getAll();
    }

    public function revokeRefreshToken(?string $refreshToken = null): self
    {
        if ($refreshToken === null) {
            $refreshToken = $this->refreshToken;
        }

        try {
            $this->client->post($this->getOAuthApiUrl() . '/revoke', [
                'query' => [
                    'token' => $refreshToken,
                ],
            ]);

            $this->setRefreshToken('');
        } catch (ClientException $e) {
            $body = $e->getResponse()->getBody()->getContents();

            throw new ApiError($body, $e->getCode());
        }

        return $this;
    }

    public function getGrantCodeConsentUrl(): string
    {
        $query = [
            'access_type' => $this->offlineMode ? 'offline' : 'online',
            'client_id' => $this->clientId,
            'state' => $this->state,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(',', $this->scopes),
        ];

        // In case we don't have a refresh token, and we need to get one (offline mode),
        // if the user has already logged in, we already got the refresh token previously, and we won't get
        // another one unless we force a new consent.
        // Beware that the max number of refresh tokens is 20, and creating a 21st will delete the first one making
        // it unusable, so STORE the refresh token the first time!
        if ($this->offlineMode() && ! $this->refreshToken) {
            $query['prompt'] = 'consent';
        }

        return $this->getOAuthGrantUrl() . '?' . http_build_query($query);
    }

    public function offlineMode(): self
    {
        $this->offlineMode = true;

        return $this;
    }

    public function getOAuthGrantUrl(): string
    {
        return $this->getBaseUrl() . '/auth';
    }
}
