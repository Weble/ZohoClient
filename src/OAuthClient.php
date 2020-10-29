<?php

namespace Weble\ZohoClient;

use GuzzleHttp\Exception\ClientException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
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
use Weble\ZohoClient\Provider\ZohoAccessToken;
use Weble\ZohoClient\Provider\ZohoProvider;
use Weble\ZohoClient\Provider\ZohoUser;

class OAuthClient
{
    const ZOHO_CLIENT_API_URL = 'https://accounts.zoho';
    const ZOHO_CLIENT_API_PATH = '/oauth/v2';

    /** @var Region */
    protected $region;
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
    /** @var ZohoAccessToken */
    protected $accessToken;
    /** @var string|null */
    protected $refreshToken;
    /** @var Cache\CacheItemPoolInterface|null */
    protected $cache;

    public function __construct(string $clientId, string $clientSecret)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->region = Region::us();
    }

    /**
     * Parse Grant Token from URL
     *
     * @param UriInterface $uri
     * @return string|null
     */
    public static function parseGrantTokenFromUrl(UriInterface $uri): ?string
    {
        parse_str($uri->getQuery(), $output);
        if (isset($output['code'])) {
            return $output['code'];
        }

        return null;
    }

    /**
     * Get the Zoho Region
     *
     * @return Region
     */
    public function getRegion(): Region
    {
        return $this->region;
    }

    /**
     * Set the Zoho Region
     *
     * @param Region $region
     * @return self
     */
    public function setRegion(Region $region): self
    {
        $this->region = $region;

        return $this;
    }

    /**
     * Set the Grant Code
     *
     * @param string $grantCode
     * @return self
     */
    public function setGrantCode(string $grantCode): self
    {
        $this->grantCode = $grantCode;

        return $this;
    }

    /**
     * Set the State
     *
     * @param string $state
     * @return self
     */
    public function setState(string $state): self
    {
        $this->state = $state;

        return $this;
    }

    /**
     * Set the Scopes
     *
     * @param array $scopes
     * @return self
     */
    public function setScopes(array $scopes): self
    {
        $this->scopes = $scopes;

        return $this;
    }

    /**
     * Set Offline Mode
     *
     * @return self
     */
    public function onlineMode(): self
    {
        $this->offlineMode = false;

        return $this;
    }

    /**
     * Check if is offline
     *
     * @return boolean
     */
    public function isOffline(): bool
    {
        return $this->offlineMode;
    }

    /**
     * Check is is online
     *
     * @return boolean
     */
    public function isOnline(): bool
    {
        return !$this->offlineMode;
    }

    /**
     * Set the redirect uri
     *
     * @param string $redirectUri
     * @return self
     */
    public function setRedirectUri(string $redirectUri): self
    {
        $this->redirectUri = $redirectUri;

        return $this;
    }

    /**
     * Set the cache pool to use
     *
     * @param Cache\CacheItemPoolInterface $cacheItemPool
     * @return self
     */
    public function useCache(Cache\CacheItemPoolInterface $cacheItemPool): self
    {
        $this->cache = $cacheItemPool;

        return $this;
    }

    /**
     * Get Access Token
     *
     * @return string
     *
     * @throws ApiError
     * @throws CannotGenerateAccessToken
     * @throws CannotGenerateRefreshToken
     * @throws GrantCodeNotSetException
     * @throws RefreshTokenNotSet
     */
    public function getAccessToken(): string
    {

        if ($this->accessTokenExpired() && $this->hasRefreshToken() && $this->isOffline()) {
            return $this->refreshAccessToken();
        }

        if ($this->hasAccessToken()) {
            return $this->accessToken;
        }

        //Theres no cache engine
        if (!$this->cache) {
            $this->generateTokens();

            if (!$this->accessToken) {
                throw new CannotGenerateAccessToken();
            }

            return $this->accessToken;
        }

        try {
            $cachedAccessToken = $this->cache->getItem('zoho_crm_access_token');

            $value = $cachedAccessToken->get();
            if (is_string($value)) {
                //This is the old way to get the token
                $this->accessToken = new AccessToken(
                    [
                        'access_token' => $value,
                        'expires_in' => $cachedAccessToken->getExpirationTimestamp() - time()
                    ]
                );
                return $value;
            } elseif ($value instanceof ZohoAccessToken) {
                $this->accessToken = $value;
                return $value->getToken();
            }

            //Nothing valid in the cache so lets get a new token
            $this->generateTokens();

            if (!$this->hasAccessToken()) {
                throw new CannotGenerateAccessToken();
            }

            return $this->accessToken;
        } catch (InvalidArgumentException $e) {
            $this->generateTokens();

            if (!$this->hasAccessToken()) {
                throw new CannotGenerateAccessToken();
            }

            return $this->accessToken->getToken();
        }
    }

    /**
     * Set the Access Token while also updating the cache
     *
     * @param ZohoAccessToken $token
     * @return self
     */
    public function setAccessToken(ZohoAccessToken $token): self
    {
        $this->accessToken = $token;

        if ($this->cache === null) {
            return $this;
        }

        try {
            $cachedToken = $this->cache->getItem('zoho_crm_access_token');
            $cachedToken->set($this->accessToken);
            $cachedToken->expiresAt($this->accessToken->getExpires());
            $this->cache->save($cachedToken);
        } catch (InvalidArgumentException $e) {
        }

        return $this;
    }

    /**
     * Check if the access token has expired
     *
     * @return boolean
     */
    public function accessTokenExpired(): bool
    {
        if (empty($this->accessToken)) {
            return false;
        }

        return $this->accessToken->hasExpired();
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
        if (!$this->hasRefreshToken()) {
            try {
                if ($this->generateTokens()->hasAccessToken()) {
                    return $this->accessToken;
                }
            } catch (GrantCodeNotSetException $e) {
                throw new RefreshTokenNotSet();
            }
        }

        try {
            $token = (new ZohoProvider([
                'clientId' => $this->clientId,
                'clientSecret' => $this->clientSecret,
            ]))->getAccessToken(
                'refresh_token',
                [
                    'refresh_token' => $this->getRefreshToken()
                ]
            );
            $this->setAccessToken($token);
            return $this->accessToken->getToken();
        } catch (IdentityProviderException $e) {
            $message = $e->getMessage();
            if ($message === 'access_denied') {
                throw new AccessDeniedException();
            }

            throw new ApiError($message ?? 'Generic Error');
        }
    }

    /**
     * Do we have a refresh token?
     *
     * @return boolean
     */
    public function hasRefreshToken(): bool
    {
        return strlen($this->refreshToken) > 0;
    }

    /**
     * Do we have an access token?
     *
     * @return boolean
     */
    public function hasAccessToken(): bool
    {
        return !empty($this->accessToken) && $this->accessToken instanceof ZohoAccessToken;
    }

    /**
     * @throws AccessDeniedException
     * @throws ApiError
     * @throws GrantCodeNotSetException
     * @throws InvalidGrantCodeException
     */
    public function generateTokens(): self
    {
        if ($this->hasRefreshToken() && $this->isOffline()) {
            try {
                $this->refreshAccessToken();

                return $this;
            } catch (CannotGenerateRefreshToken $e) {
            } catch (RefreshTokenNotSet $e) {
            }
        }

        //If you got here and you are questioning why you need to probably set ->offlineMode() on your oauth instance
        if (!$this->grantCode) {
            throw new GrantCodeNotSetException();
        }


        try {

            $token = (new ZohoProvider([
                'clientId' => $this->clientId,
                'clientSecret' => $this->clientSecret,
                'state' => $this->state,
                'redirectUri' => $this->redirectUri,
            ]))->getAccessToken(
                'authorization_code',
                [
                    'code' => $this->grantCode
                ]
            );

            $this->setRefreshToken($token->getRefreshToken());
            $this->setAccessToken($token);
            return $this->accessToken->getToken();
        } catch (IdentityProviderException $e) {
            $message = $e->getMessage();
            if ($message === 'access_denied') {
                throw new AccessDeniedException();
            }

            throw new InvalidGrantCodeException($message ?? 'Generic Error');
        }

        return $this;
    }

    /**
     * Get Refresh Token
     *
     * @return string
     * @throws ApiError
     * @throws CannotGenerateRefreshToken
     * @throws GrantCodeNotSetException
     */
    public function getRefreshToken(): string
    {
        if ($this->hasRefreshToken()) {
            return $this->refreshToken;
        }

        if ($this->cache === null) {
            $this->generateTokens();

            if (!$this->hasRefreshToken()) {
                throw new ApiError('Cannot generate a refresh Token');
            }
        }

        try {
            $cachedRefreshToken = $this->cache->getItem('zoho_crm_refresh_token');

            $value = $cachedRefreshToken->get();
            if (!empty($value)) {
                return $value;
            }

            $this->generateTokens();

            if (!$this->refreshToken) {
                throw new CannotGenerateRefreshToken();
            }

            return $this->refreshToken;
        } catch (InvalidArgumentException $e) {
            return $this->generateTokens()->getRefreshToken();
        }
    }

    /**
     * Set the refresh token
     *
     * @param string $token
     * @return self
     */
    public function setRefreshToken(string $token): self
    {
        $this->refreshToken = $token;

        if (!$this->cache) {
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
     * Get All Available regions
     * @return Region[]
     */
    public function availableRegions(): array
    {
        return Region::getAll();
    }

    /**
     * Revoke Refresh token
     *
     * @param string|null $refreshToken
     * @return self
     */
    public function revokeRefreshToken(?string $refreshToken = null): self
    {
        if ($refreshToken === null) {
            $refreshToken = $this->refreshToken;
        }

        try {
            (new ZohoProvider())->revoke($refreshToken);
            $this->setRefreshToken('');
        } catch (ClientException $e) {
            $body = $e->getResponse()->getBody()->getContents();

            throw new ApiError($body, $e->getCode());
        }

        return $this;
    }

    /**
     * Get Grant Code Consent Url
     *
     * @return string
     */
    public function getGrantCodeConsentUrl(): string
    {
        $urlOptions = [
            'scope' => implode(',', $this->scopes),
            'access_type' => $this->offlineMode ? 'offline' : 'online'
        ];

        // In case we don't have a refresh token, and we need to get one (offline mode),
        // if the user has already logged in, we already got the refresh token previously, and we won't get
        // another one unless we force a new consent.
        // Beware that the max number of refresh tokens is 20, and creating a 21st will delete the first one making
        // it unusable, so STORE the refresh token the first time!
        if ($this->isOffline() && !$this->hasRefreshToken()) {
            $urlOptions['prompt'] = 'consent';
        }

        return (new ZohoProvider([
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientSecret,
            'state' => $this->state,
        ]))
            ->getAuthorizationUrl($urlOptions);
    }

    /**
     * Toggle offline mode
     *
     * @param boolean $enabled
     * @return self
     */
    public function offlineMode(bool $enabled = true): self
    {
        $this->offlineMode = $enabled;

        return $this;
    }

    /**
     * Get the Resource owner
     *
     * @return ZohoUser
     */
    public function getResourceOwner(): ZohoUser
    {
        $this->getAccessToken();
        if (!$this->hasAccessToken()) {
            throw new RefreshTokenNotSet();
        }
        return (new ZohoProvider([
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientSecret,
        ]))->getResourceOwner($this->accessToken);
    }
}
