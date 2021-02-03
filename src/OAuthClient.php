<?php

namespace Weble\ZohoClient;

use Asad\OAuth2\Client\Provider\Zoho;
use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Psr\Cache;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\UriInterface;
use Weble\ZohoClient\Enums\Region;
use Weble\ZohoClient\Exception\AccessDeniedException;
use Weble\ZohoClient\Exception\AccessTokenNotSet;
use Weble\ZohoClient\Exception\CannotRevokeRefreshToken;
use Weble\ZohoClient\Exception\RefreshTokenNotSet;

class OAuthClient
{
    /** @var string */
    protected $region;
    /** @var string|null */
    protected $grantCode;
    /** @var string|null */
    protected $redirectUri;
    /** @var array<string> */
    protected $scopes = ['AaaServer.profile.READ'];
    /** @var bool */
    protected $offlineMode = true;
    /** @var string */
    protected $state = 'test';
    /** @var string */
    protected $clientSecret;
    /** @var string */
    protected $clientId;
    /** @var null|AccessTokenInterface */
    protected $token;
    /** @var Cache\CacheItemPoolInterface|null */
    protected $cache;
    /** @var AbstractProvider */
    protected $provider;
    /** @var string */
    protected $cachePrefix = 'zoho_crm_';

    public function __construct(string $clientId, string $clientSecret, string $region = Region::US, string $redirectUri = '')
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->region = Region::US;
        $this->redirectUri = $redirectUri;

        $this->createProvider();
    }

    public function getAuthorizationUrl(array $additionalScopes = []): string
    {
        $scopes = array_unique(array_merge($this->scopes, $additionalScopes));
        $url = $this->provider->getAuthorizationUrl([
            'scope' => $scopes,
            'access_type' => $this->offlineMode ? 'offline' : 'online',
        ]);

        $this->state = $this->provider->getState();

        return $url;
    }

    /**
     * Get the oAuth2 state variable for security checks
     * @return string
     */
    public function getState(): string
    {
        return $this->state;
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
     * @return string
     */
    public function getRegion(): string
    {
        return $this->region;
    }

    /**
     * Set the Zoho Region
     *
     * @param string $region
     * @return self
     */
    public function setRegion(string $region): self
    {
        $this->region = $region;
        $this->createProvider();

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
     * @return bool
     */
    public function isOffline(): bool
    {
        return $this->offlineMode;
    }

    /**
     * Check is is online
     *
     * @return bool
     */
    public function isOnline(): bool
    {
        return ! $this->offlineMode;
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
        $this->createProvider();

        return $this;
    }

    /**
     * Set the cache pool to use
     *
     * @param Cache\CacheItemPoolInterface $cacheItemPool
     * @param string $cachePrefix
     * @return self
     */
    public function useCache(Cache\CacheItemPoolInterface $cacheItemPool, string $cachePrefix = 'zoho_crm_'): self
    {
        $this->setCachePrefix($cachePrefix);

        $this->cache = $cacheItemPool;

        return $this;
    }

    /**
     * Set a different cache prefix
     *
     * @param string $cachePrefix
     * @return $this
     */
    public function setCachePrefix(string $cachePrefix): self
    {
        $this->cachePrefix = $cachePrefix;

        return $this;
    }

    /**
     * Get Access Token
     *
     * @return string
     *
     * @throws AccessDeniedException
     * @throws AccessTokenNotSet
     * @throws IdentityProviderException
     * @throws RefreshTokenNotSet
     */
    public function getAccessToken(): string
    {
        if (! $this->accessTokenExpired() && $this->hasAccessToken()) {
            return $this->token->getToken();
        }

        // Let's try with cache!
        if ($this->hasCache()) {
            try {
                $cachedAccessToken = $this->cache->getItem($this->cachePrefix . 'access_token');
                $value = $cachedAccessToken->get();

                if ($value) {
                    $this->setAccessToken($value, $cachedAccessToken->getExpirationTimestamp());
                }

                return $this->token->getToken();
            } catch (InvalidArgumentException $e) {
            }
        }

        // Do we have the chance to refresh the access token
        if ($this->accessTokenExpired() && $this->hasRefreshToken()) {
            return $this->refreshAccessToken();
        }

        // Maybe it's a first time request, so it's actually a grant token request?
        if (! $this->hasAccessToken() && $this->hasGrantCode()) {
            $this->generateTokensFromGrantToken();

            return $this->token->getToken();
        }

        // Nothing was working
        throw new AccessTokenNotSet();
    }

    /**
     * Generate the tokens from the grant token if set
     *
     * @return $this
     * @throws IdentityProviderException
     */
    protected function generateTokensFromGrantToken(): self
    {
        if ($this->hasGrantCode()) {
            $this->token = $this->provider->getAccessToken('authorization_code', [
                'code' => $this->grantCode,
            ]);
        }

        return $this;
    }

    /**
     * Set the Access Token while also updating the cache
     *
     * @param string $token
     * @return self
     */
    public function setAccessToken(string $token, ?int $expiresIn = null): self
    {
        if (! $this->token) {
            $this->token = new AccessToken([
                'access_token' => $token,
            ]);
        }

        $values = $this->token->jsonSerialize();
        $values['access_token'] = $token;
        if ($expiresIn !== null) {
            $values['expires_in'] = $expiresIn;
        }

        $this->token = new AccessToken($values);

        if ($this->cache === null) {
            return $this;
        }

        try {
            $cachedToken = $this->cache->getItem($this->cachePrefix . '_access_token');
            $cachedToken->set($this->token->getToken());
            $cachedToken->expiresAfter($this->token->getExpires());
            $this->cache->save($cachedToken);
        } catch (InvalidArgumentException $e) {
        }

        return $this;
    }

    /**
     * Check if the access token has expired
     *
     * @return bool
     */
    public function accessTokenExpired(): bool
    {
        if (! $this->token) {
            return false;
        }

        return $this->token->hasExpired();
    }

    /**
     * @return string
     * @throws AccessDeniedException
     * @throws AccessTokenNotSet
     * @throws IdentityProviderException
     * @throws RefreshTokenNotSet
     */
    public function refreshAccessToken(): string
    {
        if (! $this->hasRefreshToken()) {
            throw new RefreshTokenNotSet();
        }

        try {
            $grant = new RefreshToken();
            $this->token = $this->provider->getAccessToken($grant, [
                'refresh_token' => $this->getRefreshToken(),
            ]);
        } catch (IdentityProviderException $e) {
            $message = $e->getMessage();
            if ($message === 'access_denied') {
                throw new AccessDeniedException();
            }

            throw $e;
        }

        return $this->getAccessToken();
    }

    /**
     * Do we have a refresh token?
     *
     * @return bool
     */
    public function hasRefreshToken(): bool
    {
        if (! $this->token) {
            return false;
        }

        return strlen($this->token->getRefreshToken()) > 0;
    }

    /**
     * Do we have an access token?
     *
     * @return bool
     */
    public function hasAccessToken(): bool
    {
        if (! $this->token) {
            return false;
        }

        return strlen($this->token->getToken()) > 0;
    }

    /**
     * Do we have a grant code?
     *
     * @return bool
     */
    public function hasGrantCode(): bool
    {
        return strlen($this->grantCode) > 0;
    }

    /**
     * Is a cache set?
     *
     * @return bool
     */
    public function hasCache(): bool
    {
        return $this->cache !== null;
    }

    /**
     * Get Refresh Token
     *
     * @return string
     * @throws RefreshTokenNotSet
     * @throws IdentityProviderException
     */
    public function getRefreshToken(): string
    {
        if ($this->hasRefreshToken()) {
            return $this->token->getRefreshToken();
        }

        try {
            if ($this->hasCache()) {
                try {
                    $cachedRefreshToken = $this->cache->getItem($this->cachePrefix . 'refresh_token');

                    $value = $cachedRefreshToken->get();
                    if (empty($value)) {
                        throw new RefreshTokenNotSet();
                    }

                    $this->setRefreshToken($value);

                    return $this->token->getRefreshToken();
                } catch (InvalidArgumentException $e) {
                    throw new RefreshTokenNotSet();
                }
            }
        } catch (RefreshTokenNotSet $e) {
            // Maybe it's a first time request, so it's actually a grant token request?
            if (! $this->hasRefreshToken() && $this->hasGrantCode()) {
                $this->generateTokensFromGrantToken();
                $token = $this->token->getRefreshToken();

                if ($token) {
                    return $token;
                }
            }
        }

        throw new RefreshTokenNotSet();
    }

    /**
     * Set the refresh token
     *
     * @param string $token
     * @return self
     */
    public function setRefreshToken(string $token): self
    {
        if (! $this->token) {
            $this->token = new AccessToken([
                'access_token' => uniqid(),
            ]);
        }

        $values = $this->token->jsonSerialize();
        $values['refresh_token'] = $token;

        $this->token = new AccessToken($values);

        if (! $this->hasCache()) {
            return $this;
        }

        try {
            $cachedToken = $this->cache->getItem($this->cachePrefix . 'refresh_token');

            $cachedToken->set($token);
            $this->cache->save($cachedToken);
        } catch (InvalidArgumentException $e) {
        }

        return $this;
    }

    /**
     * Revoke Refresh token
     *
     * @param string|null $refreshToken
     * @return self
     * @throws CannotRevokeRefreshToken
     */
    public function revokeRefreshToken(?string $refreshToken = null): self
    {
        if ($refreshToken === null) {
            $refreshToken = $this->token->getRefreshToken();
        }

        try {
            $this->provider->getResponse(
                $this->provider->getRequest('POST', $this->provider->getBaseAccessTokenUrl([]) . '/revoke', [
                    'query' => [
                        'token' => $refreshToken,
                    ],
                ])
            );

            $this->setRefreshToken('');

            return $this;
        } catch (\Exception $e) {
            throw new CannotRevokeRefreshToken($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Toggle offline mode
     *
     * @param bool $enabled
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
     * @return ResourceOwnerInterface
     * @throws AccessTokenNotSet
     */
    public function getResourceOwner(): ResourceOwnerInterface
    {
        if (! $this->hasAccessToken()) {
            throw new AccessTokenNotSet();
        }

        return $this->provider->getResourceOwner($this->token);
    }

    protected function createProvider(): void
    {
        $this->provider = new Zoho([
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientSecret,
            'redirectUri' => $this->redirectUri,
            'dc' => $this->region,
        ]);
    }
}
