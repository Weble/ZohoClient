<?php

namespace Weble\ZohoClient;

use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Psr\Cache;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\UriInterface;
use Weble\ZohoClient\Enums\Region;
use Weble\ZohoClient\Exception\AccessDeniedException;
use Weble\ZohoClient\Exception\AccessTokenNotSet;
use Weble\ZohoClient\Exception\CannotRevokeRefreshToken;
use Weble\ZohoClient\Exception\RefreshTokenNotSet;
use Weble\ZohoClient\Oauth\Zoho;
use Weble\ZohoClient\Oauth\ZohoAccessToken;

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
    /** @var bool */
    protected $prompt = true;
    /** @var string */
    protected $state = 'test';
    /** @var string */
    protected $clientSecret;
    /** @var string */
    protected $clientId;
    /** @var null|ZohoAccessToken */
    protected $accessToken;
    /** @var Cache\CacheItemPoolInterface|null */
    protected $cache;
    /** @var AbstractProvider */
    protected $provider;
    /** @var string */
    protected $cachePrefix = 'zoho_crm_';
    /** @var string|null */
    protected $refreshToken;

    public function __construct(string $clientId, string $clientSecret, string $region = Region::US, string $redirectUri = '')
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->region = $region;
        $this->redirectUri = $redirectUri;

        $this->createProvider();
    }

    public function getAuthorizationUrl(array $additionalScopes = []): string
    {
        $scopes = array_unique(array_merge($this->scopes, $additionalScopes));

        $options = [
            'scope' => $scopes,
            'access_type' => $this->offlineMode ? 'offline' : 'online',
        ];

        if($this->prompt){
            $options['prompt'] = 'consent';
        }

        $url = $this->provider->getAuthorizationUrl($options);

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
     * @return self
     */
    public function useCache(Cache\CacheItemPoolInterface $cacheItemPool): self
    {
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
     * Get Access Token as a string
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
        return $this->getAccessTokenObject()->getToken();
    }

    /**
     * Get Access Token Object
     *
     * @return ZohoAccessToken
     *
     * @throws AccessDeniedException
     * @throws AccessTokenNotSet
     * @throws IdentityProviderException
     * @throws RefreshTokenNotSet
     */
    public function getAccessTokenObject()
    {
        if ($this->hasAccessToken() && ! $this->accessTokenExpired()) {
            return $this->accessToken;
        }

        // Let's try with cache!
        if ($this->hasCache()) {
            try {
                $cachedAccessToken = $this->cache->getItem($this->cachePrefix . 'access_token');

                if ($cachedAccessToken->isHit()) {
                    $this->accessToken = $cachedAccessToken->get();

                    return $this->accessToken;
                }
            } catch (InvalidArgumentException $e) {
            }
        }

        // Do we have the chance to refresh the access token
        if ((! $this->hasAccessToken() || $this->accessTokenExpired()) && $this->hasRefreshToken()) {
            $this->refreshAccessToken();

            return $this->accessToken;
        }

        // Maybe it's a first time request, so it's actually a grant token request?
        if (! $this->hasAccessToken() && $this->hasGrantCode()) {
            $this->generateTokensFromGrantToken();

            return $this->accessToken;
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
            $this->accessToken = $this->provider->getAccessToken('authorization_code', [
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
        if (! $this->accessToken) {
            $this->accessToken = new ZohoAccessToken([
                'access_token' => $token,
            ]);
        }

        $values = $this->accessToken->jsonSerialize();
        $values['access_token'] = $token;
        if ($expiresIn !== null) {
            $values['expires_in'] = $expiresIn;
        }

        $this->accessToken = new ZohoAccessToken($values);

        if ($this->hasCache()) {
            try {
                $cachedToken = $this->cache->getItem($this->cachePrefix . 'access_token');
                $cachedToken->set($this->accessToken);
                $cachedToken->expiresAt(new \DateTime('@' . $this->accessToken->getExpires()));
                $this->cache->save($cachedToken);
            } catch (InvalidArgumentException $e) {
            }
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
        if (! $this->accessToken) {
            return false;
        }

        if (! $this->accessToken->getExpires()) {
            return true;
        }

        return $this->accessToken->hasExpired();
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
            $this->accessToken = $this->provider->getAccessToken($grant, [
                'refresh_token' => $this->getRefreshToken(),
            ]);
        } catch (IdentityProviderException $e) {
            $message = $e->getMessage();
            if ($message === 'access_denied') {
                throw new AccessDeniedException();
            }

            throw $e;
        }

        $token = $this->getAccessToken();

        if ($this->hasCache()) {
            try {
                $cachedToken = $this->cache->getItem($this->cachePrefix . 'access_token');
                $cachedToken->set($this->accessToken);
                $cachedToken->expiresAt(new \DateTime('@' . $this->accessToken->getExpires()));
                $this->cache->save($cachedToken);
            } catch (InvalidArgumentException $e) {
            }
        }

        return $token;
    }

    /**
     * Do we have a refresh token?
     *
     * @return bool
     */
    public function hasRefreshToken(): bool
    {
        return isset($this->refreshToken);
    }

    /**
     * Do we have an access token?
     *
     * @return bool
     */
    public function hasAccessToken(): bool
    {
        if (! $this->accessToken) {
            return false;
        }

        return strlen($this->accessToken->getToken()) > 0;
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
            return $this->refreshToken;
        }

        // Maybe it's a first time request, so it's actually a grant token request?
        if (! $this->hasRefreshToken() && $this->hasGrantCode()) {
            $this->generateTokensFromGrantToken();
            $token = $this->accessToken->getRefreshToken();

            if ($token) {
                $this->refreshToken = $token;

                return $this->refreshToken;
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
        $this->refreshToken = $token;

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
            $refreshToken = $this->refreshToken;
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
     * During authorization prompt the user to confirm consent to access scopes.
     *
     * @param bool $enabled
     * @return self
     */
    public function promptForConsent(bool $enabled = true): self
    {
        $this->prompt = $enabled;

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
        if (! $this->hasAccessToken() || $this->accessTokenExpired()) {
            $this->getAccessToken();
        }

        return $this->provider->getResourceOwner($this->accessToken);
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
