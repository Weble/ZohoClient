<?php

namespace Weble\ZohoClient;

use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Cache;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\UriInterface;
use Weble\ZohoClient\Enums\Mode;
use Weble\ZohoClient\Enums\Region;
use Weble\ZohoClient\Exception\AccessDeniedException;
use Weble\ZohoClient\Exception\AccessTokenNotSet;
use Weble\ZohoClient\Exception\CannotRevokeRefreshToken;
use Weble\ZohoClient\Exception\RefreshTokenNotSet;
use Weble\ZohoClient\Oauth\Zoho;
use Weble\ZohoClient\Oauth\ZohoAccessToken;

class OAuthClient
{
    protected ?string $grantCode = null;
    protected string $state;
    protected ?ZohoAccessToken $accessToken = null;
    protected ?Cache\CacheItemPoolInterface $cache = null;
    protected Zoho $provider;
    protected string $cachePrefix = 'zoho_crm_';
    protected ?string $refreshToken = null;

    /**
     * @param string $clientId
     * @param string $clientSecret
     * @param string $region
     * @param string|null $redirectUri
     * @param string[] $scopes
     * @param bool $offlineMode
     * @param bool $prompt
     */
    public function __construct(
        protected string  $clientId,
        protected string  $clientSecret,
        protected string  $region = Region::US,
        protected ?string $redirectUri = '',
        protected array   $scopes = ['AaaServer.profile.READ'],
        protected bool    $offlineMode = true,
        protected bool    $prompt = true,
    )
    {
        $this->state = uniqid('state_');
        $this->createProvider();
    }

    /**
     * @param string[] $additionalScopes
     * @return string
     */
    public function getAuthorizationUrl(array $additionalScopes = []): string
    {
        $scopes = array_unique(array_merge($this->scopes, $additionalScopes));
        $options = [
            'scope'       => $scopes,
            'access_type' => $this->offlineMode ? Mode::OFFLINE : Mode::ONLINE,
        ];

        if ($this->prompt) {
            $options['prompt'] = 'consent';
        }

        $url = $this->provider->getAuthorizationUrl($options);
        $this->state = $this->provider->getState();

        return $url;
    }

    public function getState(): string
    {
        return $this->state;
    }

    public static function parseGrantTokenFromUrl(UriInterface $uri): ?string
    {
        parse_str($uri->getQuery(), $output);
        $code = $output['code'] ?? null;

        if (is_array($code)) {
            $code = implode("", $code);
        }

        return $code;
    }

    public function getRegion(): string
    {
        return $this->region;
    }

    public function setRegion(string $region): static
    {
        $this->region = $region;
        $this->createProvider();

        return $this;
    }

    public function setGrantCode(string $grantCode): static
    {
        $this->grantCode = $grantCode;

        return $this;
    }

    /**
     * @param string[] $scopes
     * @return $this
     */
    public function setScopes(array $scopes): static
    {
        $this->scopes = $scopes;

        return $this;
    }

    public function onlineMode(): static
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
        return !$this->offlineMode;
    }

    public function setRedirectUri(string $redirectUri): static
    {
        $this->redirectUri = $redirectUri;
        $this->createProvider();

        return $this;
    }

    public function useCache(Cache\CacheItemPoolInterface $cacheItemPool, string $cachePrefix = 'zoho_crm_'): static
    {
        $this->cache = $cacheItemPool;

        return $this->setCachePrefix($cachePrefix);
    }

    public function setCachePrefix(string $cachePrefix): static
    {
        $this->cachePrefix = $cachePrefix;

        return $this;
    }

    /**
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
     * @throws AccessDeniedException
     * @throws AccessTokenNotSet
     * @throws IdentityProviderException
     * @throws RefreshTokenNotSet
     */
    public function getAccessTokenObject(): ZohoAccessToken
    {
        if ($this->hasAccessToken() && !$this->accessTokenExpired()) {
            /** @var ZohoAccessToken $accessToken */
            $accessToken = $this->accessToken;
            return $accessToken;
        }

        // Let's try with cache!
        if ($this->hasCache()) {
            /** @var Cache\CacheItemPoolInterface $cache */
            $cache = $this->cache;
            try {
                $cachedAccessToken = $cache->getItem($this->cachePrefix . 'access_token');

                if ($cachedAccessToken->isHit()) {
                    /** @var ZohoAccessToken $token */
                    $token = $cachedAccessToken->get();
                    $this->accessToken = $token;

                    return $this->accessToken;
                }
            } catch (InvalidArgumentException) {
            }
        }

        // Do we have the chance to refresh the access token
        if ((!$this->hasAccessToken() || $this->accessTokenExpired()) && $this->hasRefreshToken()) {
            $this->refreshAccessToken();

            /** @var ZohoAccessToken $accessToken */
            $accessToken = $this->accessToken;
            return $accessToken;
        }

        // Maybe it's a first time request, so it's actually a grant token request?
        if (!$this->hasAccessToken() && $this->hasGrantCode()) {
            $this->generateTokensFromGrantToken();

            /** @var ZohoAccessToken $accessToken */
            $accessToken = $this->accessToken;
            return $accessToken;
        }


        // Nothing was working
        throw new AccessTokenNotSet();
    }

    /**
     * @throws IdentityProviderException
     */
    protected function generateTokensFromGrantToken(): static
    {
        if ($this->hasGrantCode()) {
            /** @var ZohoAccessToken $token */
            $token = $this->provider->getAccessToken('authorization_code', [
                'code' => $this->grantCode,
            ]);

            $this->accessToken = $token;
        }

        return $this;
    }

    public function setAccessToken(string $token, ?int $expiresIn = null): static
    {
        if (!$this->accessToken) {
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
            /** @var Cache\CacheItemPoolInterface $cache */
            $cache = $this->cache;
            try {
                $cachedToken = $cache->getItem($this->cachePrefix . 'access_token');
                $cachedToken->set($this->accessToken);
                $cachedToken->expiresAt(new \DateTime('@' . $this->accessToken->getExpires()));
                $cache->save($cachedToken);
            } catch (InvalidArgumentException) {
            }
        }

        return $this;
    }

    public function accessTokenExpired(): bool
    {
        if (!$this->accessToken) {
            return false;
        }

        if (!$this->accessToken->getExpires()) {
            return true;
        }

        return $this->accessToken->hasExpired();
    }

    /**
     * @throws AccessDeniedException
     * @throws AccessTokenNotSet
     * @throws IdentityProviderException
     * @throws RefreshTokenNotSet
     */
    public function refreshAccessToken(): string
    {
        if (!$this->hasRefreshToken()) {
            throw new RefreshTokenNotSet();
        }

        try {
            $grant = new RefreshToken();
            /** @var ZohoAccessToken $token */
            $token = $this->provider->getAccessToken($grant, [
                'refresh_token' => $this->getRefreshToken(),
            ]);

            $this->accessToken = $token;
        } catch (IdentityProviderException $e) {
            $message = $e->getMessage();
            if ($message === 'access_denied') {
                throw new AccessDeniedException();
            }

            throw $e;
        }

        $token = $this->getAccessToken();

        if ($this->hasCache()) {
            /** @var Cache\CacheItemPoolInterface $cache */
            $cache = $this->cache;
            try {
                $cachedToken = $cache->getItem($this->cachePrefix . 'access_token');
                $cachedToken->set($this->accessToken);
                $cachedToken->expiresAt(new \DateTime('@' . $this->accessToken->getExpires()));
                $cache->save($cachedToken);
            } catch (InvalidArgumentException) {
            }
        }

        return $token;
    }

    public function hasRefreshToken(): bool
    {
        return isset($this->refreshToken);
    }

    public function hasAccessToken(): bool
    {
        if (!$this->accessToken) {
            return false;
        }

        return strlen($this->accessToken->getToken()) > 0;
    }

    public function hasGrantCode(): bool
    {
        return strlen($this->grantCode ?? '') > 0;
    }

    public function hasCache(): bool
    {
        return $this->cache !== null;
    }

    /**
     * @throws RefreshTokenNotSet
     * @throws IdentityProviderException
     */
    public function getRefreshToken(): string
    {
        if ($this->hasRefreshToken()) {
            /** @var string $refreshToken */
            $refreshToken = $this->refreshToken;
            return $refreshToken;
        }

        // Maybe it's a first time request, so it's actually a grant token request?
        if (!$this->hasGrantCode()) {
            throw new RefreshTokenNotSet();
        }

        $this->generateTokensFromGrantToken();
        /** @var ZohoAccessToken $accessToken */
        $accessToken = $this->accessToken;
        $token = $accessToken->getRefreshToken();

        if (!$token) {
            throw new RefreshTokenNotSet();
        }

        $this->refreshToken = $token;

        return $this->refreshToken;
    }

    public function setRefreshToken(string $token): static
    {
        $this->refreshToken = $token;

        return $this;
    }

    /**
     * @throws CannotRevokeRefreshToken
     */
    public function revokeRefreshToken(?string $refreshToken = null): static
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

    public function offlineMode(bool $enabled = true): static
    {
        $this->offlineMode = $enabled;

        return $this;
    }

    public function promptForConsent(bool $enabled = true): static
    {
        $this->prompt = $enabled;

        return $this;
    }

    /**
     * @throws AccessDeniedException
     * @throws AccessTokenNotSet
     * @throws IdentityProviderException
     * @throws RefreshTokenNotSet
     */
    public function getResourceOwner(): ResourceOwnerInterface
    {
        if (!$this->hasAccessToken() || $this->accessTokenExpired()) {
            $this->getAccessToken();
        }

        /** @var AccessToken $token */
        $token = $this->accessToken;
        return $this->provider->getResourceOwner($token);
    }

    protected function createProvider(): void
    {
        $this->provider = new Zoho([
            'clientId'     => $this->clientId,
            'clientSecret' => $this->clientSecret,
            'redirectUri'  => $this->redirectUri,
            'dc'           => $this->region,
        ]);
    }
}
