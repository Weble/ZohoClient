<?php

namespace Weble\ZohoClient\Oauth;

use Asad\OAuth2\Client\AccessToken\ZohoAccessToken as AsadZohoAccessToken;

class ZohoAccessToken extends AsadZohoAccessToken
{
    /**
     * @param array<string,mixed> $options
     */
    public function __construct(array $options = [])
    {
        $options['expires_in'] = $options['expires_in_sec'] ?? $options['expires_in'] ?? null;

        parent::__construct($options);
    }
}
