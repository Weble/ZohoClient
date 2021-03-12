<?php

namespace Weble\ZohoClient\Oauth;

use Asad\OAuth2\Client\AccessToken\ZohoAccessToken as AsadZohoAccessToken;

class ZohoAccessToken extends AsadZohoAccessToken
{
    public function __construct(array $options = [])
    {
        if (! empty($options['expires_in_sec'])) {
            $options['expires_in'] = $options['expires_in_sec'];
        }

        parent::__construct($options);
    }
}
