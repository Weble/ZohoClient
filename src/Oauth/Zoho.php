<?php

namespace Weble\ZohoClient\Oauth;

use Asad\OAuth2\Client\Provider\Zoho as AsadZoho;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Token\AccessTokenInterface;

class Zoho extends AsadZoho
{
    /**
     * Creates an access token from a response.
     *
     * The grant that was used to fetch the response can be used to provide
     * additional context.
     *
     * @param  array $response
     * @param  AbstractGrant $grant
     * @return AccessTokenInterface
     */
    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        return new ZohoAccessToken($response);
    }
}
