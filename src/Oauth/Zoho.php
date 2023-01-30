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
     * @param  array<string,mixed> $response
     * @param  AbstractGrant $grant
     * @return ZohoAccessToken
     */
    protected function createAccessToken(array $response, AbstractGrant $grant): ZohoAccessToken
    {
        return new ZohoAccessToken($response);
    }
}
