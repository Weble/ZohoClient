<?php

namespace Weble\ZohoClient\Provider;

use League\OAuth2\Client\Token\AccessToken;

class ZohoAccessToken extends AccessToken
{
	/** @var string */
	protected $apiDomain;

	/** @var string */
	protected $tokenType;

	public function __construct(array $options = [])
	{
		if (!empty($options['api_domain'])) {
			$this->apiDomain = $options['api_domain'];
		}

		if (!empty($options['token_type'])) {
			$this->tokenType = $options['token_type'];
		}

		//This is where Zoho breaks RFC RFC6749 Section 5.1
		if (!empty($options['expires_in_sec'])) {
			$options['expires_in'] = $options['expires_in_sec'];
		}

		parent::__construct($options);
	}

	/**
	 * Zoho API domain name
	 * @return string
	 */
	public function getApiDomain()
	{
		return $this->apiDomain;
	}

	/**
	 * Oauth2 Bearer Toekn type
	 * @return string
	 */
	public function getTokenType()
	{
		return $this->tokenType;
	}
}
