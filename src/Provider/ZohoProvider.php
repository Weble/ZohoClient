<?php

namespace Weble\ZohoClient\Provider;

use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Weble\ZohoClient\Enums\Region;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\RequestInterface;

class ZohoProvider extends AbstractProvider
{
	use BearerAuthorizationTrait;

	const ZOHO_CLIENT_API_URL = 'https://accounts.zoho';

	/** @var Region */
	protected $region;

	public function __construct(array $options = [], array $collaborators = [])
	{
		$this->region = Region::us();
		parent::__construct($options, $collaborators);
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
	 * Returns the base URL for authorizing a client.
	 *
	 * Eg. https://oauth.service.com/authorize
	 *
	 * @return string
	 */
	public function getBaseAuthorizationUrl()
	{
		return self::ZOHO_CLIENT_API_URL . $this->region->getValue() . '/oauth/v2/auth';
	}

	/**
	 * Returns the base URL for requesting an access token.
	 *
	 * Eg. https://oauth.service.com/token
	 *
	 * @param array $params
	 * @return string
	 */
	public function getBaseAccessTokenUrl(array $params)
	{
		return self::ZOHO_CLIENT_API_URL . $this->region->getValue() . '/oauth/v2/token';
	}

	/**
	 * Returns the URL for requesting the resource owner's details.
	 *
	 * @param AccessToken $token
	 * @return string
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token)
	{
		return 'https://accounts.zoho.com/oauth/user/info';
	}

	/**
	 * Returns the default scopes used by this provider.
	 *
	 * This should only be the scopes that are required to request the details
	 * of the resource owner, rather than all the available scopes.
	 *
	 * @return array
	 */
	protected function getDefaultScopes()
	{
		return ['aaaserver.profile.READ'];
	}

	/**
	 * Checks a provider response for errors.
	 *
	 * @throws IdentityProviderException
	 * @param  ResponseInterface $response
	 * @param  array|string $data Parsed response data
	 * @return void
	 */
	protected function checkResponse(ResponseInterface $response, $data)
	{
		if (empty($data['error'])) {
			return;
		}

		throw new IdentityProviderException(
			$data['error'] ?? null,
			$response->getStatusCode(),
			$response->getBody()->getContents()
		);
	}

	/**
	 * Generates a resource owner object from a successful resource owner
	 * details request.
	 *
	 * @param  array $response
	 * @param  AccessToken $token
	 * @return ResourceOwnerInterface
	 */
	protected function createResourceOwner(array $response, AccessToken $token)
	{
		return new ZohoUser($response);
	}

	/**
	 * Requests and returns the resource owner of given access token.
	 *
	 * @param  AccessToken $token
	 * @return ResourceOwnerInterface
	 */
	protected function createAccessToken(array $response, AbstractGrant $grant)
	{
		return new ZohoAccessToken($response);
	}

	/**
	 * Revoke a token
	 *
	 * @param string $refreshToken
	 * @return RequestInterface
	 */
	public function revoke(string $refreshToken)
	{
		return $this->getRequest('POST', self::ZOHO_CLIENT_API_URL . $this->region->getValue() . '/oauth/v2/token/revoke', [
			'query' => [
				'token' => $refreshToken,
			],
		]);
	}
}
