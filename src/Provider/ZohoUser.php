<?php

namespace Weble\ZohoClient\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class ZohoUser implements ResourceOwnerInterface
{
	/** @var array */
	protected $response;

	public function __construct(array $response)
	{
		$this->response = $response;
	}

	/**
	 * Returns the identifier of the authorized resource owner.
	 *
	 * @return mixed
	 */
	public function getId()
	{
		return $this->getResponseValue('ZUID');
	}

	/**
	 * Get the display name.
	 *
	 * @return string
	 */
	public function getDisplayName()
	{
		return $this->getResponseValue('Display_Name');
	}

	/**
	 * Get the first name.
	 *
	 * @return string|null
	 */
	public function getFirstName()
	{
		return $this->getResponseValue('First_Name');
	}

	/**
	 * Get the last name.
	 *
	 * @return string|null
	 */
	public function getLastName()
	{
		return $this->getResponseValue('Last_Name');
	}

	/**
	 * Get the email address.
	 *
	 * @return string|null
	 */
	public function getEmail()
	{
		return $this->getResponseValue('Email');
	}

	/**
	 * Return all of the owner details available as an array.
	 *
	 * @return array
	 */
	public function toArray()
	{
		return $this->response;
	}

	/**
	 * Get Response value from the response array
	 *
	 * @param [type] $key
	 * @return mixed
	 */
	protected function getResponseValue(string $key)
	{
		return $this->response[$key] ?? null;
	}
}
