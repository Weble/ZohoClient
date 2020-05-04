<?php

namespace Weble\ZohoClient\Exception;

use Throwable;

class AccessDeniedException extends \Exception
{
    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        if (! $message) {
            $message = "You are probably trying to refresh access tokens too fast. Try enabling the cache provided in this package.";
        }
        parent::__construct($message, $code, $previous);
    }
}
