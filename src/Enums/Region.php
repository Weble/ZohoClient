<?php

namespace Weble\ZohoClient\Enums;

use Spatie\Enum\Enum;

/**
 * @method static self eu()
 * @method static self us()
 * @method static self cn()
 * @method static self in()
 * @method static self au()
 *
 * @method static bool isEu(string $value = null)
 * @method static bool isCn(string $value = null)
 * @method static bool isUs(string $value = null)
 * @method static bool isAu(string $value = null)
 * @method static bool isIn(string $value = null)
 */
class Region extends Enum
{
    const MAP_VALUE = [
        'eu' => '.eu',
        'us' => '.com',
        'cn' => '.com.cn',
        'in' => '.in',
        'au' => '.com.au'
    ];
}
