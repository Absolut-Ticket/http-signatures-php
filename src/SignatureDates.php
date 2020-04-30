<?php
declare(strict_types=1);

namespace HttpSignatures;

/**
 * Class SignatureDates.
 */
class SignatureDates
{
    /** @var int|null */
    private $created;

    /** @var int|null */
    private $expires;

    /** @var int */
    private $createdDrift = 1;

    /** @var int */
    private $expiresDrift = 0;

    /**
     * @param int|string $value offset to use
     * @param int|null   $start optional start value for which to add the offset (default = current time)
     *
     * @return int|null unix timestamp
     */
    public static function offset($value, ?int $start = null): ?int
    {
        if ('now' == $value) {
            return time();
        } elseif ('none' == $value) {
            return null;
        }
        if (empty($start)) {
            $start = time();
        }
        if (is_int($value)) {
            return $value;
        } elseif ('+' == substr($value, 0, 1)) {
            return $start + substr($value, 1);
        } elseif ('-' == substr($value, 0, 1)) {
            return $start - substr($value, 1);
        } else {
            return intval($value);
        }
    }

    /**
     * unset created.
     */
    public function unSetCreated()
    {
        $this->created = null;
    }

    /**
     * unset expires.
     */
    public function unSetExpires()
    {
        $this->expires = null;
    }

    /**
     * @param int|null $atTime the time to test for
     *
     * @return bool true iff created is before atTime
     */
    public function hasStarted(?int $atTime = null): bool
    {
        if (empty($atTime)) {
            $atTime = time();
        }
        if (empty($this->created)) {
            return true;
        } else {
            return $this->created <= ($atTime + $this->createdDrift);
        }
    }

    /**
     * @param int|null $atTime the time to test for
     *
     * @return bool true iff not expired with respect to atTime
     */
    public function hasExpired(?int $atTime = null): bool
    {
        if (empty($atTime)) {
            $atTime = time();
        }
        if (empty($this->expires)) {
            return false;
        } else {
            // return ( $atTime  ($this->expires) );
            return $atTime > ($this->expires + $this->expiresDrift);
        }
    }

    /**
     * @param int $drift drift for created and expires
     */
    public function setDrift(int $drift = 0)
    {
        $this->setCreatedDrift($drift);
        $this->setExpiresDrift($drift);
    }

    /**
     * @param int $drift allowed created time drift
     */
    public function setCreatedDrift(int $drift = 0)
    {
        $this->createdDrift = $drift;
    }

    /**
     * @param int $drift allowed expires time drift
     */
    public function setExpiresDrift(int $drift = 0)
    {
        $this->expiresDrift = $drift;
    }

    /**
     * @return int|null created value
     */
    public function getCreated(): ?int
    {
        return $this->created;
    }

    /**
     * @param int|null $time created value
     */
    public function setCreated(?int $time)
    {
        $this->created = $time;
    }

    /**
     * @return int|null expires value
     */
    public function getExpires(): ?int
    {
        return $this->expires;
    }

    /**
     * @param int|null $time expires value
     */
    public function setExpires(?int $time)
    {
        $this->expires = $time;
    }

    /**
     * @return int|null created offset
     */
    public function sinceCreated(): ?int
    {
        if (empty($this->created)) {
            return null;
        } else {
            return time() - $this->created;
        }
    }

    /**
     * @return int|null expires offset
     */
    public function toExpire(): ?int
    {
        if (empty($this->expires)) {
            return null;
        } else {
            return $this->expires - time();
        }
    }
}
