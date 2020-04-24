<?php

namespace HttpSignatures;

class HeaderList
{
    /** @var string[] */
    public $names;

    /** @var bool */
    private $headerListSpecified;

    /**
     * @param string[]|null $names
     * @param bool          $headerListSpecified whether the header should be given as a parameter in the signature string
     */
    public function __construct(?array $names, $headerListSpecified = true)
    {
        $this->names = [];
        if (!$names) {
            $this->headerListSpecified = false;
        } else {
            foreach ($names as $name) {
                $this->names[] = $this->normalize($name);
            }
            $this->headerListSpecified = $headerListSpecified;
        }
    }

    /**
     * @param string $name the name to normalize
     *
     * @return string the normalized name
     */
    private function normalize(string $name): string
    {
        return strtolower($name);
    }

    /**
     * @param string $string the strong from which to construct the header list
     *
     * @return static
     */
    public static function fromString(string $string): HeaderList
    {
        return new static(explode(' ', $string));
    }

    /**
     * @return string the header list as string
     */
    public function string(): string
    {
        if (sizeof($this->names)) {
            return implode(' ', $this->names);
        } else {
            return '';
        }
    }

    /**
     * @return bool whether the header list should be given as a parameter in the signature string
     */
    public function headerListSpecified(): bool
    {
        return $this->headerListSpecified;
    }

    /**
     * @return string[]
     */
    public function listHeaders(): array
    {
        return $this->names;
    }
}
