<?php
declare(strict_types=1);

namespace HttpSignatures;

/**
 * Class SignatureParametersParser.
 */
class SignatureParametersParser
{
    /** @var string */
    private $input;

    /**
     * @param string $input signature header value
     */
    public function __construct(string $input)
    {
        $this->input = $input;
    }

    /**
     * @return mixed[] associative array of parameters
     *
     * @throws SignatureParseException
     */
    public function parse(): array
    {
        $result = $this->pairsToAssociative(
            $this->arrayOfPairs()
        );
        $this->validate($result);

        return $result;
    }

    /**
     * @param mixed[][] $pairs parameter pairs to convert
     *
     * @return mixed[]
     */
    private function pairsToAssociative(array $pairs): array
    {
        $result = [];
        foreach ($pairs as $pair) {
            $result[$pair[0]] = $pair[1];
        }

        return $result;
    }

    /**
     * @return mixed[][] array of parameter pairs
     */
    private function arrayOfPairs(): array
    {
        return array_map(
            [$this, 'pair'],
            $this->segments()
        );
    }

    /**
     * @return string[] array of string segments
     */
    private function segments(): array
    {
        return explode(',', $this->input);
    }

    /**
     * @param mixed[] $result associative signature parameter array to validate
     *
     * @throws SignatureParseException
     */
    private function validate(array $result)
    {
        $this->validateAllKeysArePresent($result);
    }

    /**
     * @param mixed[] $result associative signature parameter array to validate
     *
     * @throws SignatureParseException
     */
    private function validateAllKeysArePresent(array $result)
    {
        // Regexp in pair() ensures no unwanted keys exist.
        // Ensure that all mandatory keys exist.
        $wanted = ['keyId', 'algorithm', 'signature'];
        $missing = array_diff($wanted, array_keys($result));
        if (!empty($missing)) {
            $csv = implode(', ', $missing);
            throw new SignatureParseException("Missing keys $csv");
        }
    }

    /**
     * @param string $segment segment to parse
     *
     * @return string[] parsed pair
     *
     * @throws SignatureParseException
     */
    private function pair(string $segment): array
    {
        $segmentPattern = '/\A(?:(keyId|algorithm|headers|signature)="(.*)")|(?:(created|expires)=([0-9]*))\z/';
        //$segmentPattern = '/\A(keyId|algorithm|headers|signature)="(.*)"\z/';
        $matches = [];
        $result = preg_match($segmentPattern, $segment, $matches);
        if (1 !== $result) {
            // TODO: This is not strictly required, unknown parameters should be ignored
            // @see https://tools.ietf.org/html/draft-cavage-http-signatures-10#section-2.2
            throw new SignatureParseException("Signature parameters segment '$segment' invalid");
        }
        array_shift($matches);
        if ('' == $matches[0]) {
            //integer value
            $matches = [$matches[2], intval($matches[3])];
        }

        return $matches;
    }
}
