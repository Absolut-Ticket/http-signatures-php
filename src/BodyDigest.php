<?php

declare(strict_types=1);

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

/**
 * Class BodyDigest.
 */
class BodyDigest
{
    /** @var string */
    private const VALID_HASHES =
        'sha sha1 sha256 sha512';

    /** @var string */
    private $hashName;

    /** @var string */
    private $digestHeaderPrefix;

    /**
     * @param string|null $hashAlgorithm the name of the hash algorithm to use
     *
     * @throws DigestException
     */
    public function __construct(?string $hashAlgorithm = null)
    {
        // Default to sha256 if no spec provided
        if (is_null($hashAlgorithm) || '' == $hashAlgorithm) {
            $hashAlgorithm = 'sha256';
        }

        // Normalise to openssl type for switch - remove dashes and lowercase
        $hashAlgorithm = strtolower(str_replace('-', '', $hashAlgorithm));
        if (!self::isValidDigestSpec($hashAlgorithm)) {
            throw new DigestException("'$hashAlgorithm' is not a valid Digest algorithm specifier");
        }
        switch ($hashAlgorithm) {
            case 'sha':
            case 'sha1':
                $this->hashName = 'sha1';
                $this->digestHeaderPrefix = 'SHA';
                break;
            case 'sha256':
                $this->hashName = 'sha256';
                $this->digestHeaderPrefix = 'SHA-256';
                break;
            case 'sha512':
                $this->hashName = 'sha512';
                $this->digestHeaderPrefix = 'SHA-512';
                break;
        }
    }

    /**
     * @param string $digestSpec the digest specification to check
     *
     * @return bool true iff the digest specification is valid
     */
    public static function isValidDigestSpec(string $digestSpec): bool
    {
        $digestSpec = strtolower(str_replace('-', '', $digestSpec));
        $validHashes = explode(' ', self::VALID_HASHES);

        return in_array($digestSpec, $validHashes);
    }

    /**
     * @param MessageInterface $message the request from which to construct the body digest
     *
     * @return BodyDigest the constructed body digest
     *
     * @throws DigestException
     */
    public static function fromMessage(MessageInterface $message): BodyDigest
    {
        $digestLine = $message->getHeader('Digest');
        if (!$digestLine) {
            throw new DigestException('No Digest header in message');
        }

        $digestAlgorithm = self::getDigestAlgorithm($digestLine[0]);

        return new BodyDigest($digestAlgorithm);
    }

    /**
     * @param string $digestLine the digest line to parse
     *
     * @return string the algorithm specified in the digest line
     *
     * @throws DigestException
     */
    private static function getDigestAlgorithm(string $digestLine): string
    {
        // simple test if properly delimited, but see below
        if (!strpos($digestLine, '=')) {
            throw new DigestException('Digest header does not appear to be correctly formatted');
        }

        // '=' is valid base64, so raw base64 may match
        $hashAlgorithm = explode('=', $digestLine)[0];
        if (!self::isValidDigestSpec($hashAlgorithm)) {
            throw new DigestException("'$hashAlgorithm' in Digest header is not a valid algorithm");
        }

        return $hashAlgorithm;
    }

    /**
     * @param HeaderList $headerList the list of headers to add the digest header
     *
     * @return HeaderList the completed list of headers
     */
    public function putDigestInHeaderList(HeaderList $headerList): HeaderList
    {
        if (!array_search('digest', $headerList->names)) {
            $headerList->names[] = 'digest';
        }

        return $headerList;
    }

    /**
     * Sets the digest header for the given request.
     *
     * @param MessageInterface $message the request for which to compute the digest
     *
     * @return MessageInterface the request with the set digest
     */
    public function setDigestHeader(MessageInterface $message): MessageInterface
    {
        $message = $message->withoutHeader('Digest')
            ->withHeader(
                'Digest',
                $this->getDigestHeaderLineFromBody((string) $message->getBody())
            );

        return $message;
    }

    /**
     * Constructs the digest header from the given body.
     *
     * @param string $messageBody the message body for which to compute the digest
     *
     * @return string the computed digest
     */
    public function getDigestHeaderLineFromBody(string $messageBody): string
    {
        if (is_null($messageBody)) {
            $messageBody = '';
        }

        return $this->digestHeaderPrefix.'='.base64_encode(hash($this->hashName, $messageBody, true));
    }

    /**
     * checks if digest is correct.
     *
     * @param MessageInterface $message the request for which to check the digest
     *
     * @return bool true iff the digest is correct
     */
    public function isValid(MessageInterface $message): bool
    {
        $receivedDigest = $message->getHeader('Digest')[0];
        $expectedDigest = $this->getDigestHeaderLineFromBody((string) $message->getBody());

        return hash_equals($receivedDigest, $expectedDigest);
    }
}
