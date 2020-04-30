<?php

declare(strict_types=1);

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

/**
 * Class Verifier.
 */
class Verifier
{
    /** @var KeyStoreInterface */
    private $keyStore;

    /**
     * @var string[]
     */
    private $status;

    /**
     * @param KeyStoreInterface $keyStore key store to use for verification
     */
    public function __construct(KeyStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
        $this->status = [];
    }

    /**
     * @param MessageInterface $message request to verify
     *
     * @return bool true iff Signature header exists, is valid, digest header exists, and is correct
     *
     * @throws Exception
     */
    public function isSignedWithDigest(MessageInterface $message): bool
    {
        if ($this->isValidDigest($message)) {
            if ($this->isSigned($message)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param MessageInterface $message request to verify digest for
     *
     * @return bool true iff digest header exists and is correct
     */
    public function isValidDigest(MessageInterface $message): bool
    {
        $this->status = [];
        if (0 == sizeof($message->getHeader('Digest'))) {
            $this->status[] = 'Digest header missing';

            return false;
        }
        try {
            $bodyDigest = BodyDigest::fromMessage($message);
        } catch (DigestException $e) {
            $this->status[] = $e->getMessage();

            return false;
        }

        $isValidDigest = $bodyDigest->isValid($message);
        if (!$isValidDigest) {
            $this->status[] = 'Digest header invalid';
        }

        return $isValidDigest;
    }

    /**
     * @param MessageInterface $message request to verify
     *
     * @return bool true iff Signature header exists and is valid
     *
     * @throws Exception
     */
    public function isSigned(MessageInterface $message): bool
    {
        $this->status = [];
        try {
            $verification = new Verification($message, $this->keyStore, 'Signature');
            $result = $verification->verify();
            $this->status[] =
                "Message SigningString: '".
                base64_encode($verification->getSigningString()).
                "'";

            return $result;
        } catch (Exception $e) {
            // TODO: Match at least one header
            switch (get_class($e)) {
                case 'HttpSignatures\HeaderException':
                    $this->status[] = 'Signature header not found';

                    return false;
                    break;
                case 'HttpSignatures\SignatureParseException':
                    $this->status[] = 'Signature header malformed';

                    return false;
                    break;
                case 'HttpSignatures\SignedHeaderNotPresentException':
                case 'HttpSignatures\KeyStoreException':
                case 'HttpSignatures\SignatureException':
                    $this->status[] = $e->getMessage();

                    return false;
                    break;
                default:
                    $this->status[] = 'Unknown exception '.get_class($e).': '.$e->getMessage();
                    throw $e;
                    break;
            }
        }
    }

    /**
     * @param MessageInterface $message request to verify
     *
     * @return bool true iff Authorization header exists, is valid, digest header exists, and is correct
     *
     * @throws Exception
     */
    public function isAuthorizedWithDigest(MessageInterface $message): bool
    {
        if ($this->isValidDigest($message)) {
            if ($this->isAuthorized($message)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param MessageInterface $message request to verify
     *
     * @return bool true iff Authorization header exists and is valid
     *
     * @throws Exception
     */
    public function isAuthorized(MessageInterface $message): bool
    {
        $this->status = [];
        try {
            $verification = new Verification($message, $this->keyStore, 'Authorization');
            $result = $verification->verify();
            $this->status[] =
                "Message SigningString: '".
                base64_encode($verification->getSigningString()).
                "'";

            return $result;
        } catch (Exception $e) {
            // TODO: Match at least one header
            switch (get_class($e)) {
                case 'HttpSignatures\HeaderException':
                    $this->status[] = 'Authorization header not found';

                    return false;
                    break;
                case 'HttpSignatures\SignatureParseException':
                    $this->status[] = 'Authorization header malformed';

                    return false;
                    break;
                default:
                    $this->status[] = 'Unknown exception '.get_class($e).': '.$e->getMessage();
                    throw $e;
                    break;
            }
        }
    }

    /**
     * @return KeyStoreInterface used key store for verification
     */
    public function keyStore(): KeyStoreInterface
    {
        return $this->keyStore;
    }

    /**
     * @return string[] list of errors during verification
     */
    public function getStatus(): array
    {
        return $this->status;
    }
}
