<?php

declare(strict_types=1);

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

/**
 * Class Context.
 */
class Context
{
    /** @var string[] */
    private $headers;

    /** @var KeyStoreInterface */
    private $keyStore;

    /** @var string[] */
    private $keys;

    /** @var string */
    private $signingKeyId;

    /** @var string */
    private $defaultCreated = 'now';

    /** @var string */
    private $defaultExpires = 'none';

    /** @var string */
    private $signatureAlgorithm;

    /** @var string */
    private $hashAlgorithm;

    /** @var string[] */
    private $newAlgorithmNames;

    /** @var string */
    private $digestHashAlgorithm;

    /**
     * @param array $args The context configuration
     *
     * @throws AlgorithmException
     * @throws ContextException
     * @throws Exception
     */
    public function __construct(array $args = [])
    {
        /*
         * [$this->newAlgorithmNames Only 'hs2019' for now]
         * @var array
         */
        $this->newAlgorithmNames = ['hs2019'];

        if (isset($args['keys']) && isset($args['keyStore'])) {
            throw new Exception(__CLASS__.' accepts keys or keyStore but not both');
        } elseif (isset($args['keys'])) {
            // array of keyId => keySecret
            $this->keys = $args['keys'];
        } elseif (isset($args['keyStore'])) {
            $this->setKeyStore($args['keyStore']);
        }

        // algorithm for signing; not necessary for verifying.
        if (isset($args['algorithm'])) {
            $this->setAlgorithm($args['algorithm']);
        } else {
            $this->setAlgorithm('hs2019');
        }

        if (isset($args['digestHashAlgorithm'])) {
            $this->digestHashAlgorithm = $args['digestHashAlgorithm'];
        } else {
            $this->digestHashAlgorithm = null;
        }

        // hash algorithm can be used if algorithm is hs2019
        if (isset($args['hashAlgorithm'])) {
            $this->hashAlgorithm = $args['hashAlgorithm'];
        }

        // TODO: Read headers as minimum for verification
        // headers list for signing; not necessary for verifying.
        if (isset($args['headers'])) {
            $this->setHeaders($args['headers']);
            // $this->headers = $args['headers'];
        }

        // signingKeyId specifies the key used for signing messages.
        if (isset($args['signingKeyId'])) {
            $this->signingKeyId = $args['signingKeyId'];
        } elseif (isset($args['keys']) && 1 === count($args['keys'])) {
            list($this->signingKeyId) = array_keys($args['keys']); // first key
        }
    }

    /**
     * @param KeyStoreInterface $keyStore the keystore to use
     */
    private function setKeyStore(KeyStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
    }

    /**
     * @param string $name the algorithm to use
     *
     * @throws AlgorithmException
     * @throws ContextException
     */
    public function setAlgorithm(string $name)
    {
        if (empty($name)) {
            $name = 'hs2019';
        }

        $algorithm = explode('-', $name);
        if (in_array($name, $this->newAlgorithmNames)) {
            $this->hashAlgorithm = $name;
        } elseif (sizeof($algorithm) < 2) {
            throw new ContextException("Unrecognised algorithm: '$name'", 1);
        } else {
            switch ($algorithm[0]) {
                case 'ec':
                case 'rsa':
                case 'dsa':
                case 'hmac':
                    $this->signatureAlgorithm = $algorithm[0];
                    break;

                default:
                    throw new AlgorithmException("Unrecognised signature algorithm: '$algorithm[0]'", 1);
                    break;
            }
            switch ($algorithm[1]) {
                case 'sha1':
                case 'sha256':
                case 'sha384':
                case 'sha512':
                    $this->hashAlgorithm = $algorithm[1];
                    break;

                default:
                    throw new AlgorithmException("Unrecognised hash algorithm: '$algorithm[1]'", 1);
                    break;
            }
        }
    }

    /**
     * Sets the headers to use when signing.
     *
     * @param string[]|string|null $headers
     */
    public function setHeaders($headers = null)
    {
        if (is_null($headers)) {
            $newHeaders = null;
        } elseif (is_array($headers)) {
            $newHeaders = $headers;
        } else {
            $newHeaders = explode(' ', $headers);
        }

        $this->headers = $newHeaders;
    }

    /**
     * Signs the given request via Signature header field.
     *
     * @param MessageInterface $message The request to sign
     *
     * @return MessageInterface the signed request
     *
     * @throws AlgorithmException
     * @throws ContextException
     * @throws Exception
     * @throws KeyException
     * @throws SignatureDatesException
     */
    public function sign(MessageInterface $message): MessageInterface
    {
        return $this->signer()->sign($message);
    }

    /**
     * @param bool $strictDates whether dates should be strict (i.e. created not in the future, expires not in the past)
     *
     * @return Signer the constructed signer
     *
     * @throws AlgorithmException
     * @throws ContextException
     * @throws Exception
     * @throws KeyException
     * @throws SignatureDatesException
     */
    public function signer(bool $strictDates = true): Signer
    {
        try {
            $signingKey = $this->signingKey();
        } catch (ContextException $e) {
            throw $e;
        }
        if (empty($this->hashAlgorithm)) {
            $hashAlgorithm = 'hs2019';
        } else {
            $hashAlgorithm = $this->hashAlgorithm;
        }
        if (empty($this->signatureAlgorithm)) {
            $signatureAlgorithm = $signingKey->getType();
        } else {
            $signatureAlgorithm = $this->signatureAlgorithm;
        }
        $signingKeyType = $signingKey->getType();
        if ($signingKeyType != $signatureAlgorithm) {
            $error = "Signature algorithm '$this->signatureAlgorithm' cannot be ".
                "used with signing key type '$signingKeyType'";
            throw new ContextException($error, 1);
        }
        switch ($signingKeyType) {
            case 'rsa':
                $algorithm = new RsaAlgorithm($hashAlgorithm);
                break;
            case 'dsa':
                $algorithm = new DsaAlgorithm($hashAlgorithm);
                break;
            case 'hmac':
                $algorithm = new HmacAlgorithm($hashAlgorithm);
                break;
            case 'ec':
                $algorithm = new EcAlgorithm($hashAlgorithm);
                break;

            default:
                throw new ContextException("Unrecognised '$signingKeyType'", 1);
                break;
        }

        return new Signer(
            $this->signingKey(),
            $algorithm,
            $this->headerList(),
            $this->signatureDates($strictDates),
            $this->digestHashAlgorithm
        );
    }

    /**
     * @return Key signing key
     *
     * @throws Exception
     * @throws ContextException
     */
    private function signingKey(): Key
    {
        if (empty($this->signingKeyId) && (1 == $this->keyStore()->count())) {
            $this->signingKeyId = $this->keyStore()->fetch()->getId();
        }
        if (isset($this->signingKeyId)) {
            return $this->keyStore()->fetch($this->signingKeyId);
        } else {
            throw new ContextException('No implicit or specified signing key');
        }
    }

    /**
     * @return KeyStoreInterface currently used keystore
     *
     * @throws KeyException
     */
    private function keyStore(): KeyStoreInterface
    {
        if (empty($this->keyStore)) {
            $this->keyStore = new KeyStore($this->keys);
        }

        return $this->keyStore;
    }

    /**
     * @return HeaderList header list object
     */
    private function headerList(): HeaderList
    {
        if (!is_null($this->headers)) {
            return new HeaderList($this->headers, true);
        } elseif (in_array($this->hashAlgorithm, $this->newAlgorithmNames)) {
            return new HeaderList(['(created)'], false);
        } else {
            return new HeaderList(['date'], false);
        }
    }

    /**
     * Gets the signature dates created and expires.
     *
     * @param bool $strict whether dates should be strict (i.e. created not in the future, expires not in the past)
     *
     * @return SignatureDates the signatureDates object
     *
     * @throws SignatureDatesException
     */
    public function signatureDates(bool $strict = true): SignatureDates
    {
        $signatureDates = new SignatureDates();
        $signatureDates->setCreated(SignatureDates::offset($this->defaultCreated));
        $signatureDates->setExpires(SignatureDates::offset($this->defaultExpires, $signatureDates->getCreated()));
        if ($strict) {
            if ((time() - $signatureDates->getCreated()) < 0) {
                $error = "Cannot sign a message with 'created' in the future: ".time().','.
                    $signatureDates->getCreated();
                throw new SignatureDatesException($error, 1);
            }
            if (!empty($signatureDates->getExpires())) {
                if (($signatureDates->getExpires() - time()) < 0) {
                    $error = "Cannot sign a message with 'expires' in the past: ".time().','.
                        $signatureDates->getExpires();
                    throw new SignatureDatesException($error, 1);
                }
            }
        }

        return $signatureDates;
    }

    /**
     * Signs the given request via Authorization header field.
     *
     * @param MessageInterface $message the request to authorize
     *
     * @return MessageInterface the authorized request
     *
     * @throws AlgorithmException
     * @throws ContextException
     * @throws Exception
     * @throws KeyException
     * @throws SignatureDatesException
     */
    public function authorize(MessageInterface $message): MessageInterface
    {
        return $this->signer()->authorize($message);
    }

    /**
     * @return Verifier a new verifier
     *
     * @throws KeyException
     */
    public function verifier(): Verifier
    {
        return new Verifier($this->keyStore());
    }

    /**
     * Sets the default created offset.
     *
     * @param string|int $created
     */
    public function setCreated($created)
    {
        $this->defaultCreated = $created;
    }

    /**
     * Sets the default expires offset.
     *
     * @param string|int $expires
     */
    public function setExpires($expires)
    {
        $this->defaultExpires = $expires;
    }
}
