<?php

declare(strict_types=1);

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

/**
 * Class Verification.
 */
class Verification
{
    /** @var MessageInterface */
    private $message;

    /** @var KeyStoreInterface */
    private $keyStore;

    /** @var string */
    private $header;

    /** @var mixed[] */
    private $parameters;

    /**
     * @param MessageInterface  $message  request to verify
     * @param KeyStoreInterface $keyStore key store to get verification key from
     * @param string            $header   name of the header containing the signature
     *
     * @throws HeaderException
     * @throws SignatureParseException
     */
    public function __construct(MessageInterface $message, KeyStoreInterface $keyStore, string $header)
    {
        $this->message = $message;
        $this->keyStore = $keyStore;

        // TODO: Find one signature line within multiple header instances
        // This will permit e.g. Authorization: Bearer to co-exist with Authorization: Signature
        switch (strtolower($header)) {
            case 'signature':
                if (0 == sizeof($message->getHeader('Signature'))) {
                    throw new HeaderException("Cannot locate header 'Signature'");
                } elseif (sizeof($message->getHeader('Signature')) > 1) {
                    throw new HeaderException("Multiple headers named 'Signature'");
                }
                $signatureLine = $message->getHeader('Signature')[0];
                break;
            case 'authorization':
                if (0 == sizeof($message->getHeader('Authorization'))) {
                    throw new HeaderException("Cannot locate header 'Authorization'");
                } elseif (sizeof($message->getHeader('Authorization')) > 1) {
                    throw new HeaderException("Multiple headers named 'Authorization'");
                }
                $authorizationType = explode(' ', $message->getHeader('Authorization')[0])[0];
                if ('Signature' == $authorizationType) {
                    $signatureLine = substr($message->getHeader('Authorization')[0], strlen('Signature '));
                } else {
                    throw new HeaderException("Unknown Authorization type $authorizationType, cannot verify");
                }
                break;
            default:
                throw new HeaderException("Unknown header type '".$header."', cannot verify");
                break;
        }
        $signatureParametersParser = new SignatureParametersParser(
            $signatureLine
        );
        $this->parameters = $signatureParametersParser->parse();
    }

    /**
     * @return bool true iff the signature is valid
     *
     * @throws AlgorithmException
     * @throws Exception
     * @throws HeaderException
     * @throws KeyException
     * @throws KeyStoreException
     * @throws SignedHeaderNotPresentException
     */
    public function verify(): bool
    {
        try {
            $key = $this->key();
            $algorithm = $this->getAlgorithm($key);

            return $algorithm->verify(
                $this->getSigningString(),
                $this->providedSignature(),
                $key->getVerifyingKey());
            // } catch (SignatureParseException $e) {
            //     return false;
        } catch (KeyStoreException $e) {
            throw new KeyStoreException("Cannot locate key for supplied keyId '{$this->parameter('keyId')}'", 1);
            // return false;
            // } catch (SignedHeaderNotPresentException $e) {
            //     return false;
        }
    }

    /**
     * @return Key key associated with the key id value
     *
     * @throws Exception
     * @throws KeyStoreException
     */
    private function key(): Key
    {
        return $this->keyStore->fetch($this->parameter('keyId'));
    }

    /**
     * @param string $name name of the (pseudo)-header to get the value for
     *
     * @return string value of the (pseudo)-header
     *
     * @throws Exception
     */
    private function parameter(string $name): string
    {
        // $parameters = $this->parameters();
        if (!isset($this->parameters[$name])) {
            if ('headers' == $name) {
                return 'date';
            } else {
                throw new Exception("Signature parameters does not contain '$name'");
            }
        }

        return $this->parameters[$name];
    }

    /**
     * @param Key $key algorithm is determined based on the key information
     *
     * @return AlgorithmInterface algorithm to use for verification
     *
     * @throws AlgorithmException
     * @throws Exception
     * @throws KeyException
     */
    private function getAlgorithm(Key $key): AlgorithmInterface
    {
        $hashAlgorithm = $key->getHashAlgorithm();
        if (null == $hashAlgorithm) {
            $hashAlgorithm = explode('-', $this->parameter('algorithm'))[1];
        }
        switch ($key->getClass()) {
            case 'secret':
                return new HmacAlgorithm($hashAlgorithm);
                break;
            case 'asymmetric':
                return new AsymmetricAlgorithm($hashAlgorithm); //we don't need to distinguish RSA/ECDSA here
                break;
            default:
                throw new Exception("Unknown key type '".$key->getType()."', cannot verify");
        }
    }

    private function getSignatureDates(): SignatureDates
    {
        $dates = new SignatureDates();
        if (array_key_exists('created', $this->parameters)) {
            $dates->setCreated($this->parameters['created']);
        }
        if (array_key_exists('expires', $this->parameters)) {
            $dates->setExpires($this->parameters['expires']);
        }

        return $dates;
    }

    /**
     * @return HeaderList constructed list of headers from signature string
     *
     * @throws Exception
     */
    private function headerList(): HeaderList
    {
        return HeaderList::fromString($this->parameter('headers'));
    }

    /**
     * @return string provided signature string
     *
     * @throws Exception
     */
    private function providedSignature(): string
    {
        return base64_decode($this->headerParameter('signature'));
    }

    /**
     * @param string $name name of the (pseudo)-header to get the value for
     *
     * @return string value of the (pseudo)-header
     *
     * @throws Exception
     */
    private function headerParameter(string $name): string
    {
        // $headerParameters = $this->headerParameters();
        if (!isset($this->parameters[$name])) {
            throw new Exception("'$this->header' header parameters does not contain '$name'");
        }

        return $this->parameters[$name];
    }

    /**
     * @return string the signing string to verify
     *
     * @throws Exception
     * @throws HeaderException
     * @throws SignedHeaderNotPresentException
     */
    public function getSigningString(): string
    {
        $signatureDates = $this->getSignatureDates();

        $signedString = new SigningString(
            $this->headerList(),
            $this->message,
            $signatureDates
        );

        return $signedString->string();
    }
}
