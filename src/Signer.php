<?php

declare(strict_types=1);

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

/**
 * Class Signer.
 */
class Signer
{
    /** @var Key */
    private $key;

    /** @var AlgorithmInterface */
    private $algorithm;

    /** @var HeaderList */
    private $headerList;
    /**
     * @var SignatureDates|null
     */
    private $signatureDates;

    /** @var string */
    private $digestHashAlgorithm;

    /**
     * @param Key                 $key                 key to use
     * @param AlgorithmInterface  $algorithm           algorithm to use
     * @param HeaderList          $headerList          list of headers to use
     * @param SignatureDates|null $signatureDates      signature dates to use
     * @param string|null         $digestHashAlgorithm the hashing algorithm used for computing the digest header
     */
    public function __construct(Key $key, AlgorithmInterface $algorithm, HeaderList $headerList,
                                SignatureDates $signatureDates = null, ?string $digestHashAlgorithm = null)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
        $this->signatureDates = $signatureDates;
        $this->digestHashAlgorithm = $digestHashAlgorithm;
    }

    /**
     * @param MessageInterface $message request to sign
     *
     * @return MessageInterface signed request
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     * @throws DigestException
     */
    public function signWithDigest(MessageInterface $message): MessageInterface
    {
        $bodyDigest = new BodyDigest($this->digestHashAlgorithm);
        $this->headerList = $bodyDigest->putDigestInHeaderList($this->headerList);

        return $this->sign($bodyDigest->setDigestHeader($message));
    }

    /**
     * @param MessageInterface $message request to sign
     *
     * @return MessageInterface signed request
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    public function sign(MessageInterface $message): MessageInterface
    {
        $signatureParameters = $this->signatureParameters($message);
        $message = $message->withAddedHeader('Signature', $signatureParameters->string());

        return $message;
    }

    /**
     * @param MessageInterface $message request to parse
     *
     * @return SignatureParameters parsed signature parameters
     */
    private function signatureParameters(MessageInterface $message): SignatureParameters
    {
        return new SignatureParameters(
            $this->key,
            $this->algorithm,
            $this->headerList,
            $this->signature($message),
            $this->signatureDates
        );
    }

    /**
     * @param MessageInterface $message request to sign
     *
     * @return Signature created signature
     */
    private function signature(MessageInterface $message): Signature
    {
        return new Signature(
            $message,
            $this->key,
            $this->algorithm,
            $this->headerList,
            $this->signatureDates
        );
    }

    /**
     * @param MessageInterface $message request to authorize
     *
     * @return MessageInterface authorized request
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     * @throws DigestException
     */
    public function authorizeWithDigest(MessageInterface $message): MessageInterface
    {
        $bodyDigest = new BodyDigest($this->digestHashAlgorithm);
        $this->headerList = $bodyDigest->putDigestInHeaderList($this->headerList);

        return $this->authorize($bodyDigest->setDigestHeader($message));
    }

    /**
     * @param MessageInterface $message request to authorize
     *
     * @return MessageInterface authorized request
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    public function authorize(MessageInterface $message): MessageInterface
    {
        $signatureParameters = $this->signatureParameters($message);
        $message = $message->withAddedHeader('Authorization', 'Signature '.$signatureParameters->string());

        return $message;
    }

    /**
     * @param MessageInterface $message request to parse
     *
     * @return string signing string used for signing
     *
     * @throws HeaderException
     * @throws SignedHeaderNotPresentException
     */
    public function getSigningString(MessageInterface $message): string
    {
        $singingString = new SigningString($this->headerList, $message, $this->signatureDates);

        return $singingString->string();
    }
}
