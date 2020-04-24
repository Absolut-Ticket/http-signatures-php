<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

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

    /**
     * @param Key                 $key            key to use
     * @param AlgorithmInterface  $algorithm      algorithm to use
     * @param HeaderList          $headerList     list of headers to use
     * @param SignatureDates|null $signatureDates signature dates to use
     */
    public function __construct(Key $key, AlgorithmInterface $algorithm, HeaderList $headerList, SignatureDates $signatureDates = null)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
        $this->signatureDates = $signatureDates;
    }

    /**
     * @param RequestInterface $message request to sign
     *
     * @return RequestInterface signed request
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    public function signWithDigest(RequestInterface $message): RequestInterface
    {
        $bodyDigest = new BodyDigest();
        $this->headerList = $bodyDigest->putDigestInHeaderList($this->headerList);

        return $this->sign($bodyDigest->setDigestHeader($message));
    }

    /**
     * @param RequestInterface $message request to sign
     *
     * @return RequestInterface signed request
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    public function sign(RequestInterface $message): RequestInterface
    {
        $signatureParameters = $this->signatureParameters($message);
        $message = $message->withAddedHeader('Signature', $signatureParameters->string());

        return $message;
    }

    /**
     * @param RequestInterface $message request to parse
     *
     * @return SignatureParameters parsed signature parameters
     */
    private function signatureParameters(RequestInterface $message): SignatureParameters
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
     * @param RequestInterface $message request to sign
     *
     * @return Signature created signature
     */
    private function signature(RequestInterface $message): Signature
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
     * @param RequestInterface $message request to authorize
     *
     * @return RequestInterface authorized request
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    public function authorizeWithDigest(RequestInterface $message): RequestInterface
    {
        $bodyDigest = new BodyDigest();
        $this->headerList = $bodyDigest->putDigestInHeaderList($this->headerList);

        return $this->authorize($bodyDigest->setDigestHeader($message));
    }

    /**
     * @param RequestInterface $message request to authorize
     *
     * @return RequestInterface authorized request
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    public function authorize(RequestInterface $message): RequestInterface
    {
        $signatureParameters = $this->signatureParameters($message);
        $message = $message->withAddedHeader('Authorization', 'Signature '.$signatureParameters->string());

        return $message;
    }

    /**
     * @param RequestInterface $message request to parse
     *
     * @return string signing string used for signing
     *
     * @throws HeaderException
     * @throws SignedHeaderNotPresentException
     */
    public function getSigningString(RequestInterface $message): string
    {
        $singingString = new SigningString($this->headerList, $message, $this->signatureDates);

        return $singingString->string();
    }
}
