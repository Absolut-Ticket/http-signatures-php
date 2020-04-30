<?php

declare(strict_types=1);

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

/**
 * Class Signature.
 */
class Signature
{
    /** @var Key */
    private $key;

    /** @var AlgorithmInterface */
    private $algorithm;

    /** @var SigningString */
    private $signingString;

    /**
     * @param MessageInterface    $message        request that gets signed
     * @param Key                 $key            used key
     * @param AlgorithmInterface  $algorithm      used algorithm
     * @param HeaderList          $headerList     list of headers used for signing
     * @param SignatureDates|null $signatureDates signature dates used for signing
     */
    public function __construct(MessageInterface $message, Key $key, AlgorithmInterface $algorithm,
                                HeaderList $headerList, ?SignatureDates $signatureDates = null)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->signingString = new SigningString($headerList, $message, $signatureDates);
    }

    /**
     * @return string signature
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    public function string(): string
    {
        return $this->algorithm->sign(
            $this->key->getSigningKey(),
            $this->signingString->string(),
            $this->key->getHashAlgorithm()
        );
    }
}
