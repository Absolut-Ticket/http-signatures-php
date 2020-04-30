<?php

declare(strict_types=1);

namespace HttpSignatures;

/**
 * Class SignatureParameters.
 */
class SignatureParameters
{
    /**
     * @var Key
     */
    private $key;
    /**
     * @var AlgorithmInterface
     */
    private $algorithm;
    /**
     * @var HeaderList
     */
    private $headerList;
    /**
     * @var Signature
     */
    private $signature;
    /**
     * @var SignatureDates|null
     */
    private $signatureDates;

    /**
     * @param Key                 $key            used key
     * @param AlgorithmInterface  $algorithm      used algorithm
     * @param HeaderList          $headerList     used list of headers
     * @param Signature           $signature      computed signature
     * @param SignatureDates|null $signatureDates used signature dates
     */
    public function __construct(Key $key, AlgorithmInterface $algorithm, HeaderList $headerList, Signature $signature,
                                ?SignatureDates $signatureDates = null)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
        $this->signature = $signature;
        $this->signatureDates = $signatureDates;
    }

    /**
     * @return string signature parameters concatenated as string
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    public function string(): string
    {
        return implode(',', $this->parameterComponents());
    }

    /**
     * @return string[] list of all components in the signature
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    private function parameterComponents(): array
    {
        $components = [];
        $components[] = sprintf('keyId="%s"', $this->key->getId());
        $components[] = sprintf('algorithm="%s"', $this->algorithm->name());
        if (in_array($this->algorithm->name(), ['hs2019'])) {
            if (!empty($this->signatureDates)) {
                if (in_array(
                        '(created)',
                        $this->headerList->listHeaders()
                    ) &&
                    !empty($this->signatureDates->getCreated())
                ) {
                    $components[] = sprintf('created=%s', $this->signatureDates->getCreated());
                }
                if (in_array(
                        '(expires)',
                        $this->headerList->listHeaders()
                    ) &&
                    !empty($this->signatureDates->getExpires())
                ) {
                    $components[] = sprintf('expires=%s', $this->signatureDates->getExpires());
                }
            }
        }
        if ($this->headerList->headerListSpecified()) {
            $components[] = sprintf('headers="%s"', $this->headerList->string());
        }
        $components[] = sprintf('signature="%s"', $this->signatureBase64());

        return $components;
    }

    /**
     * @return string signature in base64 encoded
     *
     * @throws AlgorithmException
     * @throws HeaderException
     * @throws KeyException
     * @throws SignedHeaderNotPresentException
     */
    private function signatureBase64(): string
    {
        return base64_encode($this->signature->string());
    }
}
