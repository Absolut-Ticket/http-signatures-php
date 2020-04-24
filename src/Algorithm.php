<?php

namespace HttpSignatures;

use RuntimeException;

abstract class Algorithm implements AlgorithmInterface
{
    /** @var string */
    protected $digestName;

    /**
     * @param string $digestName the name of the hashing algorithm to use
     *
     * @throws AlgorithmException
     */
    public function __construct(string $digestName)
    {
        if (in_array($digestName, ['sha1', 'sha256', 'sha384', 'sha512', 'hs2019'])) {
            $this->digestName = $digestName;
        } else {
            throw new AlgorithmException($digestName.' is not a supported hash format');
        }
    }

    /**
     * @param string $name the name of the algorithm to create
     *
     * @return AlgorithmInterface the created algorithm
     *
     * @throws AlgorithmException
     */
    public static function create(string $name): AlgorithmInterface
    {
        switch ($name) {
            case 'hmac-sha1':
                return new HmacAlgorithm('sha1');
                break;
            case 'hmac-sha256':
                return new HmacAlgorithm('sha256');
                break;
            case 'rsa-sha1':
                return new RsaAlgorithm('sha1');
                break;
            case 'rsa-sha256':
                return new RsaAlgorithm('sha256');
                break;
            case 'dsa-sha1':
                return new DsaAlgorithm('sha1');
                break;
            case 'dsa-sha256':
                return new DsaAlgorithm('sha256');
                break;
            case 'ec-sha1':
                return new EcAlgorithm('sha1');
                break;
            case 'ec-sha256':
                return new EcAlgorithm('sha256');
                break;
            default:
                throw new AlgorithmException("No algorithm named '$name'");
                break;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        if (in_array($this->digestName, ['hs2019'])) {
            return $this->digestName;
        } else {
            return $this->namePrefix().'-'.$this->digestName;
        }
    }

    /**
     * @return string the algorithm prefix specifying this algorithm
     */
    protected function namePrefix(): string
    {
        throw new RuntimeException('Name Prefix is not implemented in the '.get_class($this).' class');
    }

    /**
     * @param string $digestName the name of the hashing algorithm
     *
     * @return int integer code of hash algorithm
     * @throws AlgorithmException
     */
    protected function getHashAlgorithm(string $digestName): int
    {
        switch ($digestName) {
            case 'hs2019': //default for hs2019 is SHA512
            case 'sha512':
                return OPENSSL_ALGO_SHA512;
            case 'sha384':
                return OPENSSL_ALGO_SHA384;
            case 'sha256':
                return OPENSSL_ALGO_SHA256;
            case 'sha1':
                return OPENSSL_ALGO_SHA1;
            default:
                throw new AlgorithmException($digestName.' is not a supported hash format');
        }
    }
}
