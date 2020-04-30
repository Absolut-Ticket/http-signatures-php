<?php
declare(strict_types=1);

namespace HttpSignatures;

/**
 * Class AsymmetricAlgorithm.
 */
class AsymmetricAlgorithm extends Algorithm
{
    /**
     * {@inheritdoc}
     */
    public function sign($signingKey, string $data, ?string $hashAlgorithm = null): string
    {
        $algorithm = $this->getHashAlgorithm($hashAlgorithm ?: $this->digestName);
        $key = openssl_pkey_get_private($signingKey);
        if (!$key) {
            throw new AlgorithmException("OpenSSL doesn't understand the supplied key (not valid or not found)");
        }
        $signature = '';
        openssl_sign($data, $signature, $key, $algorithm);

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $message, string $signature, $verifyingKey, ?string $hashAlgorithm = null): bool
    {
        $algorithm = $this->getHashAlgorithm($hashAlgorithm ?: $this->digestName);
        $key = openssl_pkey_get_public($verifyingKey);
        if (!$key) {
            throw new AlgorithmException("OpenSSL doesn't understand the supplied key (not valid or not found)");
        }

        return 1 === openssl_verify($message, $signature, $verifyingKey, $algorithm);
    }
}
