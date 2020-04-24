<?php

namespace HttpSignatures;

class HmacAlgorithm extends Algorithm
{
    /**
     * {@inheritdoc}
     */
    public function verify(string $message, string $signature, $secret, ?string $hashAlgorithm = null): bool
    {
        return $this->sign($secret, $message, $hashAlgorithm) == $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function sign($secret, string $data, ?string $hashAlgorithm = null): string
    {
        return hash_hmac($this->getHashAlgorithmName($hashAlgorithm ?: $this->digestName), $data, $secret, true);
    }

    /**
     * @param string $digestName the name of the hash algorithm
     *
     * @return string name of the hash algorithm to use
     */
    private function getHashAlgorithmName(string $digestName): string
    {
        if ('hs2019' == $digestName) {
            return 'sha512'; //default for hs2019 is SHA512
        }

        return $digestName;
    }

    protected function namePrefix(): string
    {
        return 'hmac';
    }
}
