<?php

declare(strict_types=1);

namespace HttpSignatures;

/**
 * Interface AlgorithmInterface.
 */
interface AlgorithmInterface
{
    /**
     * @return string the name of the algorithm
     */
    public function name(): string;

    /**
     * @param mixed       $key           see https://www.php.net/manual/de/function.openssl-pkey-get-private.php for
     *                                   allowed signing keys
     * @param string      $data          the data to sign
     * @param string|null $hashAlgorithm the hashing algorithm to use or nul if it should use the one specified by
     *                                   "algorithm"
     *
     * @return string returns the signature as string
     *
     * @throws AlgorithmException
     */
    public function sign($key, string $data, ?string $hashAlgorithm = null): string;

    /**
     * Verifies the given signature.
     *
     * @param string      $message       the message to verify
     * @param string      $signature     the decoded signature of the message to verify
     * @param mixed       $verifyingKey  see https://www.php.net/manual/de/function.openssl-pkey-get-private.php for
     *                                   allowed keys
     * @param string|null $hashAlgorithm the hashing algorithm to use or nul if it should use the one specified by
     *                                   "algorithm"
     *
     * @return bool true iff the signature is valid
     *
     * @throws AlgorithmException
     */
    public function verify(string $message, string $signature, $verifyingKey, ?string $hashAlgorithm = null): bool;
}
