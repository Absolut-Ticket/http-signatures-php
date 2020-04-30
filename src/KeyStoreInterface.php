<?php
declare(strict_types=1);

namespace HttpSignatures;

/**
 * Interface KeyStoreInterface.
 */
interface KeyStoreInterface
{
    /**
     * @param string|null $keyId the key id for which to fetch the secret
     * @return Key secret for the specified $keyId
     * @throws KeyStoreException if the keyId was not found in the store
     */
    public function fetch(?string $keyId = null): Key;
}
