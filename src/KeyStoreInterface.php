<?php

namespace HttpSignatures;

interface KeyStoreInterface
{
    /**
     * return the secret for the specified $keyId.
     *
     * @param string|null $keyId
     *
     * @return Key
     *
     * @throws KeyStoreException
     */
    public function fetch(?string $keyId = null): Key;
}
