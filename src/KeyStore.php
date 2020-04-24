<?php

namespace HttpSignatures;

class KeyStore implements KeyStoreInterface
{
    /** @var Key[] */
    private $keys;

    /**
     * @param mixed[]|null $keys
     *
     * @throws KeyException
     */
    public function __construct(?array $keys = [])
    {
        $this->keys = [];
        if (!empty($keys)) {
            foreach ($keys as $id => $key) {
                $this->keys[$id] = new Key($id, $key);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function fetch(?string $keyId = null): Key
    {
        if (empty($keyId) && 1 == sizeof($this->keys)) {
            return reset($this->keys);
        }
        if (isset($this->keys[$keyId])) {
            return $this->keys[$keyId];
        } else {
            throw new KeyStoreException("Key '$keyId' not found");
        }
    }

    /**
     * @return int number of stored keys
     */
    public function count(): int
    {
        return sizeof($this->keys);
    }

    /**
     * @param mixed[] $keys
     *
     * @throws KeyException
     * @throws KeyStoreException
     */
    public function addKeys(array $keys)
    {
        $newKeys = [];
        foreach ($keys as $id => $key) {
            if (isset($this->keys[$id])) {
                throw new KeyStoreException("keyId '$id' already in Key Store", 1);
            } else {
                $newKeys[$id] = new Key($id, $key);
            }
        }
        $this->keys = array_merge($newKeys, $this->keys);
    }
}
