<?php

namespace HttpSignatures;

class RsaAlgorithm extends AsymmetricAlgorithm
{
    /**
     * {@inheritdoc}
     */
    protected function namePrefix(): string
    {
        return 'rsa';
    }
}
