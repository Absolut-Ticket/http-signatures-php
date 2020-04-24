<?php

namespace HttpSignatures;

class DsaAlgorithm extends AsymmetricAlgorithm
{
    /**
     * {@inheritdoc}
     */
    protected function namePrefix(): string
    {
        return 'dsa';
    }
}
