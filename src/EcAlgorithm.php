<?php

namespace HttpSignatures;

class EcAlgorithm extends AsymmetricAlgorithm
{
    /**
     * {@inheritdoc}
     */
    protected function namePrefix(): string
    {
        return 'ec';
    }
}
