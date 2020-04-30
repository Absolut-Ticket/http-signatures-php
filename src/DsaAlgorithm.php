<?php
declare(strict_types=1);

namespace HttpSignatures;

/**
 * Class DsaAlgorithm.
 */
class DsaAlgorithm extends AsymmetricAlgorithm
{
    /**
     * {@inheritdoc}
     *
     * @noinspection PhpMissingParentCallCommonInspection
     */
    protected function namePrefix(): string
    {
        return 'dsa';
    }
}
