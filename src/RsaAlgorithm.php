<?php
declare(strict_types=1);

namespace HttpSignatures;

/**
 * Class RsaAlgorithm.
 */
class RsaAlgorithm extends AsymmetricAlgorithm
{
    /**
     * {@inheritdoc}
     *
     * @noinspection PhpMissingParentCallCommonInspection
     */
    protected function namePrefix(): string
    {
        return 'rsa';
    }
}
