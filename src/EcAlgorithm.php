<?php
declare(strict_types=1);

namespace HttpSignatures;

/**
 * Class EcAlgorithm.
 */
class EcAlgorithm extends AsymmetricAlgorithm
{
    /**
     * {@inheritdoc}
     *
     * @noinspection PhpMissingParentCallCommonInspection
     */
    protected function namePrefix(): string
    {
        return 'ec';
    }
}
