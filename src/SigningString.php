<?php

declare(strict_types=1);

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Class SigningString.
 */
class SigningString
{
    /** @var HeaderList */
    private $headerList;

    /** @var MessageInterface */
    private $message;

    /** @var SignatureDates */
    private $signatureDates;

    // TODO: Make signatureDates mandatory

    /**
     * @param HeaderList          $headerList     list of headers to consider in signing string
     * @param MessageInterface    $message        request for which to build signing string
     * @param SignatureDates|null $signatureDates signature dates to consider in signing string
     */
    public function __construct(HeaderList $headerList, $message, $signatureDates = null)
    {
        $this->headerList = $headerList;
        $this->message = $message;
        $this->signatureDates = $signatureDates;
    }

    /**
     * @return string constructed signing string
     *
     * @throws HeaderException
     * @throws SignedHeaderNotPresentException
     */
    public function string(): string
    {
        return implode("\n", $this->lines());
    }

    /**
     * @return string[] array of lines of the signing string
     *
     * @throws SignedHeaderNotPresentException|HeaderException
     */
    private function lines(): array
    {
        $lines = [];
        if (!is_null($this->headerList->names)) {
            foreach ($this->headerList->names as $name) {
                $lines[] = $this->line($name);
            }
        }

        return $lines;
    }

    /**
     * @param string $name name of the (pseudo)-header for which to create the line
     *
     * @return string created line
     *
     * @throws HeaderException
     * @throws SignedHeaderNotPresentException
     */
    private function line(string $name): string
    {
        if (preg_match('/^\(.*\)$/', $name)) {
            switch ($name) {
                case '(request-target)':
                    return sprintf('%s: %s', $name, $this->requestTarget());
                    break;

                case '(created)':
                    return sprintf('%s: %s', $name, $this->signatureDates->getCreated());
                    break;

                case '(expires)':
                    return sprintf('%s: %s', $name, $this->signatureDates->getExpires());
                    break;

                default:
                    throw new HeaderException("Special header '$name' not understood", 1);
                    break;
            }
        } else {
            return sprintf('%s: %s', $name, $this->headerValue($name));
        }
    }

    /**
     * @return string target used in signing string
     *
     * @throws HeaderException
     */
    private function requestTarget(): string
    {
        if (!($this->message instanceof RequestInterface)) {
            //requestTarget is only possible for requests
            throw new HeaderException('Special header (request-target) is only allowed for requests', 1);
        }

        return sprintf(
            '%s %s',
            strtolower($this->message->getMethod()),
            $this->message->getRequestTarget()
        );
    }

    /**
     * @param string $name name of the header for which to get the value
     *
     * @return string header value
     *
     * @throws SignedHeaderNotPresentException
     */
    private function headerValue(string $name): string
    {
        if ($this->message->hasHeader($name)) {
            $header = '';
            $values = $this->message->getHeader($name);
            while (sizeof($values) > 0) {
                $header = $header.$values[0];
                array_shift($values);
                if (sizeof($values) > 0) {
                    $header = $header.', ';
                }
            }
            // $header = $this->message->getHeader($name);

            return $header;
        // return end($header);
        } else {
            throw new SignedHeaderNotPresentException("Header '$name' not in message");
        }
    }
}
