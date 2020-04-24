<?php

namespace HttpSignatures\tests;

use GuzzleHttp\Psr7\Request;
use HttpSignatures\Context;
use HttpSignatures\ContextException;
use HttpSignatures\HeaderException;
use HttpSignatures\KeyStore;
use HttpSignatures\SignatureDatesException;
use HttpSignatures\Tests\TestKeys;
use PHPUnit\Framework\TestCase;

class ContextTest extends TestCase
{
    private $context;

    private $signingKeySpec;

    public function setUp()
    {
        $this->signingContext = new Context([
          'headers' => ['(request-target)', 'date'],
          'algorithm' => 'rsa-sha256',
        ]);
        $this->verifyingContext = new Context();
        $this->signingKeySpec = ['rsa1' => TestKeys::rsaPrivateKey];
        // $this->sha256context = new Context([
        //     'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
        //     'algorithm' => 'rsa-sha256',
        //     'headers' => ['(request-target)', 'date'],
        // ]);
        $this->message = new Request(
          'GET',
          '/path?query=123',
          ['date' => 'today', 'accept' => 'llamas']
        );
    }

    public function testFailSignWithoutKeys()
    {
        $this->expectException(ContextException::class);
        $this->signingContext->signer()->sign($this->message);
    }

    public function testDefaultSigningContext()
    {
        $defaultContext = $this->createContext($this->signingKeySpec);
        $defaultContext->setCreated(1566239000);
        $dates = $defaultContext->signatureDates(false);
        $this->assertEquals(
          [1566239000, null],
          [$dates->getCreated(), $dates->getExpires()]
        );
        $signer = $defaultContext->signer();
        $this->assertEquals(
            implode("\n", [
              '(created): 1566239000',
            ]),
            $signer->getSigningString($this->message)
        );
        $signedMessage = $defaultContext->signer()->sign($this->message);
        $expectedSignatureLine =
            'keyId="rsa1",'.
            'algorithm="hs2019",'.
            'created=1566239000,'.
            'signature="Me94a2KUd1+9X8sAFqkHWn8Ze/hz4kREoCbqKn03BTwXd9gcVKMGp6'.
            'XfpdXalktOTlcNyli0dQlw9kNtU9VeJ1N8/nSj2TY96wQW6p397m6CdYCGJmAqZpf'.
            '/CzqJFJslp6i7iRB2GJMzbYbCsTVK/oEPlxMB0rMYxosVB2qwaLNsbqobo1FF9L1d'.
            'I0JE+M2l3Eil9K2Z/TMItRjIlii0a4l3qauxJ8fDOu5uo5mFywrm3oiWrihBBJvI+'.
            'n4cYmBc+gxByrDDYbH2n2gdKFykHkROdU/N4ic/nV7qycJxLCoWSyZpZp73ilYs4U'.
            'TZkh9B32LHJNAo/5D7YrKJXmX3NQ=="';
        $this->assertEquals(
            $expectedSignatureLine,
            $signedMessage->getHeader('Signature')[0]
        );
        $defaultContext->setExpires('+300');
        $dates = $defaultContext->signatureDates(false);
        $this->assertEquals(
          [1566239000, 1566239300],
          [$dates->getCreated(), $dates->getExpires()]
        );
        $defaultContext->setHeaders([
          '(request-target)', '(created)', '(expires)', ]);
        $signer = $defaultContext->signer(false);
        $signedMessage = $signer->sign($this->message);
        $this->assertEquals(
            implode("\n", [
              '(request-target): get /path?query=123',
              '(created): 1566239000',
              '(expires): 1566239300',
            ]),
            $signer->getSigningString($this->message)
        );
        $expectedSignatureLine =
            'keyId="rsa1",'.
            'algorithm="hs2019",'.
            'created=1566239000,'.
            'expires=1566239300,'.
            'headers="(request-target) (created) (expires)",'.
            'signature="Hav9yNOVldI9QzIRUCCP6PeGQ2ji/CtlZ5TWX0VVQ72ZMnch5hpvfj'.
            '53lDIg9sy14E7FazajttkX/OejwRGhHmlO/x9NGi/2aap8AuBIHXK+7jeP/rXxhf+'.
            'X2yrsF9Ihp/4DSbsketJinnH16Unrd7BknqTByDvgGIC7bCPeP/dCsAw7taIoVBaF'.
            'heO7HL1gPADjIjHeD/aZadsITM+HPc+rlNpgeAE3+3OzjUnUtT81LN0aqZHZJEmXh'.
            'BTHFm1vB2oGm5B/yayZ8KyUbc1z6iVsgAQestu4Y7wSivAnjooFolYKeJeYn6h1hx'.
            '5qbFVGQ6WF8V8cqrkbSzSfWyUhmg=="';
        $this->assertEquals(
            $expectedSignatureLine,
            $signedMessage->getHeader('Signature')[0]
        );
    }

    public function testv10SigningContext()
    {
        $keyStore = new KeyStore();
        $keyStore->addKeys($this->signingKeySpec);
        $v10Context = new Context([
            'headers' => ['(request-target)', 'date'],
            'algorithm' => 'rsa-sha256',
            'keyStore' => $keyStore
        ]);
        $signer = $v10Context->signer();
        $signedMessage = $signer->sign($this->message);

        $expectedSignatureLine = implode(',', [
            'keyId="rsa1"',
            'algorithm="rsa-sha256"',
            'headers="(request-target) date"',
            'signature="WGIegQCC3GEwxbkuXtq67CAqeDhkwblxAH2uoDx5kfWurhLRA5WB'.
            'FDA/aktsZAjuUoimG1w4CGxSecziER1ez44PBlHP2fCW4ArLgnQgcjkdN2cOf/g'.
            'j0OVL8s2usG4o4tud/+jjF3nxTxLl3HC+erBKsJakwXbw9kt4Cr028BToVfNXsW'.
            'oMFpv0IjcgBH2V41AVlX/mYBMMJAihBCIcpgAcGrrxmG2gkfvSn09wtTttkGHft'.
            'PIp3VpB53zbemlJS9Yw3tmmHr6cvWSXqQy/bTsEOoQJ2REfn5eiyzsJu3GiOpiI'.
            'LK67i/WH9moltJtlfV57TV72cgYtjWa6yqhtFg=="',
        ]);

        $this->assertEquals(
            $expectedSignatureLine,
            $signedMessage->getHeader('Signature')[0]
        );
    }

    public function testMismatchedAlgorithms()
    {
        $badContext = new Context([
          'headers' => ['(request-target)', 'date'],
          'algorithm' => 'dsa-sha256',
          'keys' => ['mismatched-key' => TestKeys::rsaPrivateKey],
        ]);
        $this->expectException(ContextException::class);
        $badContext->signer()->sign($this->message);
    }

    // public function testSha256Signer()
    // {
    //     $expectedDigestHeader = 'SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';
    //
    //     $signedMessage = $this->sha256context->signer()->sign($this->message);
    //     $expectedSha256String = implode(',', [
    //         'keyId="rsa1"',
    //         'algorithm="rsa-sha256"',
    //         'headers="(request-target) date"',
    //         'signature="WGIegQCC3GEwxbkuXtq67CAqeDhkwblxAH2uoDx5kfWurhLRA5WB'.
    //         'FDA/aktsZAjuUoimG1w4CGxSecziER1ez44PBlHP2fCW4ArLgnQgcjkdN2cOf/g'.
    //         'j0OVL8s2usG4o4tud/+jjF3nxTxLl3HC+erBKsJakwXbw9kt4Cr028BToVfNXsW'.
    //         'oMFpv0IjcgBH2V41AVlX/mYBMMJAihBCIcpgAcGrrxmG2gkfvSn09wtTttkGHft'.
    //         'PIp3VpB53zbemlJS9Yw3tmmHr6cvWSXqQy/bTsEOoQJ2REfn5eiyzsJu3GiOpiI'.
    //         'LK67i/WH9moltJtlfV57TV72cgYtjWa6yqhtFg=="',
    //     ]);
    //
    //     $this->assertEquals(
    //         $expectedSha256String,
    //         $signedMessage->getHeader('Signature')[0]
    //     );
    //
    //     $signedWithDigestMessage = $this->sha256context->signer()->signWithDigest($this->message);
    //
    //     $this->assertEquals(
    //         $expectedDigestHeader,
    //         $signedWithDigestMessage->getHeader('Digest')[0]
    //     );
    //
    //     $authorizedWithDigestMessage = $this->sha256context->signer()->authorizeWithDigest($this->message);
    //
    //     $this->assertEquals(
    //         $expectedDigestHeader,
    //         $authorizedWithDigestMessage->getHeader('Digest')[0]
    //     );
    // }
    //
    // public function testGetSigningString()
    // {
    //     $this->assertEquals(
    //       "(request-target): get /path?query=123\ndate: today",
    //       $this->sha256context->signer()->getSigningString($this->message)
    //     );
    // }
    //
    // public function testRsaBadalgorithm()
    // {
    //     $this->expectException(\HTTPSignatures\AlgorithmException::class);
    //     $sha224context = new Context([
    //           'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
    //           'algorithm' => 'rsa-sha224',
    //           'headers' => ['(request-target)', 'date'],
    //       ]);
    // }
    //
    // public function testEmptyHeaders()
    // {
    //     $emptyHeadersContext = new Context([
    //         'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
    //         'algorithm' => 'rsa-sha256',
    //         'headers' => [],
    //     ]);
    //
    //     $signedMessage = $emptyHeadersContext->signer()->sign($this->message);
    //     $this->assertEquals(
    //       'keyId="rsa1",algorithm="rsa-sha256",signature="Mutm6x0apXqU6aQh36l'.
    //       '+/yEU0kSzKt8tEy6nxhBXJIv0kP+z9MWH0k7CgsLLt4RcGmf5i6qnmPkkKZ5ndLUL'.
    //       'FnXpFIQjs2aWaQ4Twq29no/acrkJA1S9zFJEIy9uI+UJurzlpWe3pTBdyAvF0PnMC'.
    //       '4IQJ0f7QRyWjMCSmHGKEv7iZGmt9l1l1zbx7DHeuaLCj1AIZlwhvw0bg+uk7NrgFG'.
    //       '2Vix1w707O/u8K3IrHFDDpbNBI2YmqklyAuoPtVe+DFlaC/G80ew3VyNU9lqNAQxL'.
    //       'eD0/O05xNNdJ7xjaaAPdv0VXYwzC70aek1ZY1RKlSmDi6x5k/clmtcWsqNx1RJw=="',
    //       $signedMessage->getHeader('Signature')[0]
    //     );
    // }

    public function testBadHashAlgorithm()
    {
        $this->expectException(\HttpSignatures\AlgorithmException::class);
        $sha224context = new Context([
              'keys' => ['rsa1' => TestKeys::rsaPrivateKey],
              'algorithm' => 'rsa-sha224',
              'headers' => ['(request-target)', 'date'],
          ]);
    }

    public function testEmptyHeaders()
    {
        $defaultContext = $this->createContext($this->signingKeySpec);
        $defaultContext->setHeaders();
        $this->assertEquals(
          '(created): '.time(),
          $defaultContext->signer()->getSigningString($this->message)
        );
        $defaultContext->setHeaders([]);
        $defaultContext->setCreated(12345);
        $this->assertEquals(
          '',
          $defaultContext->signer()->getSigningString($this->message)
        );
    }

    /**
     * @param mixed[] $keys
     * @return Context
     * @throws ContextException
     * @throws \HttpSignatures\AlgorithmException
     * @throws \HttpSignatures\Exception
     * @throws \HttpSignatures\KeyStoreException
     */
    private function createContext(array $keys): Context {
        $keyStore = new KeyStore();
        $keyStore->addKeys($keys);
        return new Context(['keyStore' => $keyStore]);
    }

    public function testBasicHeaders()
    {
        $defaultContext = $this->createContext($this->signingKeySpec);
        $defaultContext->setHeaders(['date']);
        $this->assertEquals(
          'date: today',
          $defaultContext->signer()->getSigningString($this->message)
        );
    }

    // public function testRequiredHeaders()
    // {
    //     $defaultContext = new Context();
    //     $defaultContext->addKeys($this->signingKeySpec);
    //     $this->expectException(HeaderException::class);
    //     $defaultContext->setHeaders('accept');
    //     $signer = $defaultContext->signer();
    // }
    //
    public function testRejectCreatedInFuture()
    {
        $defaultContext = $this->createContext($this->signingKeySpec);
        $defaultContext->setCreated('+100');
        $this->expectException(SignatureDatesException::class);
        $signer = $defaultContext->signer();
    }

    public function testRejectExpiresInPast()
    {
        $defaultContext = $this->createContext($this->signingKeySpec);
        $defaultContext->setExpires('-300');
        $this->expectException(SignatureDatesException::class);
        $signer = $defaultContext->signer();
    }
}
