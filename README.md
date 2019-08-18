# HTTP Signatures

[![Build Status](https://travis-ci.org/liamdennehy/http-signatures-php.svg?branch=master)](https://travis-ci.org/liamdennehy/http-signatures-php)
[![Documentation Status](https://readthedocs.org/projects/http-signatures-php/badge/?version=latest)](https://http-signatures-php.readthedocs.io/en/latest/?badge=latest)

PHP implementation of [Singing HTTP Messages][draft10] draft specification;
allowing cryptographic signing and verifying of HTTP messages using PHP
[PSR-7][psr7] interfaces.

## Features

- Full compliance with [Signing HTTP Message draft IETF RFC version 10][draft10]
- Sign & verify messages using HMACs
- Sign & verify messages with RSA, Elliptic Curve and DSA private/public keys
- Add a ``Digest`` header, or automatically add the header while signing in a single operation
- Verify a ``Digest`` header while verifying the signature
- Compatible with common PSR-7 libraries

Complete documentation for this library can be found at 
[Read The Docs](https://http-signatures-php.readthedocs.io/en/latest/)

## Simple Usage

Add [liamdennehy/http-signatures-php][package] to your [``composer.json``][composer].

* A message is assumed to be a PSR-7 compatible Request or Response.
* A ``Context`` object is used to configure the signature parameters, and prepare
  the verifier functionality.
* The ``signWithDigest`` function witll add a ``Digest`` header and digitally
  sign the message in a new ``Signature`` header.

Using an PSR-7 request ``$message`` ready to send (assuming it has a ``Date``
header):

```php
  $signingContext = new \HttpSignatures\Context([
    'keys' => ['myKeyId' => file_get_contents('/path/to/secret-key')],
    'algorithm' => 'hmac-sha256',
    'headers' => ['(request-target)', 'Date'],
  ]);

  $signingContext->signer()->signWithDigest($message);
```

## Contributing

Pull Requests are welcome, as are 
[issue reports][github-issues] if you encounter any problems.

**Note**: Due to composer dependencies for the reference implementation
``composer install`` prior to local development is only posible on PHP 7.1,
or by manually removing the incompatible dependencies using the command 
(wrapped for readability):

```sh
  composer remove --dev \
  nyholm/psr7 nyholm/psr7-server riswallsmith/buzz \
  endframework/zend-httphandlerrunner
```
[draft10]: http://tools.ietf.org/html/draft-cavage-http-signatures-10
[Symfony\Component\HttpFoundation\Request]: https://github.com/symfony/HttpFoundation/blob/master/Request.php
[composer]: https://getcomposer.org/
[package]: https://packagist.org/packages/liamdennehy/http-signatures-php
[github-issues]: https://github.com/liamdennehy/http-signatures-php/issues
[psr7]: http://www.php-fig.org/psr/psr-7/

## License

HTTP Signatures PHP library is licensed under
[The MIT License (MIT)](https://opensource.org/licenses/MIT).

Documentation of the library is licensed under
[Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/)

Details are in the [LICENSE file](./LICENSE.md)
