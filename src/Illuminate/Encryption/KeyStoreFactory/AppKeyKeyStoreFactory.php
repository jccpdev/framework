<?php


namespace Illuminate\Encryption\KeyStoreFactory;


use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Encryption\KeyStoreFactory;
use Illuminate\Encryption\Key;
use Illuminate\Encryption\KeyDecoder;
use Illuminate\Encryption\KeyStore;
use RuntimeException;

class AppKeyKeyStoreFactory implements KeyStoreFactory
{

    use KeyDecoder;

    public function make(Repository $config): KeyStore
    {
        $appKey = $config->get('app.key');
        $cipher = $config->get('app.cipher');

        if (empty($appKey)) {
            throw new RuntimeException(
                'No application encryption key has been specified.'
            );
        }

        // If the key starts with "base64:", we will need to decode the key before handing
        // it off to the encrypter. Keys may be base-64 encoded for presentation and we
        // want to make sure to convert them back to the raw bytes before encrypting.
        $decodedKey = $this->decode($appKey);

        return (new KeyStore())
            ->setKey(new Key('app-key', $decodedKey, $cipher));

    }
}
