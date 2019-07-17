<?php


namespace Illuminate\Encryption\KeyStoreFactory;


use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Encryption\KeyStoreFactory;
use Illuminate\Encryption\Key;
use Illuminate\Encryption\KeyDecoder;
use Illuminate\Encryption\KeyStore;

class KeyRotationKeyStoreFactory implements KeyStoreFactory
{
    use KeyDecoder;

    private const PATH_TO_ENCRYPTION_KEY_CONFIG = 'app.encryption.keys';
    private const PATH_TO_APP_KEY = 'app.key';
    private const PATH_TO_APP_CIPHER = 'app.cipher';

    public function make(Repository $config): KeyStore
    {
        $keyFromConfig = $config->get(self::PATH_TO_ENCRYPTION_KEY_CONFIG);

        $keys = collect();

        foreach ($keyFromConfig as $key => $value) {
            $keys->push(new Key($key, $this->decode($value['value']), $value['cipher']));
        }

        if ($config->get(self::PATH_TO_APP_KEY)) {
            $keys->push(new Key('app-key', $this->decode($config->get(self::PATH_TO_APP_KEY)), $config->get(self::PATH_TO_APP_CIPHER)));
        }

        return (new KeyStore())->setKeys($keys);
    }
}