<?php


namespace Illuminate\Encryption;


use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Encryption\KeyStoreFactory as KeyStoreFactoryContract;
use Illuminate\Encryption\KeyStoreFactory\AppKeyKeyStoreFactory;

class KeyStoreFactory implements KeyStoreFactoryContract
{
    private const PATH_TO_KEY_PROVIDER = 'app.encryption.keyProvider';

    public function make(Repository $config): KeyStore
    {
        if ($config->get(self::PATH_TO_KEY_PROVIDER)) {
            return $this->makeKeyStoreFromKeyProvider($config->get(self::PATH_TO_KEY_PROVIDER))
                ->make($config);
        }
        return $this->makeAppKeyKeyStoreFactory()->make($config);
    }

    private function makeAppKeyKeyStoreFactory(): AppKeyKeyStoreFactory
    {
        return new AppKeyKeyStoreFactory();
    }

    private function makeKeyStoreFromKeyProvider($keyProvider): KeyStoreFactoryContract
    {
        return app($keyProvider);
    }
}