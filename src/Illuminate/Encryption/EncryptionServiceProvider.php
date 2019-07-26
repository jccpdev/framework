<?php

namespace Illuminate\Encryption;

use RuntimeException;
use Illuminate\Support\Str;
use Illuminate\Support\ServiceProvider;

class EncryptionServiceProvider extends ServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('encrypter', function ($app) {
            $config = $app->make('config');

            $currentKey = $config->get('app.encryption.currentKey');

            $keyStoreFactory = new KeyStoreFactory();

            $keyStore = $keyStoreFactory->make($config);

            return new Encrypter($keyStore, $currentKey);
        });
    }

}
