<?php

namespace Illuminate\Tests\Integration\Encryption;

use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Encryption\Cipher;
use RuntimeException;
use Orchestra\Testbench\TestCase;
use Illuminate\Encryption\Encrypter;
use Illuminate\Encryption\EncryptionServiceProvider;

class EncryptionTest extends TestCase
{

    public function test_encryption_provider_bind()
    {
        $this->setUpEncryptionWithAppKey();
        self::assertInstanceOf(Encrypter::class, $this->app->make('encrypter'));
        self::assertInstanceOf(Encrypter::class, $this->app->make(EncrypterContract::class));
    }

    public function test_encryption_will_not_be_instantiable_when_missing_app_key()
    {
        $this->setUpEncryptionWithAppKey();

        $this->expectException(RuntimeException::class);

        $this->app['config']->set('app.key', null);

        $this->app->make('encrypter');
    }

    public function test_encryption_will_work_with_key_rotation()
    {

    }


    private function setUpEncryptionWithAppKey()
    {
        $this->app['config']->set('app.key', 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=');
        $this->app->register(EncryptionServiceProvider::class);
    }

    private function encryptWith($keyId, $valueToEncrypt)
    {
        $keysFromConfig = [
            'key-1' => [
                'value'  => 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=',
                'cipher' => Cipher::AES_128_CBC,
            ],
            'key-2' => [
                'value'  => 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=',
                'cipher' => Cipher::AES_128_CBC,
            ],
            'key-3' => [
                'value'  => 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=',
                'cipher' => Cipher::AES_128_CBC,
            ],
        ];

        $this->app['config']->set('app.encryption.keyProvider', KeyRotationKeyStoreFactory::class);
        $this->app['config']->set('app.encryption.keys', $keysFromConfig);

        $expectedKeyStore = (new KeyStore())->setKeys(collect([
            'key-1' => $this->makeKeyStub('key-1', $keysFromConfig['key-1']['value'], $keysFromConfig['key-1']['cipher']),
            'key-2' => $this->makeKeyStub('key-2', $keysFromConfig['key-2']['value'], $keysFromConfig['key-2']['cipher']),
            'key-3' => $this->makeKeyStub('key-3', $keysFromConfig['key-3']['value'], $keysFromConfig['key-3']['cipher']),
        ]));
    }
}
