<?php

namespace Illuminate\Tests\Integration\Encryption;

use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Encryption\Cipher;
use Illuminate\Encryption\KeyStoreFactory\KeyRotationKeyStoreFactory;
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

    public function test_encryption_will_work_with_the_KeyRotationKeyStoreFactory()
    {
        //Given
        $keyIdUsedToEncrypt = $this->setUpRotationKeyEncryption();

        //When
        $this->app->register(EncryptionServiceProvider::class);
        /** @var EncrypterContract $encrypter */
        $encrypter = $this->app->make(EncrypterContract::class);
        $encryptedValue = $encrypter->encrypt('test');
        $encryptedPayload = json_decode(base64_decode($encryptedValue));

        //Then
        $this->assertEquals($keyIdUsedToEncrypt, $encryptedPayload->keyId);

    }

    private function setUpEncryptionWithAppKey()
    {
        $this->app['config']->set('app.key', 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=');
        $this->app->register(EncryptionServiceProvider::class);
    }

    private function setUpRotationKeyEncryption()
    {

        $keysFromConfig = [
            'key-1' => [
                'value'  => sprintf('base64:%s',base64_encode(Encrypter::generateKey(Cipher::AES_128_CBC))),
                'cipher' => Cipher::AES_128_CBC,
            ],
            'key-2' => [
                'value'  => sprintf('base64:%s',base64_encode(Encrypter::generateKey(Cipher::AES_256_CBC))),
                'cipher' => Cipher::AES_256_CBC,
            ],
            'key-3' => [
                'value'  => sprintf('base64:%s',base64_encode(Encrypter::generateKey(Cipher::AES_128_CBC))),
                'cipher' => Cipher::AES_128_CBC,
            ],
        ];

        $this->app['config']->set('app.encryption.keyProvider', KeyRotationKeyStoreFactory::class);
        $this->app['config']->set('app.encryption.keys', $keysFromConfig);
        $this->app['config']->set('app.encryption.currentKey', 'key-2');

        return 'key-2';

    }
}
