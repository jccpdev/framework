<?php


namespace Illuminate\Tests\Encryption\KeyStoreFactory;


use Illuminate\Encryption\Cipher;
use Illuminate\Encryption\Key;
use Illuminate\Encryption\KeyDecoder;
use Illuminate\Encryption\KeyStore;
use Illuminate\Encryption\KeyStoreFactory\KeyRotationKeyStoreFactory;
use Orchestra\Testbench\TestCase;

class KeyRotationKeyStoreFactoryTest extends TestCase
{
    use KeyDecoder;

    /** @var KeyRotationKeyStoreFactory */
    public $sut;

    public function setUp(): void
    {
        parent::setUp();

        $this->sut = new KeyRotationKeyStoreFactory();
    }

    public function testItWillMakeAKeyStoreFromAppEncryptionConfig()
    {
        //Given
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

        $this->app['config']->set('app.encryption.keys', $keysFromConfig);

        $encodedKey = 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=';
        $cipher = Cipher::AES_128_CBC;
        $this->app['config']->set('app.key', $encodedKey);
        $this->app['config']->set('app.cipher', $cipher);

        $expectedKeyStore = (new KeyStore())->setKeys(collect([
            'key-1'   => $this->makeKeyStub('key-1', $keysFromConfig['key-1']['value'], $keysFromConfig['key-1']['cipher']),
            'key-2'   => $this->makeKeyStub('key-2', $keysFromConfig['key-2']['value'], $keysFromConfig['key-2']['cipher']),
            'key-3'   => $this->makeKeyStub('key-3', $keysFromConfig['key-3']['value'], $keysFromConfig['key-3']['cipher']),
            'app-key' => $this->makeKeyStub('app-key', $encodedKey, $cipher),
        ]));

        //When
        $actualKeyStore = $this->sut->make($this->app['config']);

        //Then
        $this->assertEquals($expectedKeyStore, $actualKeyStore);


    }

    private function makeKeyStub($id, $value, $cipher): Key
    {
        return new Key($id, $this->decode($value), $cipher);
    }
}