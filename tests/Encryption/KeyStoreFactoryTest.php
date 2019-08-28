<?php


namespace Illuminate\Tests\Encryption\KeyStoreFactory;


use Illuminate\Encryption\Cipher;
use Illuminate\Encryption\Key;
use Illuminate\Encryption\KeyDecoder;
use Illuminate\Encryption\KeyStore;
use Illuminate\Encryption\KeyStoreFactory;
use Illuminate\Encryption\KeyStoreFactory\KeyRotationKeyStoreFactory;
use Orchestra\Testbench\TestCase;

class KeyStoreFactoryTest extends TestCase
{

    use KeyDecoder;

    /** @var KeyStoreFactory */
    private $sut;

    public function setUp(): void
    {
        parent::setUp();
        $this->sut = new KeyStoreFactory();
    }

    public function testFactoryWillMakeKeyStoreWithAppKeyByDefault()
    {
        //Given
        $encodedKey = 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=';
        $cipher = Cipher::AES_128_CBC;
        $this->app['config']->set('app.key', $encodedKey);
        $this->app['config']->set('app.cipher', $cipher);
        $rawKey = $this->decode($encodedKey);
        $expectedKeyStore = (new KeyStore())
            ->setKey(new Key('app-key', $rawKey, $cipher));

        //When
        $actualKeyStore = $this->sut->make($this->app['config']);

        //Then
        $this->assertEquals($expectedKeyStore, $actualKeyStore);
    }

    public function testFactoryWillMakeKeyStoreWithAppKeyByDefaultAndUnEncodedKey()
    {
        //Given
        $unencodedKey = 'b"!AÐ¿\x04=÷ût\x03S\x0Fì╗»È>ƒ\x7Fx±┐Aê¢-¬!n\t5N"';
        $cipher = Cipher::AES_128_CBC;
        $this->app['config']->set('app.key', $unencodedKey);
        $this->app['config']->set('app.cipher', $cipher);

        $expectedKeyStore = (new KeyStore())
            ->setKey(new Key('app-key', $unencodedKey, $cipher));

        //When
        $actualKeyStore = $this->sut->make($this->app['config']);

        //Then
        $this->assertEquals($expectedKeyStore, $actualKeyStore);
    }

    public function testFactoryWillMakeKeyRotationKeyStoreIfSpecifiedInConfig()
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

        $this->app['config']->set('app.encryption.keyProvider', KeyRotationKeyStoreFactory::class);
        $this->app['config']->set('app.encryption.keys', $keysFromConfig);

        $expectedKeyStore = (new KeyStore())->setKeys(collect([
            'key-1' => $this->makeKeyStub('key-1', $keysFromConfig['key-1']['value'], $keysFromConfig['key-1']['cipher']),
            'key-2' => $this->makeKeyStub('key-2', $keysFromConfig['key-2']['value'], $keysFromConfig['key-2']['cipher']),
            'key-3' => $this->makeKeyStub('key-3', $keysFromConfig['key-3']['value'], $keysFromConfig['key-3']['cipher']),
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
