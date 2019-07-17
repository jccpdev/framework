<?php


namespace Illuminate\Tests\Encryption;


use Illuminate\Encryption\Cipher;
use Illuminate\Encryption\Key;
use Illuminate\Encryption\KeyDecoder;
use Illuminate\Encryption\KeyStore;
use Illuminate\Encryption\KeyStoreFactory\AppKeyKeyStoreFactory;
use Orchestra\Testbench\TestCase;

class AppKeyKeyStoreFactoryTest extends TestCase
{
    use KeyDecoder;

    /** @var AppKeyKeyStoreFactory */
    public $sut;

    public function setUp(): void
    {
        parent::setUp();

        $this->sut = new AppKeyKeyStoreFactory();
    }

    public function testItCanMakeAKeyStoreWithBase64EncodedAppKey(): void
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

    public function testItCanMakeAKeyStoreWithRawAppKey(): void
    {
        //Given
        $encodedKey = 'base64:IUHRqAQ99pZ0A1MPjbuv1D6ff3jxv0GIvS2qIW4JNU4=';
        $cipher = Cipher::AES_128_CBC;
        $rawKey = $this->decode($encodedKey);
        $this->app['config']->set('app.key', $rawKey);
        $this->app['config']->set('app.cipher', $cipher);

        $expectedKeyStore = (new KeyStore())
            ->setKey(new Key('app-key', $rawKey, $cipher));

        //When
        $actualKeyStore = $this->sut->make($this->app['config']);

        //Then
        $this->assertEquals($expectedKeyStore, $actualKeyStore);
    }

    public function testItWillThrowRuntimeExceptionIfNoApplicationEncryptionKeyIsSpecified()
    {
        //Expected
        $this->expectException(\RuntimeException::class);

        //When
        $this->sut->make($this->app['config']);

    }

}