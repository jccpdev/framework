<?php

namespace Illuminate\Tests\Encryption;

use Illuminate\Encryption\Cipher;
use Illuminate\Encryption\Key;
use Illuminate\Encryption\KeyStore;
use Ramsey\Uuid\Uuid;
use RuntimeException;
use PHPUnit\Framework\TestCase;
use Illuminate\Encryption\Encrypter;
use Illuminate\Contracts\Encryption\DecryptException;

class EncrypterTest extends TestCase
{

    private const ALTERNATIVE_CIPHER = 'AES-256-CFB8';

    public function testEncryption()
    {
        //Given
        $e = new Encrypter($this->makeKeyStore(Uuid::uuid4()->toString(), str_repeat('a', 16)));

        //When
        $encrypted = $e->encrypt('foo');

        //Then
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        //Given
        $e = new Encrypter($this->makeKeyStore(Uuid::uuid4()->toString(), str_repeat('a', 16)));

        //When
        $encrypted = $e->encryptString('foo');

        //Then
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testEncryptionUsingBase64EncodedKey()
    {
        //Given
        $e = new Encrypter($this->makeKeyStore(Uuid::uuid4()->toString(), random_bytes(16)));

        //When
        $encrypted = $e->encrypt('foo');

        //Then
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithCustomCipher()
    {
        //Given
        $e = new Encrypter($this->makeKeyStore(
            Uuid::uuid4()->toString(),
            str_repeat('b', 32),
            Cipher::AES_256_CBC)
        );

        //When
        $encrypted = $e->encrypt('bar');

        //Then
        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));

        //When
        $encrypted = $e->encrypt('foo');

        //Then
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testDoNoAllowLongerKey()
    {
        //Expected
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');

        //Given
        $keyStore = $this->makeKeyStore(
            Uuid::uuid4()->toString(),
            str_repeat('z', 32)
        );

        //When
        new Encrypter($keyStore);

    }

    public function testWithBadKeyLength()
    {
        //Expected
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');

        //Given
        $keyStore = $this->makeKeyStore(
            Uuid::uuid4()->toString(),
            str_repeat('z', 5)
        );

        //When
        new Encrypter($keyStore);
    }

    public function testWithBadKeyLengthAlternativeCipher()
    {

        //Expected
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');

        //Given
        $keyStore = $this->makeKeyStore(
            Uuid::uuid4()->toString(),
            str_repeat('a', 16),
            self::ALTERNATIVE_CIPHER
        );

        //When
        new Encrypter($keyStore);
    }

    public function testWithUnsupportedCipher()
    {
        //Expected
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');

        //Given
        $keyStore = $this->makeKeyStore(
            Uuid::uuid4()->toString(),
            str_repeat('c', 16),
            self::ALTERNATIVE_CIPHER
        );

        //When
        new Encrypter($keyStore);
    }

    public function testExceptionThrownWhenPayloadIsInvalid()
    {
        //Expected
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('The payload is invalid.');

        //Given
        $keyStore = $this->makeKeyStore(
            Uuid::uuid4()->toString(),
            str_repeat('a', 16)
        );

        $e = new Encrypter($keyStore);

        //Then
        $payload = $e->encrypt('foo');
        $payload = str_shuffle($payload);
        $e->decrypt($payload);
    }

    public function testExceptionThrownWithDifferentKey()
    {
        //Expected
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('The MAC is invalid.');

        $a = new Encrypter($this->makeKeyStore(Uuid::uuid4()->toString(), str_repeat('a', 16)));
        $b = new Encrypter($this->makeKeyStore(Uuid::uuid4()->toString(), str_repeat('b', 16)));
        $b->decrypt($a->encrypt('baz'));
    }

    public function testExceptionThrownWhenIvIsTooLong()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('The payload is invalid.');

        $e = new Encrypter($this->makeKeyStore(Uuid::uuid4()->toString(), str_repeat('a', 16)));
        $payload = $e->encrypt('foo');
        $data = json_decode(base64_decode($payload), true);
        $data['iv'] .= $data['value'][0];
        $data['value'] = substr($data['value'], 1);
        $modified_payload = base64_encode(json_encode($data));
        $e->decrypt($modified_payload);
    }

    /**
     * @param $id
     * @param $value
     * @param string $cipher
     * @return KeyStore
     */
    private function makeKeyStore($id, $value, $cipher = Cipher::AES_128_CBC): KeyStore
    {
        //Given
        $keyStore = new KeyStore();
        $keyStore->setKey(
            new Key(
                $id,
                $value,
                $cipher
            ));

        return $keyStore;
    }
}
