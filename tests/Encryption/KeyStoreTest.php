<?php


namespace Illuminate\Tests\Encryption;


use Illuminate\Encryption\Cipher;
use Illuminate\Encryption\Key;
use Illuminate\Encryption\KeyStore;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;

class KeyStoreTest extends TestCase
{

    /** @var KeyStore */
    private $sut;

    public function setUp(): void
    {
        parent::setUp();

        $this->sut = new KeyStore();
    }

    public function testSetKeyInStoreAndGetAllKeys()
    {
        //Given
        $keyId = Uuid::uuid4()->toString();
        $newKey = new Key($keyId, 'some-random-key', Cipher::AES_256_CBC);

        //When
        $sut = $this->sut->setKey($newKey);
        $retrievedKeys = $this->sut->getAll();

        //Then
        $this->assertEquals($this->sut, $sut);
        $this->assertNotEmpty($retrievedKeys->first(function (Key $key) use ($keyId) {
            return $key->getId() === $keyId;
        }));
    }

    public function testSetKeys()
    {
        //Given
        $keyCollection = collect([
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
        ]);

        //When
        $this->sut->setKeys($keyCollection);

        //Then
        $keysStored = $this->sut->getAll();
        $this->assertEquals($keyCollection, $keysStored);

    }

    public function testSetKeysWillOnlyAcceptKeyObjects()
    {
        //Given
        $keyCollection = collect([
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new class
            {

            },
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
        ]);

        //Then
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('All objects must be of type Illuminate\Encryption\Key');

        //When
        $sut = $this->sut->setKeys($keyCollection);

        $this->assertEquals($this->sut, $sut);


    }

    public function testGetByKeyIdWillReturnTheKeyForId()
    {
        //Given
        $expectedKey = new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC);

        $keyCollection = collect([
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            $expectedKey,
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
        ]);

        $this->sut->setKeys($keyCollection);

        //When
        $actualKey = $this->sut->getByKeyId($expectedKey->getId());

        //Then
        $this->assertEquals($expectedKey, $actualKey);
    }

    public function testCountOfKeys()
    {
        //Given
        $keyCollection = collect([
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
            new Key(Uuid::uuid4()->toString(), 'some-random-key', Cipher::AES_256_CBC),
        ]);

        $expectedCount = $keyCollection->count();

        $this->sut->setKeys($keyCollection);

        //When
        $actualCount = $this->sut->count();

        //Then
        $this->assertEquals($expectedCount, $actualCount);
    }

}