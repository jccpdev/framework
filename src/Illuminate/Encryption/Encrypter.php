<?php

namespace Illuminate\Encryption;

use RuntimeException;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;

class Encrypter implements EncrypterContract
{
    /** @var Key */
    private $key;

    /** @var KeyStore */
    private $keyStore;

    /**
     * Create a new encrypter instance.
     *
     * @param KeyStore $keyStore
     * @param string|null $keyId
     */
    public function __construct(KeyStore $keyStore, string $keyId = null)
    {

        $this->keyStore = $keyStore;

        if ($keyStore->isEmpty()) {
            throw new RuntimeException('Keystore must contain at least one key.');
        }

        if ($keyId === null) {

            if ($keyStore->count() > 1) {
                throw new RuntimeException('KeyStore may only contain one key if no key id is provided');
            }

            $this->key = $keyStore->getAll()->first();
        } else {
            $this->key = $keyStore->getByKeyId($keyId);
        }

        $keyStore->getAll()->each(function (Key $key) {
            if (!static::supported($key->getValue(), $key->getCipher())) {
                throw new RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');
            }
        });


    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param string $key
     * @param string $cipher
     * @return bool
     */
    public static function supported($key, $cipher)
    {
        $length = mb_strlen($key, '8bit');

        return ($cipher === Cipher::AES_128_CBC && $length === 16) ||
            ($cipher === Cipher::AES_256_CBC && $length === 32);
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @param string $cipher
     * @return string
     * @throws \Exception
     */
    public static function generateKey($cipher)
    {
        return random_bytes($cipher === Cipher::AES_128_CBC ? 16 : 32);
    }

    /**
     * Encrypt the given value.
     *
     * @param mixed $value
     * @param bool $serialize
     * @return string
     *
     * @throws EncryptException
     * @throws \Exception
     */
    public function encrypt($value, $serialize = true)
    {
        $iv = random_bytes(openssl_cipher_iv_length($this->key->getCipher()));

        // First we will encrypt the value using OpenSSL. After this is encrypted we
        // will proceed to calculating a MAC for the encrypted value so that this
        // value can be verified later as not having been changed by the users.
        $value = \openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->key->getCipher(), $this->key->getValue(), 0, $iv
        );

        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        // Once we get the encrypted value we'll go ahead and base64_encode the input
        // vector and create the MAC for the encrypted value so we can then verify
        // its authenticity. Then, we'll JSON the data into the "payload" array.
        $mac = $this->hash($iv = base64_encode($iv), $value, $this->key);

        $payload = new EncryptionPayload($iv, $value, $mac, $this->key->getId());

        $json = json_encode($payload);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param string $value
     * @return string
     *
     * @throws EncryptException
     * @throws \Exception
     */
    public function encryptString($value)
    {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypt the given value.
     *
     * @param string $payload
     * @param bool $unserialize
     * @return mixed
     *
     * @throws DecryptException
     * @throws \Exception
     */
    public function decrypt($payload, $unserialize = true)
    {
        $payload = $this->getJsonPayload($payload);

        $key = $this->determineKey($payload);

        $iv = base64_decode($payload->getIv());

        // Here we will decrypt the value. If we are able to successfully decrypt it
        // we will then unserialize it and return it out to the caller. If we are
        // unable to decrypt this value we will throw out an exception message.
        $decrypted = \openssl_decrypt(
            $payload->getValue(), $key->getCipher(), $key->getValue(), 0, $iv
        );

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param string $payload
     * @return string
     *
     * @throws DecryptException
     * @throws \Exception
     */
    public function decryptString($payload)
    {
        return $this->decrypt($payload, false);
    }

    /**
     * Create a MAC for the given value.
     *
     * @param string $iv
     * @param mixed $value
     * @param $key
     * @return string
     */
    protected function hash($iv, $value, Key $key = null)
    {
        $key = $key ?? $this->key;
        return hash_hmac('sha256', $iv . $value, $key->getValue());
    }

    /**
     * Get the JSON array from the given payload.
     *
     * @param string $payload
     * @return array
     *
     * @throws DecryptException
     * @throws \Exception
     */
    protected function getJsonPayload($payload): EncryptionPayload
    {
        $rawPayload = json_decode(base64_decode($payload), true);

        $payload = new EncryptionPayload(
            $rawPayload['iv'],
            $rawPayload['value'],
            $rawPayload['mac'],
            $rawPayload['keyId']
        );

        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if (!$this->validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        if (!$this->validMac($payload)) {
            throw new DecryptException('The MAC is invalid.');
        }

        return $payload;
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param mixed $payload
     * @return bool
     */
    protected function validPayload(EncryptionPayload $payload)
    {
        return
            is_object($payload)
            && !empty($payload->getIv())
            && !empty($payload->getValue())
            && !empty($payload->getMac())
            && strlen(base64_decode($payload->getIv(), true)) === openssl_cipher_iv_length($this->key->getCipher());
    }

    /**
     * Determine if the MAC for the given payload is valid.
     *
     * @param EncryptionPayload $payload
     * @return bool
     * @throws \Exception
     */
    protected function validMac(EncryptionPayload $payload)
    {
        $calculated = $this->calculateMac($payload, $bytes = random_bytes(16));

        return hash_equals(
            hash_hmac('sha256', $payload->getMac(), $bytes, true), $calculated
        );
    }

    /**
     * Calculate the hash of the given payload.
     *
     * @param EncryptionPayload $payload
     * @param string $bytes
     * @return string
     */
    protected function calculateMac(EncryptionPayload $payload, $bytes)
    {
        $key = $this->determineKey($payload);

        return hash_hmac(
            'sha256', $this->hash($payload->getIv(), $payload->getValue(), $key), $bytes, true
        );
    }

    private function determineKey(EncryptionPayload $payload): ?Key
    {
        return $this->keyStore->getByKeyId($payload->getKeyId());
    }
}
