<?php


namespace Illuminate\Encryption;


use Illuminate\Support\Collection;

class KeyStore
{
    /** @var Collection */
    private $keys;

    public function __construct()
    {
        $this->keys = new Collection();
    }

    /**
     * @param Key $key
     * @return KeyStore
     */
    public function setKey(Key $key): self
    {
        $this->keys->push($key);
        return $this;
    }

    /**
     * @param iterable $keys
     * @return KeyStore
     */
    public function setKeys(iterable $keys): self
    {
        foreach ($keys as $key) {

            if (!$key instanceof Key) {
                throw new \TypeError('All objects must be of type Illuminate\Encryption\Key');
            }

            $this->keys->push($key);
        }

        return $this;
    }

    /**
     * @return Collection
     */
    public function getAll(): Collection
    {
        return $this->keys;
    }

    /**
     * @param $id
     * @return mixed
     */
    public function getByKeyId($id)
    {
        return $this->keys->first(function (Key $key) use ($id) {
            return $key->getId() === $id;
        });
    }

    /**
     * @return int
     */
    public function count(): int
    {
        return $this->keys->count();
    }

}