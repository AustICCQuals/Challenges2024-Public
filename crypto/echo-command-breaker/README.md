# Echo Command Breaker

- **Category:** crypto
- **Difficulty:** easy
- **Author:** joseph
- **Description:** _Let's warm up with a simple [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB) puzzle. Minimal cryptography knowledge required!_
- **Files:**
    - `publish/server.py` (sha256: 6fa432f6a361f5c785b514a2805e3eaf590246143d783fbff7da3465d4815d5b)
- **Flag:** `oiccflag{ecb_could_also_stand_for_easy_crypto_brainteaser_:)}`

# Notes

Must be deployed as a remote service

```
docker build -t oicc-2024/echo-command-breaker src/
docker run --privileged -p 1337:1337 -t oicc-2024/echo-command-breaker
```
