
2021-06-23 v0.7.2
-----------------------

- Remove unecessary `did-jwt` dependency to resolve issues in `@verida/datastore`

2021-03-18 v0.7.1
-----------------------

- Update to latest `@verida/wallet-utils` with NEAR fixes

2021-03-17 v0.7.0
-----------------------

- Update to latest `@verida/wallet-utils` for NEAR support

2020-11-04 v0.6.1
-----------------------

- Handle `doc.proof` being an object or function depending on environment (to support react-native)

2020-11-03 v0.6.0
-----------------------

- Update DID helper to latest so it builds correctly when installed with `npm`

2020-09-13 - v0.5.2
-----------------------

- Fix issues with `verifyProof` not fetching the proof correctly

2020-07-24 - v0.5.1
-----------------------

- Fix issues with `doc.proof` when in react-native environment

2020-07-12 - v0.5
-----------------------

- Upgrade to ethers 5
- Support @verida/wallet-utils to support additional blockchains
- Add full unit test coverage

2020-06-29 - v0.4.4
-----------------------

- Add verifySignedMessage() method
- Add getDidFromVid() method
- Add support for usernames
- Ensure committing a DID provides a valid signature
