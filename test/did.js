import assert from "assert";
import DIDDocument from '../src/DidDocument';

describe('DID', async function() {
    describe('Document', async function() {
        let doc;

        this.beforeAll(async function() {
            let publicKeys = {
                asym: "a651b53d6688935c00d5b1035087eae1f44afcaafbd9805b023c392fa3dd3808",
                sign: "f7e03208c6f4de184a8db90d24fb8c3171dc417499ae453da4e4108edf9d717b",
                auth: "84faffe8e5fb67e084e6032ee7313c2645119bffbc61d57525d2c92f02afa14f"
            }

            doc = new DIDDocument({
                did: did
            });

            doc.addPublicKey({
                id: `${did}#asymKey`,
                type: 'Curve25519EncryptionPublicKey',
                publicKeyHex: publicKeys.asym
            });

            doc.addPublicKey({
                id: `${did}#sign`,
                type: 'Secp256k1VerificationKey2018',
                publicKeyHex: publicKeys.sign
            });

            doc.addAuthentication({
                publicKey: `${did}#sign`,
                type: 'Secp256k1SignatureAuthentication2018'
            });

            doc.addService({
                id: `${did}#Verida-Wallet`,
                type: 'verida.App',
                serviceEndpoint: 'https://wallet.verida.io',
                description: 'Verida Wallet'
            });

            doc.addService({
                id: `${did}#Verida-Demo-Application`,
                type: 'verida.App',
                serviceEndpoint: 'https://demoapp.verida.io',
                description: 'Verida Demo Application'
            });

        });

        var did = 'did:veri:0x2e922f72f4f1a27701dde0627dfd693376ab0d02';
        
        it('should create DID with public key and save to server', async function() {
            let result = await doc.commit(doc);
            assert(result,true);
        });

        it('should load a DID document from server', async function() {
            let doc = new DIDDocument({
                did: did
            });

            let serverDoc = await doc.load();

            if (!serverDoc) {
                assert(true,false);
            }

            assert(serverDoc.id == did, true);
        });

        it('should create a valid JWT proof', async function() {
            let privateSignKey = "a8fcc1e509786771d02d36103c3c4ce8e4fe741d2a095a395d7e08b2ae15cbb4f7e03208c6f4de184a8db90d24fb8c3171dc417499ae453da4e4108edf9d717b";
            doc.createProof(privateSignKey);
            assert(doc.verifyProof(), true);
        })
    })
});