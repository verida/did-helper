import assert from "assert";
import { DIDDocument } from 'did-document';
import DIDHelper from '../src/DIDHelper';
import WalletUtils from "@verida/wallet-utils";

describe('DID', async function() {
    describe('Document', async function() {
        let doc;
        let HOST = 'http://localhost:5001/';
        const CHAIN = 'vechain'
        const account = WalletUtils.createAccount(CHAIN)
        const privateKey = account.privateKey
        let privateSignKey = "0xa8fcc1e509786771d02d36103c3c4ce8e4fe741d2a095a395d7e08b2ae15cbb4f7e03208c6f4de184a8db90d24fb8c3171dc417499ae453da4e4108edf9d717b";

        var did = account.did.toLowerCase();
        var vid = 'did:vid:0x2e922f72f4f1a27701dde0627dfd693376ab0d02';

        this.beforeAll(async function() {
            let publicKeys = {
                asym: "0xa651b53d6688935c00d5b1035087eae1f44afcaafbd9805b023c392fa3dd3808",
                sign: "0xf7e03208c6f4de184a8db90d24fb8c3171dc417499ae453da4e4108edf9d717b",
                auth: "0x84faffe8e5fb67e084e6032ee7313c2645119bffbc61d57525d2c92f02afa14f"
            }

            doc = new DIDDocument({
                did: vid
            });

            doc.addPublicKey({
                id: `${vid}#asymKey`,
                type: 'Curve25519EncryptionPublicKey',
                publicKeyHex: publicKeys.asym
            });

            doc.addPublicKey({
                id: `${vid}#sign`,
                type: 'Secp256k1VerificationKey2018',
                publicKeyHex: publicKeys.sign
            });

            doc.addAuthentication({
                publicKey: `${vid}#sign`,
                type: 'Secp256k1SignatureAuthentication2018'
            });

            doc.addService({
                id: `${vid}#application`,
                type: 'verida.App',
                serviceEndpoint: 'https://wallet.verida.io',
                description: 'Verida Wallet'
            });

            doc.addService({
                id: `${vid}#Verida-Demo-Application`,
                type: 'verida.Application',
                serviceEndpoint: 'https://demoapp.verida.io',
                description: 'Verida Demo Application'
            });

        });

        it('should have a verified proof', function() {
            DIDHelper.createProof(doc, privateSignKey);
            let result = DIDHelper.verifyProof(doc);
            assert(result, true);
        });
        
        it('should create DID with public key and save to server', async function() {
            doc = DIDHelper.createProof(doc, privateSignKey);
            const message = "Do you approve access to view and update \"Verida Demo Application\"?\n\n" + did;
            const sig = await WalletUtils.signMessage(CHAIN, privateKey, message)
            let result = await DIDHelper.commit(did, doc, sig, HOST);
            assert(result,true);
        });

        it('should load a VID document from server', async function() {
            let serverDoc = await DIDHelper.load(vid, HOST);

            if (!serverDoc) {
                assert.fail("Unable to load DID from server");
            } else {
                assert(serverDoc.id == vid, true);
            }
        });

        it('should support looking up a VID Document by DID', async function() {
            let doc = await DIDHelper.loadForApp(did, "Verida Demo Application", HOST);
            
            // Current issue:
            //  - VID not saved in verida_did_app_lookup
            //  - VID proof doesn't include the DID that owns it (did:ethr:0x....)

            assert(doc);
        })
    })
});