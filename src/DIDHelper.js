import { DIDDocument } from 'did-document';
import { sign } from "tweetnacl";
import {
  decodeUTF8,
  encodeBase64,
  decodeBase64
} from "tweetnacl-util";
import utils from '@verida/wallet-utils';
import Axios from 'axios';

class DIDHelper {

    /**
     * Load a VID Document from the server by VID
     */
    async load(vid, host) {
        try {
            let response = await Axios.get(host + 'load?vid=' + vid);
            let document = response.data.data.document;
            let doc = new DIDDocument(document, document['@context']);

            return doc;
        } catch (err) {
            return null;
        }
    }

    /**
     * Load a VID Document from the server by DID and app name
     */
    async loadForApp(did, appName, host) {
        try {
            let response = await Axios.get(host + 'loadForApp?did=' + did + '&appName=' + appName);
            let document = response.data.data.document;
            let doc = new DIDDocument(document, document['@context']);

            return doc;
        } catch (err) {
            return null;
        }
    }

    /**
     * Load the DID linked to a VID
     */
    async getDidFromVid(vid, host) {
        try {
            let response = await Axios.get(host + 'getDidFromVid?vid=' + vid);
            let did = response.data.data.did;
            return did;
        } catch (err) {
            return null;
        }
    }

    /**
     * Get the DID from a username
     * 
     * @param {*} username 
     */
    async getDidFromUsername(username, host) {
        try {
            let response = await Axios.get(host + 'username/getDid?username=' + username);
            let did = response.data.data.did;
            return did;
        } catch (err) {
            return null;
        }
    }

    /**
     * Save a DID Document to the server
     */
    async commit(publicDid, didDocument, signature, host) {
        if (!this.verifyProof(didDocument)) {
            throw new Error("Document does not have a valid proof");
        }

        try {
            await Axios.post(host + 'commit', {
                params: {
                    document: didDocument,
                    did: publicDid,
                    signature: signature
                }
            });

            return true;
        } catch (err) {
            console.log(err)
            if (err.response && typeof err.response.data && err.response.data.status == 'fail') {
                throw new Error(err.response.data.message);
            }

            throw err;
        }
    }

    /**
     * Link a human readable username with a public DID
     * 
     * @todo Put this on the blockchain
     * @param {string} username Username to link to the DID
     * @param {string} did Public blockchain DID (ie: Ethereum / VeChain)
     * @param {string} signature 
     */
    async commitUsername(username, did, signature, host) {
        try {
            await Axios.post(host + 'username/commit', {
                params: {
                    username: username,
                    did: did,
                    signature: signature
                }
            });

            return true;
        } catch (err) {
            if (err.response && typeof err.response.data && err.response.data.status == 'fail') {
                throw new Error(err.response.data.message);
            }

            throw err;
        }
    }

    createProof(doc, privateKeyHex) {
        let privateKeyBytes = Buffer.from(privateKeyHex.slice(2), 'hex');

        let data = doc.toJSON();
        delete data['proof'];

        let messageUint8 = decodeUTF8(JSON.stringify(data));
        let signature = encodeBase64(sign.detached(messageUint8, privateKeyBytes));

        data['proof'] = {
            alg: 'Ed25519',
            signature: signature
        };

        return new DIDDocument(data)
    }

    verifyProof(doc) {
        let proof = doc.proof();

        if (typeof(proof.signature) == 'undefined') {
            return false;
        }

        let signature = proof.signature;
        let data = doc.toJSON();
        delete data['proof'];

        let signKeyBytes = this.getKeyBytes(doc, 'sign');
        let messageUint8 = decodeUTF8(JSON.stringify(data));

        try {
            return sign.detached.verify(messageUint8, decodeBase64(signature), signKeyBytes);
        } catch (err) {
            return false;
        }
    }

    getKey(doc, type) {
        type = type ? type : 'sign';
        return doc.publicKey.find(entry => entry.id.includes(type));
    }

    getKeyBytes(doc, type) {
        type = type ? type : 'sign';
        let key = this.getKey(doc, type);
        return Buffer.from(key.publicKeyHex.slice(2), 'hex');
    }

    verifySignedMessage(did, message, sig) {
        let address = false;
        let chain = false;

        let matches = did.match(/did:([a-z0-9]*):0x([a-z0-9]*)/);
        if (matches.length >1) {
            chain = matches[1];
            address = '0x' + matches[2];
        }

        if (!address || !chain) {
            return false;
        }

        try {
            let signingAddress = utils.recoverAddress(chain, message, sig)
            return signingAddress.toLowerCase() == address.toLowerCase();
        } catch (err) {
            return false;
        }
    }
}

let didHelper = new DIDHelper();
export default didHelper;