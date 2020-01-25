import { DIDDocument } from 'did-document';
import { sign } from "tweetnacl";
import {
  decodeUTF8,
  encodeBase64,
  decodeBase64
} from "tweetnacl-util";
import Axios from 'axios';

class DIDHelper {

    /**
     * Load a DID Document from the server
     */
    async load(did, host) {
        try {
            let response = await Axios.get(host + 'load?did=' + did);
            let document = response.data.data.document;
            let doc = new DIDDocument(document, document['@context']);

            return doc;
        } catch (err) {
            return null;
        }
    }

    /**
     * Save a DID Document to the server
     */
    async commit(didDocument, host) {
        if (!this.verifyProof(didDocument)) {
            throw new Error("Document does not have a valid proof");
        }

        try {
            let response = await Axios.post(host + 'commit', {
                params: {
                    document: didDocument
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
        
        doc.proof({
            alg: 'ES256K',
            signature: signature
        });

        return doc;
    }

    verifyProof(doc) {
        let proof = doc.proof();

        if (typeof(proof.signature) == 'undefined') {
            return false;
        }

        let signature = proof.signature;
        let data = doc.toJSON();
        delete data['proof'];

        let signKey = doc.publicKey.find(entry => entry.id.includes('sign'));
        let signKeyBytes = Buffer.from(signKey.publicKeyHex.slice(2), 'hex');

        let messageUint8 = decodeUTF8(JSON.stringify(data));

        try {
            return sign.detached.verify(messageUint8, decodeBase64(signature), signKeyBytes);
        } catch (err) {
            return false;
        }
    }
}

let didHelper = new DIDHelper();
export default didHelper;