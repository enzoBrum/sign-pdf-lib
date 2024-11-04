import { PdfSigningDocument } from "./pdf-signing-document";
import { PdfVerifySignaturesResult, SignatureVerifySignatureResult, VerifySignatureResult } from "../models";
import { getSignatureDetails, getSignatureName } from "../helpers";

import { PDFDict, PDFName } from "pdf-lib";
import * as forge from "node-forge";
import * as _ from "lodash";

function getMessageFromSignature(signature: string) {
  const p7Asn1 = forge.asn1.fromDer(signature, false);
  return [p7Asn1, forge.pkcs7.messageFromAsn1(p7Asn1)];
}

export class SignatureChecker {
  #signingDoc: PdfSigningDocument;

  static async fromPdfAsync(pdf: Buffer): Promise<SignatureChecker> {
    const signingDoc = await PdfSigningDocument.fromPdfAsync(pdf);

    return new SignatureChecker(signingDoc);
  }

  private constructor(signingDoc: PdfSigningDocument) {
    this.#signingDoc = signingDoc;
  }

  async verifySignaturesAsync(rootCerts: string[] = []): Promise<PdfVerifySignaturesResult | undefined> {
    const signatures = this.#signingDoc.getSignatures();
    const caStore = forge.pki.createCaStore(rootCerts);

    if (_.isEmpty(signatures)) {
      return undefined;
    }

    const checks: VerifySignatureResult[] = [];
    let integrity = true;
    for (let i = 0; i < signatures.length; i++) {
      const signature = signatures[i];
      const check = await this.verifySignatureAsync(signature, i == signatures.length - 1, caStore);
      checks.push(check);
      if ("integrity" in check) {
        integrity = integrity && check.integrity;
      } else if (i !== signatures.length - 1) {
        integrity = false;
      }
    }

    return {
      integrity,
      signatures: checks,
    };
  }

  private getSigningCert(message: any): forge.pki.Certificate {
    const serial = message.rawCapture.serial
      .split("")
      // @ts-ignore
      .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
      .join("");

    // @ts-ignore
    return message.certificates.find((c) => c.serialNumber === serial);
  }

  /**
   *
   * Verifies if CMS is valid.
   * Checks performed: (as defined by RFC 5652)
   *
   * 1. messageDigest equals manually calculated digest of interval defined by /ByteRange
   * 2. signedAttrs was signed by private key of some certificate inside the CMS.
   * 3. eContentType equals contentType inside SignedAttributes
   *
   * TODO: signing-certificate-v2 and CMS Algorithm Identifier Protection Attribute
   */
  private verifyCMSIntegrity(result: SignatureVerifySignatureResult, message: any, parsedAsn1: any, signedData: any) {
    // Using any here because node-forge typing sucks.

    const {
      rawCapture: { signature: sig, authenticatedAttributes: authAttributes, digestAlgorithm },
    } = message;

    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();
    const setAuthAttrs = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, authAttributes);

    // @ts-ignore
    const signedAttrsDigest = forge.md[hashAlgorithm].create().update(forge.asn1.toDer(setAuthAttrs).data).digest().getBytes();
    // @ts-ignore
    const signedDataDigest = forge.md[hashAlgorithm].create().update(signedData).digest().getBytes();
    const signingCert = this.getSigningCert(message);

    // @ts-ignore
    const messageDigestAttr = authAttributes.find((attr) => forge.asn1.derToOid(attr.value[0].value) === forge.pki.oids.messageDigest)
      .value[1].value[0].value;

    // 1. messageDigest equals SignedData
    result.integrity = signedDataDigest === messageDigestAttr;

    // 2. signedAttrs signed by cert.
    result.signatureValid = (signingCert.publicKey as forge.pki.rsa.PublicKey).verify(signedAttrsDigest, sig);

    // 3. eContentType equals ContentType inside SignedAttrs
    // @ts-ignore
    const contentTypeAttr = authAttributes.find((attr) => forge.asn1.derToOid(attr.value[0].value) === forge.pki.oids.contentType).value[1]
      .value[0].value;
    result.eContentTypeValid = contentTypeAttr === message.rawCapture.contentType; // contentType here means eContentType. Name is different because node-forge uses pkcs#7
  }

  private sortCertificates(certs: forge.pki.Certificate[]): forge.pki.Certificate[] {
    const parentIdx = Array(certs.length);
    const childIdx = Array(certs.length);

    // O(n^2) --> we never will have hundreds of certificates, riiight????
    for (let i = 0; i < certs.length; ++i) {
      for (let j = 0; j < certs.length; ++j) {
        if (certs[i].subject.hash === certs[j].issuer.hash) {
          childIdx[i] = j;
          parentIdx[j] = i;
        } else if (certs[i].issuer.hash === certs[j].subject.hash) {
          childIdx[j] = i;
          parentIdx[i] = j;
        }
      }
    }

    let curr_cert = 0;
    const above_0_cert: forge.pki.Certificate[] = [];
    const below_0_cert: forge.pki.Certificate[] = [];
    const visited = Array(certs.length).fill(false);

    visited[0] = true;

    while (true) {
      const next_cert = parentIdx[curr_cert];
      if (next_cert === curr_cert || next_cert === undefined) break;
      if (visited[next_cert]) throw Error("Cycle in certificate chain!!!");
      above_0_cert.push(certs[next_cert]);
      visited[next_cert] = true;
      curr_cert = next_cert;
    }

    curr_cert = 0;
    while (true) {
      const next_cert = childIdx[curr_cert];
      if (next_cert === curr_cert || next_cert === undefined) break;
      if (visited[next_cert]) throw Error("Cycle in certificate chain!!!");
      visited[next_cert] = true;
      above_0_cert.push(certs[next_cert]);
      curr_cert = next_cert;
    }

    return below_0_cert.concat([certs[0]]).concat(above_0_cert);
  }

  private verifyCertificates(message: any, store: forge.pki.CAStore, result: SignatureVerifySignatureResult) {
    const certs = this.sortCertificates(message.certificates);
    try {
      result.trustedCertificate = forge.pki.verifyCertificateChain(store, certs);
    } catch (error) {
      console.error(`Error while verifying certificates: ${error}`);
      result.trustedCertificate = false;
    }
  }

  private async verifySignatureAsync(signature: PDFDict, isLast: boolean, store: forge.pki.CAStore): Promise<VerifySignatureResult> {
    if (!signature.get(PDFName.of("V"))) {
      return {
        name: getSignatureName(signature),
        isField: true,
      };
    }

    const signBuffer = this.#signingDoc.getSignatureBuffer(signature);
    const signatureHexStr = this.#signingDoc.getSignatureHexString(signature);
    const signatureStr = Buffer.from(signatureHexStr, "hex").toString("latin1");

    const [parsedAsn1, message] = getMessageFromSignature(signatureStr);

    // last signature must go until the end.
    const appended = isLast && !this.#signingDoc.isSignatureForEntireDocument(signature);

    const result: SignatureVerifySignatureResult = {
      name: getSignatureName(signature),
      integrity: false,
      trustedCertificate: false,
      signatureValid: false,
      details: getSignatureDetails(signature.lookup(PDFName.of("V"), PDFDict)),
      eContentTypeValid: false,
      valid: false,
    };

    this.verifyCMSIntegrity(result, message, parsedAsn1, signBuffer.toString("latin1"));
    this.verifyCertificates(message, store, result);

    result.valid = result.integrity && result.trustedCertificate && result.signatureValid && result.eContentTypeValid;
    return result;
  }
}
