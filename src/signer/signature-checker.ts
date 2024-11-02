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

  async verifySignaturesAsync(): Promise<PdfVerifySignaturesResult | undefined> {
    const signatures = this.#signingDoc.getSignatures();

    if (_.isEmpty(signatures)) {
      return undefined;
    }

    const checks: VerifySignatureResult[] = [];
    let integrity = true;
    for (let i = 0; i < signatures.length; i++) {
      const signature = signatures[i];
      const check = await this.verifySignatureAsync(signature, i == signatures.length - 1);
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

  //private async verifyCertificateChain()

  private async verifySignatureAsync(signature: PDFDict, isLast: boolean): Promise<VerifySignatureResult> {
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
      expiredCertificate: false,
      signatureValid: false,
      details: getSignatureDetails(signature.lookup(PDFName.of("V"), PDFDict)),
      eContentTypeValid: false,
      valid: false,
    };

    this.verifyCMSIntegrity(result, message, parsedAsn1, signBuffer.toString("latin1"));

    return result;
  }
}
