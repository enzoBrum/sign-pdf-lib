import { PdfSigningDocument } from "./pdf-signing-document";
import {
  PdfVerifySignaturesResult,
  SignatureVerifySignatureResult,
  VerifySignatureResult,
} from "../models";
import { getSignatureDetails, getSignatureName } from "../helpers";

import { PDFDict, PDFName } from "pdf-lib";
import * as forge from "node-forge";
import * as _ from "lodash";

type Asn1 = forge.asn1.Asn1;
type CMS = forge.pkcs7.Captured<forge.pkcs7.PkcsSignedData>;

function getMessageFromSignature(signature: string): [Asn1, CMS] {
  const p7Asn1 = forge.asn1.fromDer(signature, false);
  return [p7Asn1, forge.pkcs7.messageFromAsn1(p7Asn1) as CMS];
}

export class SignatureChecker {
  #signingDoc: PdfSigningDocument;
  #fetchedCrls: Map<string, any>;
  #fetchedCerts: Map<string, forge.pki.Certificate[]>;
  #fetchCallback: ((url: string) => Promise<string | null>) | null;
  caStore: forge.pki.CAStore | null;

  static async fromPdfAsync(
    pdf: Buffer,
    caStore: forge.pki.CAStore | null = null,
    fetchCallback: null | ((url: string) => Promise<string | null>) = null
  ): Promise<SignatureChecker> {
    const signingDoc = await PdfSigningDocument.fromPdfAsync(pdf);

    return new SignatureChecker(signingDoc, caStore, fetchCallback);
  }

  private constructor(
    signingDoc: PdfSigningDocument,
    caStore: forge.pki.CAStore | null = null,
    fetchCallback: ((url: string) => Promise<string | null>) | null = null
  ) {
    this.#signingDoc = signingDoc;
    this.#fetchedCrls = new Map<string, any>();
    this.#fetchedCerts = new Map<string, forge.pki.Certificate[]>();
    this.#fetchCallback = fetchCallback;
    this.caStore = caStore ? caStore : forge.pki.createCaStore();
  }

  async verifySignaturesAsync(): Promise<
    PdfVerifySignaturesResult | undefined
  > {
    const signatures = this.#signingDoc.getSignatures();

    if (_.isEmpty(signatures)) {
      return undefined;
    }

    const checks: VerifySignatureResult[] = [];
    let integrity = true;
    for (let i = 0; i < signatures.length; i++) {
      const signature = signatures[i];
      const check = await this.verifySignatureAsync(
        signature,
        i == signatures.length - 1
      );
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

  private getAuthorityInfoAccess(ext: forge.asn1.Asn1): string[] {
    try {
      const aiaUrls: string[] = [];
      if (!ext || !ext.value) return aiaUrls;

      for (let i = 0; i < ext.value.length; ++i) {
        // @ts-ignore
        const accessDescriptionUrl = ext.value[i].value[1].value;
        if (accessDescriptionUrl) aiaUrls.push(accessDescriptionUrl);
      }
      return aiaUrls;
    } catch (e) {
      console.error("Error while parsing accessDescriptionUrl: %s", e);
      return [];
    }
  }
  private getCrlUrls(ext: forge.asn1.Asn1): string[] {
    try {
      const crlUrls: string[] = [];
      if (!ext || !ext.value) return crlUrls;
      for (let i = 0; i < ext.value.length; ++i) {
        // @ts-ignore
        const generalName = ext.value[i].value[0].value[0].value[0].value;
        if (!generalName) continue;
        crlUrls.push(generalName as string);
      }
      return crlUrls;
    } catch (e) {
      console.error("Error while parsing crlDistributionPoints: %s", e);
      return [];
    }
  }

  private parsePemCertificates(s: string): forge.pki.Certificate[] {
    const certs = [];
    let begin = 0;
    while (true) {
      begin = s.indexOf("-----BEGIN CERTIFICATE-----", begin);
      if (begin === -1) break;

      let end = s.indexOf("-----END CERTIFICATE-----", begin);
      if (end === -1) break;

      end += "-----END CERTIFICATE-----".length;
      try {
        const cert = forge.pki.certificateFromPem(s.substring(begin, end));
        certs.push(cert);
      } catch (error) {
        console.error(`Error while reading certificate: ${error}`);
      }

      begin = end;
    }

    return certs;
  }

  private async fetchParentCertificate(
    cert: forge.pki.Certificate
  ): Promise<forge.pki.Certificate | null> {
    if (!this.#fetchCallback) return null;

    // @ts-ignore
    const ext = cert.getExtension("authorityInfoAccess")?.value;
    if (!ext) return null;
    const authorityInfoAccess = forge.asn1.fromDer(
      // @ts-ignore
      ext
    );
    const aiaUrls = this.getAuthorityInfoAccess(authorityInfoAccess);

    for (let i = 0; i < aiaUrls.length; ++i) {
      const url = aiaUrls[i];
      try {
        let certs: forge.pki.Certificate[];
        if (this.#fetchedCerts.has(url)) {
          certs = this.#fetchedCerts.get(url) as forge.pki.Certificate[];
        } else {
          const response = await this.#fetchCallback(url);
          if (!response) continue;

          // 1. Try multiple PEMs
          certs = this.parsePemCertificates(response);

          // 2, try pkcs7
          if (!certs.length) {
            certs = (forge.pkcs7.messageFromPem(response) as any)
              .certificates as forge.pki.Certificate[];
          }

          this.#fetchedCerts.set(url, certs);
        }

        const parent = certs.find((c) => cert.isIssuer(c));
        if (parent) return parent;
      } catch (e) {
        console.error(
          `Error while fetching certificate at ${url}. Error: ${e}`
        );
      }
    }
    return null;
  }

  private async fetchCrls(cert: forge.pki.Certificate): Promise<void> {
    if (!this.#fetchCallback) return;

    // @ts-ignore
    const ext = cert.getExtension("cRLDistributionPoints")?.value;
    if (!ext) return;

    const crlDistributionPoints = forge.asn1.fromDer(
      // @ts-ignore
      ext
    );

    const crlUrls = this.getCrlUrls(crlDistributionPoints);

    for (let i = 0; i < crlUrls.length; ++i) {
      const url = crlUrls[i];
      try {
        if (this.#fetchedCrls.has(url)) {
          continue;
        } else {
          this.#fetchedCrls.set(url, "token");
          const crl = await this.#fetchCallback(url);
          if (!crl) continue;
          // @ts-ignore
          crl = forge.pki.certificateRevocationListFromPem(crl, true, true);
          this.#fetchedCrls.set(url, crl);
        }
      } catch (e) {
        console.error(`Could not ready CRL at ${url}. Error: ${e}`);
      }
    }
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
  private verifyCMSIntegrity(
    result: SignatureVerifySignatureResult,
    message: CMS,
    parsedAsn1: Asn1,
    signedData: any
  ) {
    const {
      rawCapture: {
        signature: sig,
        authenticatedAttributes: authAttributes,
        digestAlgorithm,
      },
    } = message;

    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();
    const setAuthAttrs = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      authAttributes
    );

    const signedAttrsDigest = (forge.md as any)[hashAlgorithm]
      .create()
      .update(forge.asn1.toDer(setAuthAttrs).data)
      .digest()
      .getBytes();
    const signedDataDigest = (forge.md as any)[hashAlgorithm]
      .create()
      .update(signedData)
      .digest()
      .getBytes();
    const signingCert = this.getSigningCert(message);

    const messageDigestAttr = authAttributes.find(
      (attr: any) =>
        forge.asn1.derToOid(attr.value[0].value) ===
        forge.pki.oids.messageDigest
    ).value[1].value[0].value;

    // 1. messageDigest equals SignedData
    result.integrity = signedDataDigest === messageDigestAttr;

    // 2. signedAttrs signed by cert.
    result.signatureValid = (
      signingCert.publicKey as forge.pki.rsa.PublicKey
    ).verify(signedAttrsDigest, sig);

    // 3. eContentType equals ContentType inside SignedAttrs
    const contentTypeAttr = authAttributes.find(
      (attr: any) =>
        forge.asn1.derToOid(attr.value[0].value) === forge.pki.oids.contentType
    ).value[1].value[0].value;
    result.eContentTypeValid =
      contentTypeAttr === message.rawCapture.contentType; // contentType here means eContentType. Name is different because node-forge uses pkcs#7
  }

  private async sortCertificates(
    certs: forge.pki.Certificate[]
  ): Promise<forge.pki.Certificate[]> {
    const parentIdx = Array(certs.length);
    const childIdx = Array(certs.length);

    parentIdx.fill(-1);
    childIdx.fill(-1);

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

    for (let i = 0; i < certs.length; ++i) {
      if (parentIdx[i] === -1) {
        const parent = await this.fetchParentCertificate(certs[i]);
        if (parent && parent.subject.hash !== certs[i].subject.hash) {
          certs.push(parent);
          parentIdx[i] = certs.length - 1;
          parentIdx.push(-1);
          childIdx.push(i);
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
      if (
        next_cert === curr_cert ||
        next_cert === undefined ||
        certs[next_cert] == undefined
      )
        break;
      if (visited[next_cert]) throw Error("Cycle in certificate chain!!!");
      above_0_cert.push(certs[next_cert]);
      visited[next_cert] = true;
      curr_cert = next_cert;
    }

    curr_cert = 0;
    while (true) {
      const next_cert = childIdx[curr_cert];
      if (
        next_cert === curr_cert ||
        next_cert === undefined ||
        certs[next_cert] === undefined
      )
        break;
      if (visited[next_cert]) throw Error("Cycle in certificate chain!!!");
      visited[next_cert] = true;
      below_0_cert.push(certs[next_cert]);
      curr_cert = next_cert;
    }

    return below_0_cert.concat([certs[0]]).concat(above_0_cert);
  }

  private async verifyCertificates(
    message: CMS,
    result: SignatureVerifySignatureResult
  ) {
    const certs = await this.sortCertificates(message.certificates);
    const promises: Promise<void>[] = [];
    for (let i = 0; i < certs.length; ++i)
      promises.push(this.fetchCrls(certs[i]));
    await Promise.all(promises);

    try {
      // @ts-ignore
      result.trustedCertificate = this.caStore
        ? forge.pki.verifyCertificateChain(
            this.caStore,
            certs,
            // @ts-ignore
            (
              verified: boolean | string,
              depth: number,
              certs: forge.pki.Certificate[]
            ) => {
              const cert = certs[depth];
              const ext = (
                cert.getExtension("cRLDistributionPoints") as any | undefined
              )?.value;
              if (!ext) return true;
              const crlDistributionPoints = forge.asn1.fromDer(
                // @ts-ignore
                ext
              );

              const crlUrls = this.getCrlUrls(crlDistributionPoints);
              for (let i = 0; i < crlUrls.length; ++i) {
                const crl = this.#fetchedCrls.get(crlUrls[i]);
                if (!crl) continue;

                // We only fail later se can at least know if the certificate is trusted.
                if (crl.isCertRevoked(cert)) {
                  result.revoked = `Cert ${cert.serialNumber} was revoked by CRL at ${crlUrls[i]}`;
                }
              }
              return true;
            }
          )
        : true;
    } catch (error) {
      // @ts-ignore
      console.error(`Error while verifying certificates: ${error.message}`);
      result.trustedCertificate = false;
    }
  }

  private async verifySignatureAsync(
    signature: PDFDict,
    isLast: boolean
  ): Promise<VerifySignatureResult> {
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
    const appended =
      isLast && !this.#signingDoc.isSignatureForEntireDocument(signature);

    const result: SignatureVerifySignatureResult = {
      name: getSignatureName(signature),
      integrity: false,
      trustedCertificate: false,
      signatureValid: false,
      details: getSignatureDetails(signature.lookup(PDFName.of("V"), PDFDict)),
      eContentTypeValid: false,
      valid: false,
      revoked: false,
    };

    this.verifyCMSIntegrity(
      result,
      message,
      parsedAsn1,
      signBuffer.toString("latin1")
    );
    await this.verifyCertificates(message, result);

    result.valid =
      result.integrity &&
      result.trustedCertificate &&
      result.signatureValid &&
      result.eContentTypeValid &&
      !result.revoked &&
      !appended;
    return result;
  }
}
