import { PdfSigningDocument } from "./pdf-signing-document";
import {
  CertificateInfo,
  PdfVerifySignaturesResult,
  SignatureInfo,
  SignatureValidity,
  SignatureVerifySignatureResult,
  VerifySignatureResult,
} from "../models";
import { getSignatureDetails, getSignatureName } from "../helpers";

import { PDFDict, PDFName, PDFString } from "pdf-lib";
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
  #otsOid: string[] | null;
  caStore: forge.pki.CAStore | null;
  #perfInfo: any;

  static async fromPdfAsync(
    pdf: Buffer,
    caStore: forge.pki.CAStore | null = null,
    fetchCallback: null | ((url: string) => Promise<string | null>) = null,
    otsOid: string[] | null = null,
    perfInfo: any = null
  ): Promise<SignatureChecker> {
    let begin = performance.now();
    const signingDoc = await PdfSigningDocument.fromPdfAsync(pdf);
    let end = performance.now();

    perfInfo.parserPdf.value += end - begin;

    return new SignatureChecker(signingDoc, caStore, fetchCallback, otsOid, perfInfo);
  }

  private constructor(
    signingDoc: PdfSigningDocument,
    caStore: forge.pki.CAStore | null = null,
    fetchCallback: ((url: string) => Promise<string | null>) | null = null,
    otsOid: string[] | null = null,
    perfInfo: any = null
  ) {
    this.#signingDoc = signingDoc;
    this.#fetchedCrls = new Map<string, any>();
    this.#fetchedCerts = new Map<string, forge.pki.Certificate[]>();
    this.#fetchCallback = fetchCallback;
    this.#otsOid = otsOid;
    this.caStore = caStore ? caStore : forge.pki.createCaStore();
    this.#perfInfo = perfInfo;
  }

  async verifySignaturesAsync(): Promise<PdfVerifySignaturesResult | undefined> {
    const signatures = this.#signingDoc.getSignatures();

    if (_.isEmpty(signatures)) {
      return undefined;
    }

    const checks: SignatureVerifySignatureResult[] = [];
    let integrity = true;
    for (let i = 0; i < signatures.length; i++) {
      const signature = signatures[i];
      const check = await this.verifySignatureAsync(signature, i == signatures.length - 1);
      checks.push(check);
      integrity = integrity && check.signature.validity.individualChecks.integrity;
    }

    return {
      integrity: integrity,
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

  private async fetchParentCertificate(cert: forge.pki.Certificate): Promise<forge.pki.Certificate | null> {
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
            certs = (forge.pkcs7.messageFromPem(response) as any).certificates as forge.pki.Certificate[];
          }

          this.#fetchedCerts.set(url, certs);
        }

        const parent = certs.find((c) => cert.isIssuer(c));
        if (parent) return parent;
      } catch (e) {
        console.error(`Error while fetching certificate at ${url}. Error: ${e}`);
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
          let crl = await this.#fetchCallback(url);
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
  private async verifyCMSIntegrity(validity: SignatureValidity, message: CMS, parsedAsn1: Asn1, docHash: string) {
    const {
      rawCapture: { signature: sig, authenticatedAttributes: authAttributes, digestAlgorithm },
    } = message;

    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();
    const setAuthAttrs = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, authAttributes);

    const signedAttrsDigest = (forge.md as any)[hashAlgorithm].create().update(forge.asn1.toDer(setAuthAttrs).data).digest().getBytes();
    const signingCert = this.getSigningCert(message);

    const messageDigestAttr = authAttributes.find((attr: any) => forge.asn1.derToOid(attr.value[0].value) === forge.pki.oids.messageDigest)
      .value[1].value[0].value;

    // 1. messageDigest equals SignedData
    validity.individualChecks.integrity = docHash === messageDigestAttr;

    // 2. signedAttrs signed by cert.
    validity.individualChecks.cms_valid = (signingCert.publicKey as forge.pki.rsa.PublicKey).verify(signedAttrsDigest, sig);

    // 3. eContentType equals ContentType inside SignedAttrs
    const contentTypeAttr = authAttributes.find((attr: any) => forge.asn1.derToOid(attr.value[0].value) === forge.pki.oids.contentType)
      .value[1].value[0].value;
    validity.individualChecks.cms_valid = validity.individualChecks.cms_valid && contentTypeAttr === message.rawCapture.contentType; // contentType here means eContentType. Name is different because node-forge uses pkcs#7
  }

  private async verifyOTS(validity: SignatureValidity, signingCert: forge.pki.Certificate, docHash: string | undefined): Promise<void> {
    const ots_extension_der = signingCert.extensions.find((ext) => this.#otsOid?.find((oid) => oid === ext.id) !== undefined);
    if (!ots_extension_der) {
      validity.individualChecks.does_ots_pades_match_signature_digest = undefined;
      return;
    }

    const ots_extension = forge.asn1.fromDer(ots_extension_der.value);
    // @ts-ignore
    const receivedHash = ots_extension.value[1].value[1].value;
    validity.individualChecks.does_ots_pades_match_signature_digest = docHash === receivedHash;
  }

  private async sortCertificates(certs: forge.pki.Certificate[]): Promise<forge.pki.Certificate[]> {
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
      if (next_cert === curr_cert || next_cert === undefined || certs[next_cert] == undefined) break;
      if (visited[next_cert]) throw Error("Cycle in certificate chain!!!");
      above_0_cert.push(certs[next_cert]);
      visited[next_cert] = true;
      curr_cert = next_cert;
    }

    curr_cert = 0;
    while (true) {
      const next_cert = childIdx[curr_cert];
      if (next_cert === curr_cert || next_cert === undefined || certs[next_cert] === undefined) break;
      if (visited[next_cert]) throw Error("Cycle in certificate chain!!!");
      visited[next_cert] = true;
      below_0_cert.push(certs[next_cert]);
      curr_cert = next_cert;
    }

    return below_0_cert.concat([certs[0]]).concat(above_0_cert);
  }

  private async verifyCertificates(message: CMS, validity: SignatureValidity) {
    let begin = performance.now();
    const certs = await this.sortCertificates(message.certificates);
    let end = performance.now();
    this.#perfInfo.trustedChain.value += end - begin;
    const promises: Promise<void>[] = [];
    begin = performance.now();
    for (let i = 0; i < certs.length; ++i) promises.push(this.fetchCrls(certs[i]));
    await Promise.all(promises);
    end = performance.now();
    this.#perfInfo.crls.value += end - begin;

    try {
      // @ts-ignore
      begin = performance.now();
      validity.individualChecks.trusted = this.caStore
        ? forge.pki.verifyCertificateChain(
            this.caStore,
            certs,
            // @ts-ignore
            (verified: boolean | string, depth: number, certs: forge.pki.Certificate[]) => {
              if (verified !== true) {
                return verified;
              }
              const cert = certs[depth];
              const ext = (cert.getExtension("cRLDistributionPoints") as any | undefined)?.value;
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
                  console.log(`Cert ${cert.serialNumber} was revoked by CRL at ${crlUrls[i]}`);
                  validity.individualChecks.revoked = true;
                }
              }
              return true;
            }
          )
        : true;
      end = performance.now();
      this.#perfInfo.trustedChain.value += end - begin;
    } catch (error) {
      // @ts-ignore
      console.error(`Error while verifying certificates: ${error.message}`);
      validity.individualChecks.trusted = false;
    }
  }

  private async calculateDocHash(
    signBuffer: Buffer,
    cmsMessage: CMS,
    signingCert: forge.pki.Certificate
  ): Promise<[string, string | undefined]> {
    const {
      rawCapture: { signature: sig, authenticatedAttributes: authAttributes, digestAlgorithm },
    } = cmsMessage;

    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();
    const signBufferDigest = await self.crypto.subtle.digest(
      hashAlgorithm === "sha256"
        ? "SHA-256"
        : hashAlgorithm === "sha512"
        ? "SHA-512"
        : hashAlgorithm === "sha384"
        ? "SHA-384"
        : hashAlgorithm,
      signBuffer
    );

    const ots_extension_der = signingCert.extensions.find((ext) => this.#otsOid?.find((oid) => oid === ext.id) !== undefined);
    if (!ots_extension_der) {
      return [Buffer.from(signBufferDigest).toString("latin1"), undefined];
    }

    const ots_extension = forge.asn1.fromDer(ots_extension_der.value);

    // @ts-ignore
    let hashAlgorithmOts = forge.oids[forge.asn1.derToOid(ots_extension.value[0].value[0].value)];

    const signBufferDigestOts =
      hashAlgorithmOts === hashAlgorithm
        ? signBufferDigest
        : await self.crypto.subtle.digest(
            hashAlgorithmOts === "sha256"
              ? "SHA-256"
              : hashAlgorithmOts === "sha512"
              ? "SHA-512"
              : hashAlgorithmOts === "sha384"
              ? "SHA-384"
              : hashAlgorithmOts,
            signBuffer
          );

    return [
      Buffer.from(signBufferDigest).toString("latin1"),
      Array.from(new Uint8Array(signBufferDigestOts))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
    ];
  }

  private async verifySignatureAsync(signature: PDFDict, isLast: boolean): Promise<SignatureVerifySignatureResult> {
    let begin = performance.now();
    const signBuffer = this.#signingDoc.getSignatureBuffer(signature);
    const signatureHexStr = this.#signingDoc.getSignatureHexString(signature);
    console.log(signatureHexStr);
    const signatureStr = Buffer.from(signatureHexStr, "hex").toString("latin1");
    let end = performance.now();

    this.#perfInfo.byteRange.value += end - begin;

    begin = performance.now();
    const [parsedAsn1, message] = getMessageFromSignature(signatureStr);
    end = performance.now();
    this.#perfInfo.cmsParsing.value += end - begin;

    const signingCert = this.getSigningCert(message);

    begin = performance.now();
    const [docHash, docHashForOts] = await this.calculateDocHash(signBuffer, message, signingCert);
    end = performance.now();

    this.#perfInfo.docHash.value += end - begin;

    // last signature must go until the end.
    begin = performance.now();
    const appended = isLast && !this.#signingDoc.isSignatureForEntireDocument(signature);
    end = performance.now();

    const validity: SignatureValidity = {
      is_valid: false,
      individualChecks: {
        is_signature_valid: false,
        integrity: false,
        trusted: false,
        cms_valid: false,
        does_ots_pades_match_signature_digest: false,
        revoked: false,
      },
    };

    begin = performance.now();
    await this.verifyCMSIntegrity(validity, message, parsedAsn1, docHash);
    end = performance.now();

    this.#perfInfo.cmsVerification.value += end - begin;
    await this.verifyCertificates(message, validity);
    begin = performance.now();
    await this.verifyOTS(validity, signingCert, docHashForOts);
    end = performance.now();
    this.#perfInfo.verifyCertAu.value += end - begin;

    const is_otc = validity.individualChecks.does_ots_pades_match_signature_digest !== undefined;
    // @ts-ignore -> ts is not smart enough to see that the ternary will always return a boolean.
    validity.is_valid =
      validity.individualChecks.integrity &&
      validity.individualChecks.trusted &&
      validity.individualChecks.cms_valid &&
      (is_otc ? validity.individualChecks.does_ots_pades_match_signature_digest : true) &&
      !validity.individualChecks.revoked &&
      !appended;
    validity.individualChecks.is_signature_valid = validity.is_valid;

    begin = performance.now();
    const signingTimeAttr = message.rawCapture.authenticatedAttributes.find(
      // @ts-ignore
      (c) => forge.asn1.derToOid(c.value[0].value) == "1.2.840.113549.1.9.5"
    );

    let signingTime: number;
    if (signingTimeAttr) {
      const signingTimeStr = signingTimeAttr.value[1].value[0].value;
      if (isNaN(forge.asn1.generalizedTimeToDate(signingTimeStr).getTime()))
        signingTime = forge.asn1.utcTimeToDate(signingTimeStr).getTime();
      else signingTime = forge.asn1.generalizedTimeToDate(signingTimeStr).getTime();
    } else {
      const signatureV = signature.lookup(PDFName.of("V"), PDFDict);
      // @ts-ignore
      const dateStr = signatureV.get(PDFName.of("M")).value.replace(/\\(\d{3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)));

      const year = dateStr.slice(2, 6);
      const month = dateStr.slice(6, 8) || "1";
      const day = dateStr.slice(8, 10) || "1";

      const hour = dateStr.slice(10, 12) || "0";
      const minute = dateStr.slice(12, 14) || "0";
      const second = dateStr.slice(14, 16) || "0";

      const signal = dateStr.slice(16, 17) || "Z";
      const hourTz = dateStr.slice(17, 19) || "0";
      const minuteTz = dateStr.slice(20, 22) || "0";
      ("");
      const formattedDate = `${year}-${month}-${day}T${hour}:${minute}:${second}${signal}${signal != "Z" ? `${hourTz}:${minuteTz}` : ""}`;
      signingTime = new Date(formattedDate).getTime();
    }

    const signatureInfo: SignatureInfo = {
      coverage: validity.individualChecks.integrity ? "ENTIRE_FILE" : "ERROR", // We only check for weather the interval defined by the byterange is covered or not. So, if integrity is true, signature covers entire file.
      signature_time: signingTime,
      reason: undefined,
      verification_time: Date.now(),
      validity: validity,
    };

    const certificateInfo: CertificateInfo = {
      SHA1: forge.md.sha1.create().update(forge.asn1.toDer(signingCert.tbsCertificate).data).digest().toHex(),
      is_otc: is_otc,
      trust_status: validity.individualChecks.trusted ? "trusted" : "not trusted",
      subject: {
        common_name: signingCert.subject.getField("CN").value,
        email_address: undefined,
      },
      issuer: {
        common_name: signingCert.issuer.getField("CN").value,
        organization_name: undefined,
      },
      not_valid_before: signingCert.validity.notBefore.getTime() / 1000,
      not_valid_after: signingCert.validity.notAfter.getTime() / 1000,
      serial: signingCert.serialNumber,
    };

    const result: SignatureVerifySignatureResult = {
      certificate: certificateInfo,
      signature: signatureInfo,
      software_version: "1.0.0",
    };
    end = performance.now();
    this.#perfInfo.reportCreation.value += end - begin;

    return result;
  }
}
