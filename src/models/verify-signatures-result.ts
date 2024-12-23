import { SignatureParameters as SignatureParameters } from "./parameters/signature-parameters";

export interface CertificateSubject {
  common_name: string;
  email_address: string | undefined;
}

export interface CertificateIssuer {
  organization_name: string | undefined;
  common_name: string;
}

export interface SignatureValidityIndividualChecks {
  is_signature_valid: boolean;
  integrity: boolean;
  trusted: boolean;
  cms_valid: boolean;
  does_ots_pades_match_signature_digest: boolean;
  revoked: boolean;
}

export interface SignatureValidity {
  is_valid: boolean;
  individualChecks: SignatureValidityIndividualChecks;
}

export interface SignatureInfo {
  coverage: string;
  signature_time: number;
  reason: string | undefined;
  verification_time: number;
  validity: SignatureValidity;
}

export interface CertificateInfo {
  SHA1: string;
  subject: CertificateSubject;
  issuer: CertificateIssuer;
  not_valid_before: number;
  not_valid_after: number;
  serial: string;
}

export interface SignatureVerifySignatureResult {
  certificate: CertificateInfo;
  signature: SignatureInfo;
  software_version: string;
}

export interface FieldVerifySignatureResult {
  name: string;
  isField: boolean;
}

export type VerifySignatureResult = SignatureVerifySignatureResult | FieldVerifySignatureResult;

export interface PdfVerifySignaturesResult {
  integrity: boolean;
  signatures: VerifySignatureResult[];
}
