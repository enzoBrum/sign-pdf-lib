import { PDFName, PDFString } from "pdf-lib";

import { PdfVerifySignaturesResult, SignatureField } from "../models";
import {
  SignFieldParameters,
  AddFieldParameters,
  SignDigitalParameters,
} from "../models/parameters";
import { SignatureComputerSettings, SignerSettings } from "../models/settings";
import { PdfDocumentDigitalSigner } from "./pdf-document-digital-signer";
import { SignatureEmbeder } from "./signature-embeder";
import { SignatureComputer } from "./signature-computer";
import { PdfSigningDocument } from "./pdf-signing-document";
import { SignatureChecker } from "./signature-checker";
import { NoSignatureComputerError } from "../errors/no-signature-computer-error";

export class PdfDigitalSigner {
  #settings: SignerSettings;
  #signatureComputer: SignatureComputer | null;

  constructor(settings: SignerSettings) {
    this.#settings = settings;
    this.#signatureComputer = settings.signatureComputer
      ? new SignatureComputer(settings.signatureComputer)
      : null;
  }

  public async addPlaceholderAsync(
    pdf: Buffer,
    info: SignDigitalParameters
  ): Promise<Buffer> {
    const pdfDocSigner = await PdfDocumentDigitalSigner.fromPdfAsync(pdf);
    const pageIndex = info.pageNumber - 1;
    const { background, texts } = info.visual ?? {};
    const visualRef = await pdfDocSigner.addVisualAsync({ background, texts });
    const placeholderInfo = this.getPlaceholderParameters();
    const placeholderRef = pdfDocSigner.addSignaturePlaceholder({
      ...info.signature,
      ...placeholderInfo,
    });
    const rectangle = info.visual?.rectangle;
    const embedFont = !!(info.visual && info.visual?.texts);
    const name = info.name;
    pdfDocSigner.addSignatureField({
      name,
      pageIndex,
      rectangle,
      visualRef,
      placeholderRef,
      embedFont,
    });
    return pdfDocSigner.saveAsync();
  }

  public async addFieldAsync(
    pdf: Buffer,
    info: AddFieldParameters
  ): Promise<Buffer> {
    const pdfDocSigner = await PdfDocumentDigitalSigner.fromPdfAsync(pdf);
    const pageIndex = info.pageNumber - 1;
    const rectangle = info.rectangle;
    const embedFont = false;
    const name = info.name;
    pdfDocSigner.addSignatureField({ name, pageIndex, rectangle, embedFont });

    return pdfDocSigner.saveAsync();
  }

  public async signAsync(
    pdf: Buffer,
    info: SignDigitalParameters,
    addPlaceholder: boolean = true
  ): Promise<Buffer> {
    if (!this.#signatureComputer) throw new NoSignatureComputerError();

    const placeholderPdf = addPlaceholder
      ? await this.addPlaceholderAsync(pdf, info)
      : pdf;
    const signatureEmbeder = await SignatureEmbeder.fromPdfAsync(
      placeholderPdf
    );
    const toBeSignedBuffer = signatureEmbeder.getSignBuffer();
    const signature = this.#signatureComputer.computeSignature(
      toBeSignedBuffer,
      info.signature?.date || new Date()
    );
    return signatureEmbeder.embedSignature(signature);
  }

  public async signFieldAsync(
    pdf: Buffer,
    info: SignFieldParameters
  ): Promise<Buffer> {
    if (!this.#signatureComputer) throw new NoSignatureComputerError();

    const pdfDocSigner = await PdfDocumentDigitalSigner.fromPdfAsync(pdf);
    const placeholderInfo = this.getPlaceholderParameters();
    const placeholderRef = pdfDocSigner.addSignaturePlaceholder({
      ...info.signature,
      ...placeholderInfo,
    });
    const visualRef = await pdfDocSigner.addVisualAsync({ ...info.visual });
    const embedFont = !!(info.visual && "texts" in info.visual);
    pdfDocSigner.updateSignature(info.fieldName, {
      placeholderRef,
      visualRef,
      embedFont,
    });
    const placeholderPdf = await pdfDocSigner.saveAsync();
    const signatureEmbeder = await SignatureEmbeder.fromPdfAsync(
      placeholderPdf
    );
    const toBeSignedBuffer = signatureEmbeder.getSignBuffer();
    const signature = this.#signatureComputer.computeSignature(
      toBeSignedBuffer,
      info.signature?.date || new Date()
    );
    return signatureEmbeder.embedSignature(signature);
  }

  public async verifySignaturesAsync(
    pdf: Buffer
  ): Promise<PdfVerifySignaturesResult | undefined> {
    const signatureChecker = await SignatureChecker.fromPdfAsync(pdf);
    return await signatureChecker.verifySignaturesAsync();
  }

  public async getFieldsAsync(pdf: Buffer): Promise<SignatureField[]> {
    const signingDoc = await PdfSigningDocument.fromPdfAsync(pdf);
    return signingDoc.getFields().map((field) => {
      const name = field.lookup(PDFName.of("T"), PDFString).asString();
      const pageNumber = signingDoc.getSignaturePageNumber(name);
      return {
        name,
        pageNumber,
      };
    });
  }

  public async getSignatureCount(pdf: Buffer): Promise<number> {
    const signingDoc = await PdfSigningDocument.fromPdfAsync(pdf);
    return signingDoc.getSignatureCount();
  }

  public setSignatureComputer(settings: SignatureComputerSettings) {
    this.#signatureComputer = new SignatureComputer(settings);
  }

  private getPlaceholderParameters() {
    return {
      signaturePlaceholder: "A".repeat(this.#settings.signatureLength),
      rangePlaceHolder: this.#settings.rangePlaceHolder,
    };
  }
}
