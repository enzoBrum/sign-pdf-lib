import { SignPdfError } from './sign-pdf-error';

export class NoSignatureComputerError extends SignPdfError {
    constructor() {
        super("No signature computer set. You need to call setSignatureComputer first.");
    }
}
