import { SignPdfError } from './sign-pdf-error';

export class TooSmallPlaceholderError extends SignPdfError {
    expectedSize: number
    constructor(expectedSize: number) {
        super('Not enough space to store signature.');
        this.expectedSize = expectedSize
    }
}
