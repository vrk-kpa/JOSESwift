import Foundation

struct JWSSigningInput {

    let header: JWSHeader

    let payload: Payload

    private var encodePayload: Bool {
        header.b64 ?? true
    }

    func signingInput() throws -> Data {
        guard let headerData = header.data().base64URLEncodedString().data(using: .ascii) else {
            throw JWSError.cannotComputeSigningInput
        }

        let payloadData: Data
        if encodePayload {
            guard let encodedPayload = payload.data().base64URLEncodedString().data(using: .ascii) else {
                throw JWSError.cannotComputeSigningInput
            }
            payloadData = encodedPayload
        } else {
            payloadData = payload.data()
        }

        return headerData + ".".data(using: .ascii)! + payloadData
    }
}
