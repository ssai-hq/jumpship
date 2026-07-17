# Internal packages

Business rules and private adapters live under this Go module boundary. Dependency direction points from composition roots through adapters and ports toward domain packages and generated contracts. Repository co-location never grants runtime access to another process, store, network, IAM role, signer, or data class.

P01 creates package documentation only. Later packet owners add behavior within their declared paths and must keep the static architecture check green for direct and transitive imports.
