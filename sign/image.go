/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sign

// SignedImage contains additional metadata from the signing and verification
// process.
type SignedImage struct {
	reference string
	digest    string
}

// Reference returns the OCI registry reference of the object.
func (m *SignedImage) Reference() string {
	return m.reference
}

// Digest returns the digest of the signed object.
func (m *SignedImage) Digest() string {
	return m.digest
}
