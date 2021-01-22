package oid_cloud

import "encoding/asn1"

var PackageVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 1}

var PackageID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 5}

var InstanceID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 6}

var DeploymentName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 7}

var TenantID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 8}

//
var PhysicalSecurity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 9}

//
var SignerSecurity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 10}

var SignerSecuritySoftware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 10, 1}

var SignerSecurityHSM = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 10, 2}

// DMVerity

var DMVerityRootHash = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 28900, 1, 1, 11, 1}
