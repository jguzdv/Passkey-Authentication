# LDAP Schema

```txt
dn: CN=fIDO-Authenticator-Aaguid,<SchemaContainerDN>
changetype: ntdsSchemaAdd
adminDescription: fIDO-Authenticator-Aaguid
adminDisplayName: fIDO-Authenticator-Aaguid
attributeID: 1.2.840.113556.1.8000.2554.54579.64576.60639.19922.45518.10745386.112824.2.2
attributeSyntax: 2.5.5.10
isSingleValued: TRUE
lDAPDisplayName: fIDOAuthenticatorAaguid
name: fIDO-Authenticator-Aaguid
oMSyntax: 4
objectCategory: CN=Attribute-Schema,<SchemaContainerDN>
objectClass: attributeSchema
rangeLower: 16
rangeUpper: 16
schemaIdGuid:: 6mK5hwhZRTG0yl5t5AB3WQ==


dn: CN=fIDO-Authenticator-Credential-Id,<SchemaContainerDN>
changetype: ntdsSchemaAdd
adminDescription: fIDO-Authenticator-Credential-Id
adminDisplayName: fIDO-Authenticator-Credential-Id
attributeID: 1.2.840.113556.1.8000.2554.54579.64576.60639.19922.45518.10745386.112824.2.1
attributeSyntax: 2.5.5.10
isSingleValued: TRUE
lDAPDisplayName: fIDOAuthenticatorCredentialId
name: fIDO-Authenticator-Credential-Id
oMSyntax: 4
objectCategory: CN=Attribute-Schema,<SchemaContainerDN>
objectClass: attributeSchema
rangeLower: 16
rangeUpper: 128
schemaIdGuid:: CW0AgPCsTwKMz0nVQKC3Xw==
searchFlags: 1


dn: CN=fIDO-Authenticator-Devices,<SchemaContainerDN>
changetype: ntdsSchemaAdd
adminDescription: fIDO-Authenticator-Devices
adminDisplayName: fIDO-Authenticator-Devices
defaultSecurityDescriptor: D:S:
governsID: 1.2.840.113556.1.8000.2554.54579.64576.60639.19922.45518.10745386.112824.1
lDAPDisplayName: fIDOAuthenticatorDevices
name: fIDO-Authenticator-Devices
objectCategory: CN=Class-Schema,<SchemaContainerDN>
objectClass: classSchema
objectClassCategory: 1
rDNAttID: cn
schemaIdGuid:: loYx5wh5TNqHYH8lAqrQnQ==
subClassOf: top
possSuperiors: user


dn:
changetype: ntdsSchemaModify
replace: schemaUpdateNow
schemaUpdateNow: 1
-


dn: CN=fIDO-Authenticator-Device,<SchemaContainerDN>
changetype: ntdsSchemaAdd
adminDescription: fIDO-Authenticator-Device
adminDisplayName: fIDO-Authenticator-Device
defaultSecurityDescriptor: D:S:
governsID: 1.2.840.113556.1.8000.2554.54579.64576.60639.19922.45518.10745386.112824.1.2
lDAPDisplayName: fIDOAuthenticatorDevice
name: fIDO-Authenticator-Device
objectCategory: CN=Class-Schema,<SchemaContainerDN>
objectClass: classSchema
objectClassCategory: 1
rDNAttID: cn
schemaIdGuid:: Pd68TF6uRXmql6LCWgtm0g==
subClassOf: top
possSuperiors: fIDOAuthenticatorDevices
mayContain: userCertificate
mayContain: logonCount
mayContain: fIDOAuthenticatorAaguid
mayContain: fIDOAuthenticatorCredentialId


dn:
changetype: ntdsSchemaModify
replace: schemaUpdateNow
schemaUpdateNow: 1
-
```