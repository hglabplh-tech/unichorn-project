package org.harry.security.util;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.Name;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.qualified.QCStatements;
import iaik.x509.extensions.qualified.structures.QCStatement;
import iaik.x509.extensions.qualified.structures.etsi.QcEuCompliance;
import iaik.x509.qualified.QualifiedCertificate;

public class CertChecker {

    public static void checkQualified(X509Certificate certificate, VerifyUtil.SignerInfoCheckResults results) {
        try {
            boolean success = false;
            QCStatements qcStatements = (QCStatements) certificate.getExtension(QCStatements.oid);

            QCStatement[] statements = qcStatements.getQCStatements();
            boolean euCompliant = false;
            for (QCStatement statement: statements) {
                euCompliant |= QcEuCompliance.statementID.equals(statement.getStatementID());
            }

            // if euCompliant -- no country
            if (euCompliant) {
                Name subjectName = (Name)certificate.getSubjectDN();
                String country = subjectName.getRDN(ObjectID.country);
                if (country != null && !country.isEmpty()) {
                    success = true;
                    QualifiedCertificate cert;
                }
            }
        } catch (Exception ex) {
            throw new IllegalStateException("cannot check if certificate is qualified", ex);
        }
    }
}
