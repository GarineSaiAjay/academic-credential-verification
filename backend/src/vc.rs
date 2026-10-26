//! Export of an issued credential as a W3C Verifiable Credentials Data Model 2.0 document.
//!
//! The document has the shape other systems expect (`@context`, `type`, `issuer`, `validFrom`,
//! `credentialSubject`, `credentialStatus`, `proof`). The proofs are NOT W3C Data Integrity proofs: they are
//! this system's own Ed25519 stage signatures, carried with the exact message each one signed, so anyone can
//! check them with any Ed25519 library. A generic VC verifier will not understand them; the `credentialStatus`
//! URL gives the live verdict, including revocation.

use axum::{
    extract::{Path, State},
    http::header,
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    credentials::{assess, fetch_approvals, ApprovalRow, CredRow},
    crypto,
    error::{AppError, Res},
    AppState,
};

const PROOF_TYPE: &str = "AcvsEd25519Approval2026";

/// Builds the document. The student's own identifier is left out, as it is from the public verify page.
pub fn document(base: &str, c: &CredRow, approvals: &[ApprovalRow]) -> Value {
    let proofs: Vec<Value> = approvals
        .iter()
        .map(|a| {
            json!({
                "type": PROOF_TYPE,
                "created": a.signed_at,
                "proofPurpose": "assertionMethod",
                "verificationMethod": format!("urn:acvs:ed25519:{}", a.public_key),
                "stage": a.role,
                "signedMessage": String::from_utf8_lossy(&crypto::approval_message(c.id, &a.role, &c.credential_hash)),
                "proofValue": a.signature,
            })
        })
        .collect();
    let mut subject = json!({
        "type": "AcvsGraduate",
        "studentName": c.student_name,
        "program": c.program,
        "graduationDate": c.graduation_date,
    });
    if let Some(g) = &c.gpa {
        subject["gpa"] = g.clone().into();
    }
    if let Some(h) = &c.honors {
        subject["honors"] = h.clone().into();
    }
    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", format!("{base}/api/v1/vc/context")],
        "id": format!("urn:uuid:{}", c.id),
        "type": ["VerifiableCredential", "AcvsAcademicCredential"],
        "issuer": base,
        "validFrom": approvals.last().map(|a| a.signed_at),
        "credentialSubject": subject,
        "credentialStatus": {
            "id": format!("{base}/api/v1/verify/{}", c.id),
            "type": "AcvsVerifyEndpoint",
        },
        "credentialHash": c.credential_hash,
        "proof": proofs,
    });
    if let Some(old) = c.supersedes {
        doc["supersedes"] = format!("urn:uuid:{old}").into();
    }
    doc
}

/// Only a credential that verifies as VALID right now can be exported; the file would otherwise present
/// something pending, revoked or tampered with as if it were an award.
pub async fn export(State(st): State<AppState>, Path(id): Path<Uuid>) -> Res<impl IntoResponse> {
    let (c, a) = assess(&st, id).await?;
    if a.verdict != "VALID" {
        return Err(AppError::Conflict(format!(
            "credential is {}; only a VALID credential can be exported",
            a.verdict
        )));
    }
    let approvals = fetch_approvals(&st.db, id).await?;
    let doc = document(&st.cfg.public_base_url, &c, &approvals);
    Ok((
        [
            (header::CONTENT_TYPE, "application/vc+ld+json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"credential.json\"",
            ),
        ],
        Json(doc),
    ))
}

/// The JSON-LD context that defines the terms above.
pub async fn context(State(st): State<AppState>) -> impl IntoResponse {
    let ns = format!("{}/api/v1/vc/context#", st.cfg.public_base_url);
    (
        [
            (header::CONTENT_TYPE, "application/ld+json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        Json(json!({
            "@context": {
                "@version": 1.1,
                "@protected": true,
                "acvs": ns,
                "xsd": "http://www.w3.org/2001/XMLSchema#",
                "AcvsAcademicCredential": "acvs:AcademicCredential",
                "AcvsGraduate": "acvs:Graduate",
                "AcvsVerifyEndpoint": "acvs:VerifyEndpoint",
                "AcvsEd25519Approval2026": "acvs:Ed25519Approval2026",
                "studentName": "acvs:studentName",
                "program": "acvs:program",
                "graduationDate": {"@id": "acvs:graduationDate", "@type": "xsd:date"},
                "gpa": "acvs:gpa",
                "honors": "acvs:honors",
                "credentialHash": "acvs:credentialHash",
                "supersedes": {"@id": "acvs:supersedes", "@type": "@id"},
                "stage": "acvs:stage",
                "signedMessage": "acvs:signedMessage"
            }
        })),
    )
}
