# src/Visit/

Visit workflow classes manage a patient's current hospital journey without
duplicating protected clinical records. Reception creates an administrative visit
and triage queue entry; the nurse claims and routes it; the doctor routes it to
lab or pharmacy. For multi-order consultations, the visit remains in lab until
every linked test completes and remains in pharmacy until every linked
prescription is resolved. A dispensed final prescription completes the visit;
a refused prescription returns the encounter to its assigned doctor for
documented review and removes sibling orders from the pharmacy queue.

`VisitService` owns state-transition, payment, and availability rules. Doctor
lists and doctor-originated routing delegate to the central joined authorizer,
so visit ownership without a current assignment never grants access.
For nurse-to-doctor routing, the service opens one repository transaction,
reserves the visit conditionally, and delegates assignment persistence to
`PatientRepository::assign()`. The visit-first lock order and rollback keep the
assignment and `with_doctor` ownership atomic without duplicating assignment
SQL in this module. MySQL row locks are gated by driver; SQLite uses its
transaction semantics without `FOR UPDATE`.

Administrator doctor revocation follows the inverse operation through
`VisitService::revokeDoctorAssignment()`: one shared transaction locks and
returns the matching `with_doctor` visit to `with_nurse`, clears only
`active_doctor_id`, and then deactivates the assignment. The historical
`doctor_id` and existing `nurse_id` remain intact. A persistence failure rolls
back both changes, while assignment revocation outside this supported
application path still causes the central doctor authorizer to deny access.
