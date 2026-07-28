# src/Visit/

Visit workflow classes manage a patient's current hospital journey without
duplicating protected clinical records. Reception creates an administrative visit
and triage queue entry; the nurse claims and routes it; the doctor routes it to
lab or pharmacy. For multi-order consultations, the visit remains in lab until
every linked test completes and remains in pharmacy until every linked
prescription is resolved. A dispensed final prescription completes the visit;
a refused prescription returns the encounter to its assigned doctor for
documented review and removes sibling orders from the pharmacy queue.

`VisitService` owns state-transition, payment, and availability rules.
`VisitRepository` owns only prepared, portable PDO queries.
