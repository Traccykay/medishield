# src/Visit/

Visit workflow classes manage a patient's current hospital journey without
duplicating protected clinical records. Reception creates an administrative visit
and triage queue entry; the nurse claims and routes it; the doctor routes it to
lab or pharmacy; pharmacy completes it after dispensing.

`VisitService` owns state-transition, payment, and availability rules.
`VisitRepository` owns only prepared, portable PDO queries.
